// SPDX-License-Identifier: GPL-3.0-or-later
#include <cstdint>
#include <cstring>
#include <optional>
#include <string>
#include <string_view>
#include <utility>
#include <vector>

#include "esp_random.h"
#include "mbedtls/platform_util.h"

#include "access_requests.h"
#include "hmac.h"
#include "latchkey_util/access_json.h"
#include "latchkey_util/label_table.h"
#include "latchkey_util/passcode_id.h"
#include "latchkey_util/passcode_rules.h"
#include "latchkey_util/passcode_type.h"
#include "lock_manager.h"
#include "methods.h"
#include "rpc.h"
#include "store.h"
#include "ttlock/features.h"
#include "ttlock/session.h"
#include "ttlock/types.h"

namespace methods {

namespace {

using latchkey_util::Label;
using latchkey_util::LabelTable;
using latchkey_util::ListedCode;
using latchkey_util::NewCode;
using latchkey_util::PasscodeId;
using latchkey_util::Target;
using lock_access::Secret;
using store::locks::Record;
using ttlock::Feature;
using ttlock::Passcode;
using ttlock::PasscodeType;
using ttlock::Session;
using ttlock::Status;
using ttlock::Validity;

constexpr store::labels::Kind kLabels = store::labels::Kind::Passcodes;
constexpr size_t kRandomPasscodeDigits = 6;
constexpr int kRandomPasscodeAttempts = 20;
constexpr uint32_t kRandomCeiling = 4294967290u;
constexpr uint64_t kProbeId = UINT64_MAX;
constexpr const char* kTypeMessage = "type is permanent, timed, one_time or cyclic";
constexpr const char* kIdMessage = "id must be a passcode id from lock.passcodes.list";
constexpr const char* kNoSuchPasscode = "no such passcode on the lock";
constexpr const char* kAmbiguousId =
    "two passcodes on the lock share that id, so the board cannot tell which one is meant";
constexpr const char* kAdminEntry = "that is the keypad admin passcode: change it with lock.adminPasscode.set";
constexpr const char* kCollision =
    "the board cannot tell that code apart from another passcode on the lock by its id: choose another code";
constexpr const char* kCyclic =
    "this board cannot add cyclic passcodes yet: no reference shows how the lock takes their weekly window";

static_assert(latchkey_util::kMaxLabels == 32 && latchkey_util::kMaxLabelNameCodePoints == 24 &&
                  latchkey_util::kMaxLabelNameBytes == 48,
              "the messages state these limits");

struct Passcodes {
    std::vector<Passcode> items;
    std::vector<PasscodeId> ids;
    std::vector<uint64_t> numbers;

    ~Passcodes() {
        for (Passcode& item : items) {
            lock_access::wipe(item.code);
        }
    }

    std::vector<ListedCode> listed() const {
        std::vector<ListedCode> out;
        out.reserve(items.size());
        for (size_t i = 0; i < items.size(); ++i) {
            out.push_back(ListedCode{numbers[i], items[i].code});
        }
        return out;
    }
};

std::string_view adminCodeOf(const Record& record) {
    return std::string_view(record.adminPasscode, strnlen(record.adminPasscode, sizeof(record.adminPasscode)));
}

bool idOf(const Record& record, std::string_view code, PasscodeId& out) {
    latchkey_util::LockAesKey key{};
    std::memcpy(key.data(), record.aesKey, key.size());
    const bool made = latchkey_util::passcodeId(key, code, hmac::sha256, out);
    mbedtls_platform_zeroize(key.data(), key.size());
    return made;
}

std::string randomDigits(size_t count) {
    std::string digits(count, '0');
    for (char& digit : digits) {
        uint32_t value = esp_random();
        while (value >= kRandomCeiling) {
            value = esp_random();
        }
        digit = static_cast<char>('0' + value % 10);
    }
    return digits;
}

bool listAll(Session& session, const Record& record, Passcodes& out, Status& status, rpc::Reply& reply) {
    status = session.passcodeList(out.items);
    if (status != Status::Ok) {
        return false;
    }
    out.ids.resize(out.items.size());
    out.numbers.resize(out.items.size());
    for (size_t i = 0; i < out.items.size(); ++i) {
        if (!idOf(record, out.items[i].code, out.ids[i])) {
            reply = rpc::fail("internal", "cannot compute a passcode id");
            return false;
        }
        out.numbers[i] = latchkey_util::passcodeIdNumber(out.ids[i]);
    }
    return true;
}

bool isTimed(PasscodeType type) { return type == PasscodeType::Period || type == PasscodeType::Count; }

bool appendEntry(std::string& out, const PasscodeId& id, const Passcode& item, const Label* label,
                 std::string_view code) {
    const std::string hexId = latchkey_util::formatPasscodeId(id);
    latchkey_util::PasscodeView view;
    view.id = hexId;
    view.type = latchkey_util::passcodeTypeName(item.type);
    view.name = label != nullptr ? std::string_view(label->name) : std::string_view();
    view.managed = label != nullptr && label->managed;
    view.code = code;
    if (isTimed(item.type)) {
        latchkey_util::UtcWindow window;
        if (!lock_access::utcWindow(item.validity, window)) {
            return false;
        }
        view.window = window;
    }
    latchkey_util::appendPasscodeJson(out, view);
    return true;
}

rpc::Reply badWindow() {
    return rpc::fail("bad_response", "the lock sent a validity window with a date that cannot exist");
}

rpc::Reply entryResult(const PasscodeId& id, const Passcode& item, const Label* label, std::string_view code,
                       std::initializer_list<std::string_view> warnings) {
    std::string text;
    if (!appendEntry(text, id, item, label, code)) {
        return badWindow();
    }
    cJSON* result = cJSON_CreateObject();
    cJSON_AddItemToObject(result, "passcode", lock_access::rawJson(text));
    lock_access::wipe(text);
    lock_access::addWarnings(result, warnings);
    return rpc::ok(result);
}

bool loadLabels(const std::string& mac, LabelTable& out, rpc::Reply& reply) {
    const esp_err_t error = lock_manager::loadLabels(mac, kLabels, out);
    if (error != ESP_OK) {
        reply = lock_access::labelsUnreadable(error);
        return false;
    }
    return true;
}

rpc::Reply checkRoom(const std::string& mac, const std::string& name) {
    LabelTable labels;
    rpc::Reply problem;
    if (!loadLabels(mac, labels, problem)) {
        return problem;
    }
    Label probe;
    probe.id = kProbeId;
    probe.managed = true;
    probe.name = name;
    if (!labels.put(probe)) {
        return rpc::fail("too_many", lock_access::kLabelsFullMessage);
    }
    return lock_manager::labelsFit(mac, kLabels, labels) ? rpc::ok() : lock_access::storageFull();
}

rpc::Reply passcodesList(const cJSON* params, const rpc::Context&) {
    std::string mac;
    if (!lock_access::readLock(params, mac)) {
        return lock_access::invalid(lock_access::kLockMessage);
    }
    rpc::Reply gated = lock_access::gate(mac, {Feature::Passcode});
    if (!gated.error.empty()) {
        return lock_access::withTarget(std::move(gated), mac);
    }
    rpc::Reply reply = lock_manager::runOnLock(
        mac, "lock.passcodes.list", [mac](Session& session, const Record& record, rpc::Reply& out) {
            Passcodes passcodes;
            Status status = Status::Ok;
            if (!listAll(session, record, passcodes, status, out)) {
                return status;
            }
            LabelTable labels;
            if (!loadLabels(mac, labels, out)) {
                return Status::Ok;
            }
            size_t bound = 2;
            for (const uint64_t number : passcodes.numbers) {
                const Label* label = labels.find(number);
                bound += latchkey_util::passcodeJsonBound(label != nullptr ? label->name.size() : 0);
            }
            if (!lock_access::listFits(bound)) {
                out = lock_access::tooLarge(passcodes.items.size(), "passcodes");
                return Status::Ok;
            }
            std::string text;
            text.reserve(bound);
            text += '[';
            for (size_t i = 0; i < passcodes.items.size(); ++i) {
                if (i > 0) {
                    text += ',';
                }
                if (!appendEntry(text, passcodes.ids[i], passcodes.items[i], labels.find(passcodes.numbers[i]), {})) {
                    out = badWindow();
                    return Status::Ok;
                }
            }
            text += ']';
            if (labels.keepOnly(passcodes.numbers) && lock_manager::saveLabels(mac, kLabels, labels) != ESP_OK) {
                out = rpc::fail("storage_error", "cannot preserve removed passcode labels");
                return Status::Ok;
            }
            cJSON* result = cJSON_CreateObject();
            cJSON_AddItemToObject(result, "passcodes", lock_access::rawJson(text));
            out = rpc::ok(result);
            return Status::Ok;
        });
    return lock_access::withTarget(std::move(reply), mac);
}

struct AddRequest {
    std::string mac;
    PasscodeType type = PasscodeType::Permanent;
    Secret code;
    std::string name;
    Validity validity;
};

rpc::Reply readAdd(const cJSON* params, AddRequest& out) {
    if (!lock_access::readLock(params, out.mac)) {
        return lock_access::invalid(lock_access::kLockMessage);
    }
    const cJSON* type = lock_access::member(params, "type");
    if (!cJSON_IsString(type) || type->valuestring == nullptr ||
        !latchkey_util::passcodeTypeOf(type->valuestring, out.type)) {
        return lock_access::invalid(kTypeMessage);
    }
    if (!lock_access::readCode(lock_access::member(params, "code"), out.code)) {
        return lock_access::invalid(lock_access::kCodeMessage);
    }
    if (!lock_access::readName(lock_access::member(params, "name"), out.name)) {
        return lock_access::invalid(lock_access::kNameMessage);
    }
    if (isTimed(out.type) && !lock_access::readWindow(lock_access::member(params, "validity"), out.validity)) {
        return lock_access::invalid(lock_access::kValidityMessage);
    }
    return rpc::ok();
}

Secret drawCode(const Passcodes& passcodes, const Record& record, PasscodeId& id) {
    const std::vector<ListedCode> listed = passcodes.listed();
    for (int attempt = 0; attempt < kRandomPasscodeAttempts; ++attempt) {
        std::string digits = randomDigits(kRandomPasscodeDigits);
        const Secret code(digits);
        lock_access::wipe(digits);
        if (!idOf(record, code.get(), id)) {
            break;
        }
        const NewCode verdict = latchkey_util::checkNewCode(listed, adminCodeOf(record), code.get(),
                                                            latchkey_util::passcodeIdNumber(id), std::nullopt);
        if (verdict == NewCode::Free) {
            return code;
        }
    }
    return Secret();
}

rpc::Reply refusal(NewCode verdict) {
    return rpc::fail("lock_error", verdict == NewCode::IdTaken ? kCollision : lock_access::kInUseMessage);
}

Status addPasscode(const AddRequest& request, Session& session, const Record& record, rpc::Reply& out) {
    Passcodes passcodes;
    Status status = Status::Ok;
    if (!listAll(session, record, passcodes, status, out)) {
        return status;
    }
    PasscodeId id{};
    Secret code = request.code;
    if (code.empty()) {
        code = drawCode(passcodes, record, id);
        if (code.empty()) {
            out = rpc::fail("internal", "cannot draw a random code the lock does not already hold");
            return Status::Ok;
        }
    } else {
        if (!idOf(record, code.get(), id)) {
            out = rpc::fail("internal", "cannot compute a passcode id");
            return Status::Ok;
        }
        const NewCode verdict = latchkey_util::checkNewCode(passcodes.listed(), adminCodeOf(record), code.get(),
                                                            latchkey_util::passcodeIdNumber(id), std::nullopt);
        if (verdict != NewCode::Free) {
            out = refusal(verdict);
            return Status::Ok;
        }
    }
    LabelTable labels;
    if (!loadLabels(request.mac, labels, out)) {
        return Status::Ok;
    }
    labels.keepOnly(passcodes.numbers);
    const uint64_t number = latchkey_util::passcodeIdNumber(id);
    Label label;
    label.id = number;
    label.managed = true;
    label.name = request.name;
    if (!labels.put(label)) {
        out = rpc::fail("too_many", lock_access::kLabelsFullMessage);
        return Status::Ok;
    }
    if (!lock_manager::labelsFit(request.mac, kLabels, labels)) {
        out = lock_access::storageFull();
        return Status::Ok;
    }
    Passcode passcode;
    passcode.type = request.type;
    passcode.code = code.get();
    if (request.type != PasscodeType::Permanent) {
        passcode.validity = request.validity;
    }
    status = session.passcodeAdd(passcode);
    lock_access::wipe(passcode.code);
    if (status != Status::Ok) {
        return status;
    }
    const bool stored = lock_manager::saveLabels(request.mac, kLabels, labels) == ESP_OK;
    out = entryResult(id, passcode, labels.find(number), code.get(),
                      {stored ? "" : lock_access::kNamesNotStored, lock_access::easyCodeWarning(code.get())});
    return Status::Ok;
}

rpc::Reply passcodesAdd(const cJSON* params, const rpc::Context&) {
    AddRequest request;
    rpc::Reply problem = readAdd(params, request);
    if (!problem.error.empty()) {
        return lock_access::withTarget(std::move(problem), request.mac);
    }
    rpc::Reply gated = lock_access::gate(request.mac, {Feature::Passcode});
    if (!gated.error.empty()) {
        return lock_access::withTarget(std::move(gated), request.mac);
    }
    if (request.type == PasscodeType::Cyclic) {
        return lock_access::withTarget(rpc::fail("unsupported", kCyclic), request.mac);
    }
    rpc::Reply room = checkRoom(request.mac, request.name);
    if (!room.error.empty()) {
        return lock_access::withTarget(std::move(room), request.mac);
    }
    rpc::Reply reply = lock_manager::runOnLock(
        request.mac, "lock.passcodes.add", [request](Session& session, const Record& record, rpc::Reply& out) {
            return addPasscode(request, session, record, out);
        });
    return lock_access::withTarget(std::move(reply), request.mac);
}

struct UpdateRequest {
    std::string mac;
    PasscodeId id{};
    Secret code;
    bool renames = false;
    std::string name;
    bool moves = false;
    Validity validity;
};

rpc::Reply readUpdate(const cJSON* params, UpdateRequest& out) {
    if (!lock_access::readLock(params, out.mac)) {
        return lock_access::invalid(lock_access::kLockMessage);
    }
    const cJSON* id = lock_access::member(params, "id");
    if (!cJSON_IsString(id) || id->valuestring == nullptr || !latchkey_util::parsePasscodeId(id->valuestring, out.id)) {
        return lock_access::invalid(kIdMessage);
    }
    if (!lock_access::readCode(lock_access::member(params, "code"), out.code)) {
        return lock_access::invalid(lock_access::kCodeMessage);
    }
    const cJSON* name = lock_access::member(params, "name");
    out.renames = name != nullptr;
    if (!lock_access::readName(name, out.name)) {
        return lock_access::invalid(lock_access::kNameMessage);
    }
    const cJSON* validity = lock_access::member(params, "validity");
    out.moves = validity != nullptr;
    if (out.moves && !lock_access::readWindow(validity, out.validity)) {
        return lock_access::invalid(lock_access::kValidityMessage);
    }
    return rpc::ok();
}

bool findOne(const Passcodes& passcodes, const Record& record, const PasscodeId& wanted, size_t& index,
             rpc::Reply& out) {
    switch (latchkey_util::findTarget(passcodes.listed(), adminCodeOf(record), latchkey_util::passcodeIdNumber(wanted),
                                      index)) {
        case Target::Found:
            return true;
        case Target::Missing:
            out = lock_access::invalid(kNoSuchPasscode);
            return false;
        case Target::Ambiguous:
            out = rpc::fail("lock_error", kAmbiguousId);
            return false;
        case Target::AdminCode:
            out = lock_access::invalid(kAdminEntry);
            return false;
    }
    return false;
}

Status updatePasscode(const UpdateRequest& request, Session& session, const Record& record, rpc::Reply& out) {
    Passcodes passcodes;
    Status status = Status::Ok;
    if (!listAll(session, record, passcodes, status, out)) {
        return status;
    }
    size_t index = 0;
    if (!findOne(passcodes, record, request.id, index, out)) {
        return Status::Ok;
    }
    const Passcode& entry = passcodes.items[index];
    const Secret code = request.code.empty() ? Secret(entry.code) : request.code;
    const bool recoded = code.get() != entry.code;
    PasscodeId id = passcodes.ids[index];
    if (recoded) {
        if (!idOf(record, code.get(), id)) {
            out = rpc::fail("internal", "cannot compute a passcode id");
            return Status::Ok;
        }
        const NewCode verdict = latchkey_util::checkNewCode(passcodes.listed(), adminCodeOf(record), code.get(),
                                                            latchkey_util::passcodeIdNumber(id), index);
        if (verdict != NewCode::Free) {
            out = refusal(verdict);
            return Status::Ok;
        }
    }
    LabelTable labels;
    if (!loadLabels(request.mac, labels, out)) {
        return Status::Ok;
    }
    labels.keepOnly(passcodes.numbers);
    const uint64_t number = latchkey_util::passcodeIdNumber(id);
    const std::optional<std::string> rename = request.renames ? std::optional<std::string>(request.name) : std::nullopt;
    if (!latchkey_util::relabel(labels, passcodes.numbers[index], number, rename)) {
        out = rpc::fail("too_many", lock_access::kLabelsFullMessage);
        return Status::Ok;
    }
    if (!lock_manager::labelsFit(request.mac, kLabels, labels)) {
        out = lock_access::storageFull();
        return Status::Ok;
    }
    if (lock_manager::retainLabels(request.mac, kLabels, labels) != ESP_OK) {
        out = rpc::fail("storage_error", "cannot preserve passcode labels before updating");
        return Status::Ok;
    }
    Passcode changed;
    changed.type = entry.type;
    changed.code = code.get();
    changed.validity = isTimed(entry.type) && request.moves ? request.validity : entry.validity;
    if (recoded || changed.validity != entry.validity) {
        status = session.passcodeUpdate(entry.code, changed);
    }
    lock_access::wipe(changed.code);
    if (status != Status::Ok) {
        return status;
    }
    const bool stored = lock_manager::saveLabels(request.mac, kLabels, labels) == ESP_OK;
    out = entryResult(id, changed, labels.find(number), {},
                      {stored ? "" : lock_access::kNamesNotStored,
                       recoded ? lock_access::easyCodeWarning(code.get()) : std::string()});
    return Status::Ok;
}

rpc::Reply passcodesUpdate(const cJSON* params, const rpc::Context&) {
    UpdateRequest request;
    rpc::Reply problem = readUpdate(params, request);
    if (!problem.error.empty()) {
        return lock_access::withTarget(std::move(problem), request.mac);
    }
    rpc::Reply gated = lock_access::gate(request.mac, {Feature::ModifyPasscodeFunction});
    if (!gated.error.empty()) {
        return lock_access::withTarget(std::move(gated), request.mac);
    }
    rpc::Reply reply = lock_manager::runOnLock(
        request.mac, "lock.passcodes.update", [request](Session& session, const Record& record, rpc::Reply& out) {
            return updatePasscode(request, session, record, out);
        });
    return lock_access::withTarget(std::move(reply), request.mac);
}

rpc::Reply passcodesDelete(const cJSON* params, const rpc::Context&) {
    std::string mac;
    if (!lock_access::readLock(params, mac)) {
        return lock_access::invalid(lock_access::kLockMessage);
    }
    const cJSON* item = lock_access::member(params, "id");
    PasscodeId wanted{};
    if (!cJSON_IsString(item) || item->valuestring == nullptr ||
        !latchkey_util::parsePasscodeId(item->valuestring, wanted)) {
        return lock_access::withTarget(lock_access::invalid(kIdMessage), mac);
    }
    rpc::Reply gated = lock_access::gate(mac, {Feature::Passcode});
    if (!gated.error.empty()) {
        return lock_access::withTarget(std::move(gated), mac);
    }
    rpc::Reply reply = lock_manager::runOnLock(
        mac, "lock.passcodes.delete", [mac, wanted](Session& session, const Record& record, rpc::Reply& out) {
            Passcodes passcodes;
            Status status = Status::Ok;
            if (!listAll(session, record, passcodes, status, out)) {
                return status;
            }
            size_t index = 0;
            if (!findOne(passcodes, record, wanted, index, out)) {
                return Status::Ok;
            }
            LabelTable labels;
            if (!loadLabels(mac, labels, out)) {
                return Status::Ok;
            }
            labels.keepOnly(passcodes.numbers);
            labels.remove(passcodes.numbers[index]);
            if (lock_manager::retainLabels(mac, kLabels, labels) != ESP_OK) {
                out = rpc::fail("storage_error", "cannot preserve the passcode label before deletion");
                return Status::Ok;
            }
            status = session.passcodeDelete(passcodes.items[index].type, passcodes.items[index].code);
            if (status != Status::Ok) {
                return status;
            }
            const bool stored = lock_manager::saveLabels(mac, kLabels, labels) == ESP_OK;
            cJSON* result = cJSON_CreateObject();
            lock_access::addWarnings(result, {stored ? "" : lock_access::kNamesNotStored});
            out = rpc::ok(result);
            return Status::Ok;
        });
    return lock_access::withTarget(std::move(reply), mac);
}

rpc::Reply passcodesClear(const cJSON* params, const rpc::Context&) {
    std::string mac;
    if (!lock_access::readLock(params, mac)) {
        return lock_access::invalid(lock_access::kLockMessage);
    }
    rpc::Reply gated = lock_access::gate(mac, {Feature::Passcode});
    if (!gated.error.empty()) {
        return lock_access::withTarget(std::move(gated), mac);
    }
    rpc::Reply reply = lock_manager::runOnLock(
        mac, "lock.passcodes.clear", [mac](Session& session, const Record&, rpc::Reply& out) {
            if (lock_manager::retainLabels(mac, kLabels, LabelTable{}) != ESP_OK) {
                out = rpc::fail("storage_error", "cannot preserve passcode labels before clearing");
                return Status::Ok;
            }
            const Status status = session.passcodeClear();
            if (status != Status::Ok) {
                return status;
            }
            const bool stored = lock_manager::saveLabels(mac, kLabels, LabelTable{}) == ESP_OK;
            cJSON* result = cJSON_CreateObject();
            lock_access::addWarnings(result, {stored ? "" : lock_access::kNamesNotStored});
            out = rpc::ok(result);
            return Status::Ok;
        });
    return lock_access::withTarget(std::move(reply), mac);
}

}

void registerPasscodes() {
    rpc::registerMethod("lock.passcodes.list", {.audited = false, .job = true}, passcodesList);
    rpc::registerMethod("lock.passcodes.add", {.job = true}, passcodesAdd);
    rpc::registerMethod("lock.passcodes.update", {.job = true}, passcodesUpdate);
    rpc::registerMethod("lock.passcodes.delete", {.job = true}, passcodesDelete);
    rpc::registerMethod("lock.passcodes.clear", {.job = true}, passcodesClear);
}

}
