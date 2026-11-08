// SPDX-License-Identifier: GPL-3.0-or-later
#include <cmath>
#include <cstdint>
#include <cstdio>
#include <cstring>
#include <optional>
#include <string>
#include <utility>
#include <vector>

#include "esp_log.h"
#include "esp_random.h"
#include "mbedtls/platform_util.h"
#include "psa/crypto.h"

#include "clock.h"
#include "events.h"
#include "latchkey_util/ble_adv.h"
#include "latchkey_util/credential_id.h"
#include "latchkey_util/label.h"
#include "latchkey_util/label_table.h"
#include "latchkey_util/lock_time.h"
#include "latchkey_util/passcode_id.h"
#include "latchkey_util/passcode_type.h"
#include "latchkey_util/weekly_window.h"
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
using latchkey_util::PasscodeId;
using latchkey_util::WeeklyWindow;
using store::locks::Record;
using ttlock::Feature;
using ttlock::Passcode;
using ttlock::PasscodeType;
using ttlock::Session;
using ttlock::Status;
using ttlock::Validity;

constexpr const char* TAG = "access";
constexpr size_t kRandomPasscodeDigits = 6;
constexpr int kRandomPasscodeAttempts = 20;
constexpr uint32_t kRandomCeiling = 4294967290u;
constexpr int64_t kLatestUtc = 4102444800;
constexpr char kHexDigits[] = "0123456789abcdef";
constexpr const char* kLockMessage = "lock must be a Bluetooth address like AA:BB:CC:DD:EE:FF";
constexpr const char* kNameMessage = "name must be at most 24 characters (at most 48 bytes)";
constexpr const char* kCodeMessage = "code must be 4 to 9 digits, or left out for a random one";
constexpr const char* kTypeMessage = "type is permanent, timed, one_time or cyclic";
constexpr const char* kIdMessage = "id must be a passcode id from lock.passcodes.list";
constexpr const char* kValidityMessage =
    "validity must be {start, end} in UTC seconds, the end after the start, within the lock's years 2000 to 2099";
constexpr const char* kCycleMessage =
    "cycle must be {days: weekdays 1 (Monday) to 7 (Sunday), start: \"HH:MM\", end: \"HH:MM\"}, ending after it "
    "starts";
constexpr const char* kNoSuchPasscode = "no such passcode on the lock";
constexpr const char* kAdminCodeMessage = "that is the keypad admin passcode: change it with lock.adminPasscode.set";
constexpr const char* kDuplicateMessage = "that passcode is already on the lock";
constexpr const char* kLabelsFullMessage = "the board keeps names for at most 32 entries of each kind per lock";

static_assert(latchkey_util::kMaxLabels == 32 && latchkey_util::kMaxLabelNameCodePoints == 24 &&
                  latchkey_util::kMaxLabelNameBytes == 48,
              "the messages state these limits");

struct Credentials {
    const char* noun;
    const char* collection;
    const char* listMethod;
    const char* enrollMethod;
    const char* validityMethod;
    const char* deleteMethod;
    const char* clearMethod;
    const char* timeoutMessage;
    Feature feature;
    store::labels::Kind labels;
    uint64_t maxId;
    uint8_t scans;
    Status (Session::*list)(std::vector<ttlock::Credential>&);
    Status (Session::*enroll)(const Validity&, const ttlock::EnrollCallback&, uint64_t&);
    Status (Session::*setValidity)(uint64_t, const Validity&);
    Status (Session::*remove)(uint64_t);
    Status (Session::*clear)();
    Status (Session::*addCycle)(uint64_t, const ttlock::WeeklyCycle&);
    Status (Session::*clearCycles)(uint64_t);
};

const Credentials kFingerprints{
    "fingerprint",
    "fingerprints",
    "lock.fingerprints.list",
    "lock.fingerprints.enroll",
    "lock.fingerprints.setValidity",
    "lock.fingerprints.delete",
    "lock.fingerprints.clear",
    "no finger was scanned within 10 s; the lock leaves enrolment by itself",
    Feature::FingerPrint,
    store::labels::Kind::Fingerprints,
    latchkey_util::kMaxFingerprintId,
    4,
    &Session::fingerprintList,
    &Session::fingerprintEnroll,
    &Session::fingerprintSetValidity,
    &Session::fingerprintDelete,
    &Session::fingerprintClear,
    &Session::fingerprintAddCycle,
    &Session::fingerprintClearCycles,
};

const Credentials kCards{
    "card",
    "cards",
    "lock.cards.list",
    "lock.cards.enroll",
    "lock.cards.setValidity",
    "lock.cards.delete",
    "lock.cards.clear",
    "no card was held to the lock within 10 s; the lock leaves enrolment by itself",
    Feature::Ic,
    store::labels::Kind::Cards,
    latchkey_util::kMaxCardNumber,
    1,
    &Session::cardList,
    &Session::cardEnroll,
    &Session::cardSetValidity,
    &Session::cardDelete,
    &Session::cardClear,
    &Session::cardAddCycle,
    &Session::cardClearCycles,
};

class Secret {
public:
    Secret() = default;
    explicit Secret(std::string value) : value_(std::move(value)) {}
    Secret(const Secret& other) : value_(other.value_) {}
    Secret& operator=(const Secret& other) {
        if (this != &other) {
            wipe();
            value_ = other.value_;
        }
        return *this;
    }
    ~Secret() { wipe(); }

    const std::string& get() const { return value_; }
    bool empty() const { return value_.empty(); }

private:
    void wipe() { mbedtls_platform_zeroize(value_.data(), value_.size()); }

    std::string value_;
};

struct Passcodes {
    std::vector<Passcode> items;

    ~Passcodes() {
        for (Passcode& item : items) {
            mbedtls_platform_zeroize(item.code.data(), item.code.size());
        }
    }
};

struct Snapshot {
    Record record;

    ~Snapshot() { mbedtls_platform_zeroize(&record, sizeof(record)); }
};

const latchkey_util::UtcOffsetAt& offsetAt() {
    static const latchkey_util::UtcOffsetAt offset = [](int64_t utc) { return wallclock::utcOffsetAt(utc); };
    return offset;
}

rpc::Reply invalid(const char* message) { return rpc::fail("invalid_argument", message); }

rpc::Reply withTarget(rpc::Reply reply, const std::string& mac) {
    reply.target = mac;
    return reply;
}

const cJSON* member(const cJSON* params, const char* key) { return cJSON_GetObjectItemCaseSensitive(params, key); }

bool absent(const cJSON* item) { return item == nullptr || cJSON_IsNull(item); }

bool isText(const cJSON* item) { return cJSON_IsString(item) && item->valuestring != nullptr; }

bool readLock(const cJSON* params, std::string& out) {
    const cJSON* item = member(params, "lock");
    uint8_t address[latchkey_util::kBleAddressSize];
    if (!isText(item) || !latchkey_util::parseBleAddress(item->valuestring, address)) {
        return false;
    }
    out = latchkey_util::formatBleAddress(address);
    return true;
}

bool isBlank(const char* text) {
    for (const char* c = text; *c != '\0'; ++c) {
        if (std::strchr(" \t\r\n\f\v", *c) == nullptr) {
            return false;
        }
    }
    return true;
}

bool readName(const cJSON* item, std::string& out) {
    if (absent(item)) {
        out.clear();
        return true;
    }
    if (!isText(item)) {
        return false;
    }
    if (isBlank(item->valuestring)) {
        out.clear();
        return true;
    }
    return latchkey_util::normalizeLabel(item->valuestring, latchkey_util::kMaxLabelNameCodePoints, out) &&
           out.size() <= latchkey_util::kMaxLabelNameBytes;
}

bool readCode(const cJSON* item, Secret& out) {
    if (absent(item) || (isText(item) && item->valuestring[0] == '\0')) {
        out = Secret();
        return true;
    }
    if (!isText(item) || !ttlock::isPasscode(item->valuestring)) {
        return false;
    }
    out = Secret(item->valuestring);
    return true;
}

bool readUtc(const cJSON* item, int64_t& out) {
    if (!cJSON_IsNumber(item) || std::floor(item->valuedouble) != item->valuedouble || item->valuedouble < 0 ||
        item->valuedouble > kLatestUtc) {
        return false;
    }
    out = static_cast<int64_t>(item->valuedouble);
    return true;
}

bool readWindow(const cJSON* item, Validity& out) {
    int64_t start = 0;
    int64_t end = 0;
    return cJSON_IsObject(item) && readUtc(member(item, "start"), start) && readUtc(member(item, "end"), end) &&
           latchkey_util::lockValidity(start, end, offsetAt(), out);
}

bool readCycle(const cJSON* item, std::optional<WeeklyWindow>& out) {
    if (absent(item)) {
        out.reset();
        return true;
    }
    const cJSON* days = member(item, "days");
    const cJSON* start = member(item, "start");
    const cJSON* end = member(item, "end");
    if (!cJSON_IsObject(item) || !cJSON_IsArray(days) || !isText(start) || !isText(end)) {
        return false;
    }
    WeeklyWindow window;
    const cJSON* day = nullptr;
    cJSON_ArrayForEach(day, days) {
        if (!cJSON_IsNumber(day) || std::floor(day->valuedouble) != day->valuedouble ||
            !latchkey_util::addWeekday(static_cast<int>(day->valuedouble), window.days)) {
            return false;
        }
    }
    if (!latchkey_util::parseClockTime(start->valuestring, window.startMinute) ||
        !latchkey_util::parseClockTime(end->valuestring, window.endMinute) || !latchkey_util::isWeeklyWindow(window)) {
        return false;
    }
    out = window;
    return true;
}

rpc::Reply gate(const std::string& mac, Feature feature) {
    uint64_t mask = 0;
    rpc::Reply known = lock_manager::featureMask(mac, mask);
    if (!known.error.empty()) {
        return known;
    }
    if (!ttlock::hasFeature(mask, feature)) {
        const std::string message = std::string("the lock does not report ") + ttlock::toString(feature);
        return rpc::fail("unsupported", message.c_str());
    }
    return rpc::ok();
}

rpc::Reply labelsUnreadable(esp_err_t error) {
    ESP_LOGE(TAG, "cannot read the labels: %s", esp_err_to_name(error));
    return rpc::fail("internal", "the board cannot read its names for this lock");
}

bool loadLabels(const Record& record, store::labels::Kind kind, LabelTable& out, rpc::Reply& reply) {
    const esp_err_t error = store::labels::load(record.mac, kind, out);
    if (error != ESP_OK) {
        reply = labelsUnreadable(error);
        return false;
    }
    return true;
}

bool saveLabels(const Record& record, store::labels::Kind kind, const LabelTable& table) {
    const esp_err_t error = store::labels::save(record.mac, kind, table);
    if (error != ESP_OK) {
        ESP_LOGE(TAG, "cannot store the labels: %s", esp_err_to_name(error));
    }
    return error == ESP_OK;
}

void addWarning(cJSON* result, bool stored) {
    if (!stored) {
        cJSON_AddStringToObject(result, "warning", "the lock took the change, but the board could not store its names");
    }
}

bool hmacSha256(const uint8_t* key, size_t keyLength, const uint8_t* message, size_t messageLength,
                uint8_t (&digest)[latchkey_util::kHmacSha256Size]) {
    psa_key_attributes_t attributes = PSA_KEY_ATTRIBUTES_INIT;
    psa_set_key_type(&attributes, PSA_KEY_TYPE_HMAC);
    psa_set_key_bits(&attributes, PSA_BYTES_TO_BITS(keyLength));
    psa_set_key_usage_flags(&attributes, PSA_KEY_USAGE_SIGN_MESSAGE);
    psa_set_key_algorithm(&attributes, PSA_ALG_HMAC(PSA_ALG_SHA_256));
    mbedtls_svc_key_id_t keyId = MBEDTLS_SVC_KEY_ID_INIT;
    const psa_status_t imported = psa_import_key(&attributes, key, keyLength, &keyId);
    psa_reset_key_attributes(&attributes);
    if (imported != PSA_SUCCESS) {
        return false;
    }
    size_t length = 0;
    const psa_status_t computed = psa_mac_compute(keyId, PSA_ALG_HMAC(PSA_ALG_SHA_256), message, messageLength,
                                                  digest, sizeof(digest), &length);
    psa_destroy_key(keyId);
    return computed == PSA_SUCCESS && length == sizeof(digest);
}

bool idOf(const Record& record, const std::string& code, PasscodeId& out) {
    latchkey_util::LockAesKey key{};
    std::memcpy(key.data(), record.aesKey, key.size());
    const bool made = latchkey_util::passcodeId(key, code, hmacSha256, out);
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

bool isAdminCode(const Record& record, const std::string& code) {
    return record.adminPasscode[0] != '\0' && code == record.adminPasscode;
}

const Passcode* findCode(const std::vector<Passcode>& items, const std::string& code) {
    for (const Passcode& item : items) {
        if (item.code == code) {
            return &item;
        }
    }
    return nullptr;
}

cJSON* windowJson(const Validity& validity, bool& ok) {
    int64_t start = 0;
    int64_t end = 0;
    ok = latchkey_util::utcOfLockTime(validity.start, offsetAt(), start) &&
         latchkey_util::utcOfLockTime(validity.end, offsetAt(), end);
    if (!ok) {
        return nullptr;
    }
    cJSON* window = cJSON_CreateObject();
    cJSON_AddNumberToObject(window, "start", static_cast<double>(start));
    cJSON_AddNumberToObject(window, "end", static_cast<double>(end));
    return window;
}

cJSON* cycleJson(const WeeklyWindow& window) {
    cJSON* cycle = cJSON_CreateObject();
    cJSON* days = cJSON_AddArrayToObject(cycle, "days");
    for (uint8_t day : latchkey_util::weekdays(window.days)) {
        cJSON_AddItemToArray(days, cJSON_CreateNumber(day));
    }
    cJSON_AddStringToObject(cycle, "start", latchkey_util::formatClockTime(window.startMinute).c_str());
    cJSON_AddStringToObject(cycle, "end", latchkey_util::formatClockTime(window.endMinute).c_str());
    return cycle;
}

cJSON* passcodeJson(const PasscodeId& id, const Passcode& item, const Label* label, bool admin, bool& ok) {
    ok = true;
    cJSON* entry = cJSON_CreateObject();
    cJSON_AddStringToObject(entry, "id", latchkey_util::formatPasscodeId(id).c_str());
    cJSON_AddStringToObject(entry, "type", latchkey_util::passcodeTypeName(item.type));
    cJSON_AddStringToObject(entry, "name", label != nullptr ? label->name.c_str() : "");
    if (item.type == PasscodeType::Period || item.type == PasscodeType::Count) {
        cJSON* window = windowJson(item.validity, ok);
        cJSON_AddItemToObject(entry, "validity", ok ? window : cJSON_CreateNull());
    } else {
        cJSON_AddNullToObject(entry, "validity");
    }
    cJSON_AddBoolToObject(entry, "managed", label != nullptr && label->managed);
    if (admin) {
        cJSON_AddBoolToObject(entry, "admin", true);
    }
    return entry;
}

rpc::Reply badWindow() {
    return rpc::fail("bad_response", "the lock sent a validity window with a date that cannot exist");
}

struct Listed {
    const Passcode* entry = nullptr;
    PasscodeId id{};
};

bool listPasscodes(Session& session, const Record& record, Passcodes& out, std::vector<PasscodeId>& ids,
                   Status& status, rpc::Reply& reply) {
    status = session.passcodeList(out.items);
    if (status != Status::Ok) {
        return false;
    }
    ids.resize(out.items.size());
    for (size_t i = 0; i < out.items.size(); ++i) {
        if (!idOf(record, out.items[i].code, ids[i])) {
            reply = rpc::fail("internal", "cannot compute a passcode id");
            return false;
        }
    }
    return true;
}

std::vector<uint64_t> numbersOf(const std::vector<PasscodeId>& ids) {
    std::vector<uint64_t> numbers;
    numbers.reserve(ids.size());
    for (const PasscodeId& id : ids) {
        numbers.push_back(latchkey_util::passcodeIdNumber(id));
    }
    return numbers;
}

Listed findId(const Passcodes& passcodes, const std::vector<PasscodeId>& ids, const PasscodeId& wanted) {
    for (size_t i = 0; i < ids.size(); ++i) {
        if (ids[i] == wanted) {
            return Listed{&passcodes.items[i], ids[i]};
        }
    }
    return Listed{};
}

rpc::Reply passcodesList(const cJSON* params, const rpc::Context&) {
    std::string mac;
    if (!readLock(params, mac)) {
        return invalid(kLockMessage);
    }
    rpc::Reply gated = gate(mac, Feature::Passcode);
    if (!gated.error.empty()) {
        return withTarget(std::move(gated), mac);
    }
    rpc::Reply reply = lock_manager::runOnLock(
        mac, "lock.passcodes.list", [](Session& session, const Record& record, rpc::Reply& out) {
            Passcodes passcodes;
            std::vector<PasscodeId> ids;
            Status status = Status::Ok;
            if (!listPasscodes(session, record, passcodes, ids, status, out)) {
                return status;
            }
            LabelTable labels;
            if (!loadLabels(record, store::labels::Kind::Passcodes, labels, out)) {
                return Status::Ok;
            }
            cJSON* result = cJSON_CreateObject();
            cJSON* list = cJSON_AddArrayToObject(result, "passcodes");
            for (size_t i = 0; i < ids.size(); ++i) {
                const Passcode& item = passcodes.items[i];
                const Label* label = labels.find(latchkey_util::passcodeIdNumber(ids[i]));
                bool ok = true;
                cJSON_AddItemToArray(list, passcodeJson(ids[i], item, label, isAdminCode(record, item.code), ok));
                if (!ok) {
                    cJSON_Delete(result);
                    out = badWindow();
                    return Status::Ok;
                }
            }
            if (labels.keepOnly(numbersOf(ids))) {
                saveLabels(record, store::labels::Kind::Passcodes, labels);
            }
            out = rpc::ok(result);
            return Status::Ok;
        });
    return withTarget(std::move(reply), mac);
}

struct AddRequest {
    std::string mac;
    PasscodeType type = PasscodeType::Permanent;
    Secret code;
    std::string name;
    Validity validity;
};

rpc::Reply readAdd(const cJSON* params, AddRequest& out) {
    if (!readLock(params, out.mac)) {
        return invalid(kLockMessage);
    }
    const cJSON* type = member(params, "type");
    if (!isText(type) || !latchkey_util::passcodeTypeOf(type->valuestring, out.type)) {
        return invalid(kTypeMessage);
    }
    if (!readCode(member(params, "code"), out.code)) {
        return invalid(kCodeMessage);
    }
    if (!readName(member(params, "name"), out.name)) {
        return invalid(kNameMessage);
    }
    if (out.type == PasscodeType::Period || out.type == PasscodeType::Count) {
        if (!readWindow(member(params, "validity"), out.validity)) {
            return invalid(kValidityMessage);
        }
    }
    return rpc::ok();
}

Secret uniqueCode(const Passcodes& passcodes, const Record& record) {
    for (int attempt = 0; attempt < kRandomPasscodeAttempts; ++attempt) {
        Secret code(randomDigits(kRandomPasscodeDigits));
        if (findCode(passcodes.items, code.get()) == nullptr && !isAdminCode(record, code.get())) {
            return code;
        }
    }
    return Secret();
}

Status addPasscode(const AddRequest& request, Session& session, const Record& record, rpc::Reply& out) {
    Passcodes passcodes;
    std::vector<PasscodeId> ids;
    Status status = Status::Ok;
    if (!listPasscodes(session, record, passcodes, ids, status, out)) {
        return status;
    }
    LabelTable labels;
    if (!loadLabels(record, store::labels::Kind::Passcodes, labels, out)) {
        return Status::Ok;
    }
    labels.keepOnly(numbersOf(ids));
    Secret code = request.code.empty() ? uniqueCode(passcodes, record) : request.code;
    if (code.empty()) {
        out = rpc::fail("internal", "cannot draw a random passcode the lock does not already hold");
        return Status::Ok;
    }
    if (isAdminCode(record, code.get())) {
        out = invalid(kAdminCodeMessage);
        return Status::Ok;
    }
    if (findCode(passcodes.items, code.get()) != nullptr) {
        out = rpc::fail("lock_error", kDuplicateMessage);
        return Status::Ok;
    }
    PasscodeId id{};
    if (!idOf(record, code.get(), id)) {
        out = rpc::fail("internal", "cannot compute a passcode id");
        return Status::Ok;
    }
    const uint64_t number = latchkey_util::passcodeIdNumber(id);
    if (!labels.hasRoomFor(number)) {
        out = rpc::fail("too_many", kLabelsFullMessage);
        return Status::Ok;
    }
    Passcode passcode;
    passcode.type = request.type;
    passcode.code = code.get();
    if (request.type != PasscodeType::Permanent) {
        passcode.validity = request.validity;
    }
    status = session.passcodeAdd(passcode);
    mbedtls_platform_zeroize(passcode.code.data(), passcode.code.size());
    if (status != Status::Ok) {
        return status;
    }
    Label label;
    label.id = number;
    label.managed = true;
    label.name = request.name;
    labels.put(label);
    const bool stored = saveLabels(record, store::labels::Kind::Passcodes, labels);
    Passcode shown;
    shown.type = request.type;
    shown.validity = passcode.validity;
    bool ok = true;
    cJSON* entry = passcodeJson(id, shown, labels.find(number), false, ok);
    cJSON_AddStringToObject(entry, "code", code.get().c_str());
    cJSON* result = cJSON_CreateObject();
    cJSON_AddItemToObject(result, "passcode", entry);
    addWarning(result, stored);
    out = rpc::ok(result);
    return Status::Ok;
}

rpc::Reply passcodesAdd(const cJSON* params, const rpc::Context&) {
    AddRequest request;
    rpc::Reply problem = readAdd(params, request);
    if (!problem.error.empty()) {
        return withTarget(std::move(problem), request.mac);
    }
    rpc::Reply gated = gate(request.mac, Feature::Passcode);
    if (!gated.error.empty()) {
        return withTarget(std::move(gated), request.mac);
    }
    if (request.type == PasscodeType::Cyclic) {
        return withTarget(rpc::fail("unsupported",
                                    "this board cannot add cyclic passcodes yet: no reference shows how the lock "
                                    "takes their weekly window"),
                          request.mac);
    }
    rpc::Reply reply = lock_manager::runOnLock(
        request.mac, "lock.passcodes.add",
        [request](Session& session, const Record& record, rpc::Reply& out) {
            return addPasscode(request, session, record, out);
        });
    return withTarget(std::move(reply), request.mac);
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
    if (!readLock(params, out.mac)) {
        return invalid(kLockMessage);
    }
    const cJSON* id = member(params, "id");
    if (!isText(id) || !latchkey_util::parsePasscodeId(id->valuestring, out.id)) {
        return invalid(kIdMessage);
    }
    if (!readCode(member(params, "code"), out.code)) {
        return invalid(kCodeMessage);
    }
    const cJSON* name = member(params, "name");
    out.renames = name != nullptr;
    if (!readName(name, out.name)) {
        return invalid(kNameMessage);
    }
    const cJSON* validity = member(params, "validity");
    out.moves = validity != nullptr;
    if (out.moves && !readWindow(validity, out.validity)) {
        return invalid(kValidityMessage);
    }
    return rpc::ok();
}

Status updatePasscode(const UpdateRequest& request, Session& session, const Record& record, rpc::Reply& out) {
    Passcodes passcodes;
    std::vector<PasscodeId> ids;
    Status status = Status::Ok;
    if (!listPasscodes(session, record, passcodes, ids, status, out)) {
        return status;
    }
    const Listed found = findId(passcodes, ids, request.id);
    if (found.entry == nullptr) {
        out = invalid(kNoSuchPasscode);
        return Status::Ok;
    }
    const Passcode& entry = *found.entry;
    if (isAdminCode(record, entry.code)) {
        out = invalid(kAdminCodeMessage);
        return Status::Ok;
    }
    LabelTable labels;
    if (!loadLabels(record, store::labels::Kind::Passcodes, labels, out)) {
        return Status::Ok;
    }
    labels.keepOnly(numbersOf(ids));
    const Secret code = request.code.empty() ? Secret(entry.code) : request.code;
    const bool recoded = code.get() != entry.code;
    if (recoded && isAdminCode(record, code.get())) {
        out = invalid(kAdminCodeMessage);
        return Status::Ok;
    }
    if (recoded && findCode(passcodes.items, code.get()) != nullptr) {
        out = rpc::fail("lock_error", kDuplicateMessage);
        return Status::Ok;
    }
    PasscodeId id = found.id;
    if (recoded && !idOf(record, code.get(), id)) {
        out = rpc::fail("internal", "cannot compute a passcode id");
        return Status::Ok;
    }
    const uint64_t oldNumber = latchkey_util::passcodeIdNumber(found.id);
    const uint64_t number = latchkey_util::passcodeIdNumber(id);
    const Label* old = labels.find(oldNumber);
    Label label = old != nullptr ? *old : Label{};
    label.id = number;
    if (request.renames) {
        label.name = request.name;
    }
    labels.remove(oldNumber);
    if (!labels.hasRoomFor(number) && (label.managed || !label.name.empty())) {
        out = rpc::fail("too_many", kLabelsFullMessage);
        return Status::Ok;
    }
    const bool timed = entry.type == PasscodeType::Period || entry.type == PasscodeType::Count;
    Passcode changed;
    changed.type = entry.type;
    changed.code = code.get();
    changed.validity = timed && request.moves ? request.validity : entry.validity;
    if (recoded || changed.validity != entry.validity) {
        status = session.passcodeUpdate(entry.code, changed);
        if (status != Status::Ok) {
            mbedtls_platform_zeroize(changed.code.data(), changed.code.size());
            return status;
        }
    }
    mbedtls_platform_zeroize(changed.code.data(), changed.code.size());
    labels.put(label);
    const bool stored = saveLabels(record, store::labels::Kind::Passcodes, labels);
    bool ok = true;
    cJSON* result = cJSON_CreateObject();
    cJSON_AddItemToObject(result, "passcode", passcodeJson(id, changed, labels.find(number), false, ok));
    addWarning(result, stored);
    if (!ok) {
        cJSON_Delete(result);
        out = badWindow();
        return Status::Ok;
    }
    out = rpc::ok(result);
    return Status::Ok;
}

rpc::Reply passcodesUpdate(const cJSON* params, const rpc::Context&) {
    UpdateRequest request;
    rpc::Reply problem = readUpdate(params, request);
    if (!problem.error.empty()) {
        return withTarget(std::move(problem), request.mac);
    }
    rpc::Reply gated = gate(request.mac, Feature::ModifyPasscodeFunction);
    if (!gated.error.empty()) {
        return withTarget(std::move(gated), request.mac);
    }
    rpc::Reply reply = lock_manager::runOnLock(
        request.mac, "lock.passcodes.update",
        [request](Session& session, const Record& record, rpc::Reply& out) {
            return updatePasscode(request, session, record, out);
        });
    return withTarget(std::move(reply), request.mac);
}

rpc::Reply passcodesDelete(const cJSON* params, const rpc::Context&) {
    std::string mac;
    if (!readLock(params, mac)) {
        return invalid(kLockMessage);
    }
    const cJSON* item = member(params, "id");
    PasscodeId wanted{};
    if (!isText(item) || !latchkey_util::parsePasscodeId(item->valuestring, wanted)) {
        return withTarget(invalid(kIdMessage), mac);
    }
    rpc::Reply gated = gate(mac, Feature::Passcode);
    if (!gated.error.empty()) {
        return withTarget(std::move(gated), mac);
    }
    rpc::Reply reply = lock_manager::runOnLock(
        mac, "lock.passcodes.delete", [wanted](Session& session, const Record& record, rpc::Reply& out) {
            Passcodes passcodes;
            std::vector<PasscodeId> ids;
            Status status = Status::Ok;
            if (!listPasscodes(session, record, passcodes, ids, status, out)) {
                return status;
            }
            const Listed found = findId(passcodes, ids, wanted);
            if (found.entry == nullptr) {
                out = invalid(kNoSuchPasscode);
                return Status::Ok;
            }
            if (isAdminCode(record, found.entry->code)) {
                out = invalid(kAdminCodeMessage);
                return Status::Ok;
            }
            LabelTable labels;
            if (!loadLabels(record, store::labels::Kind::Passcodes, labels, out)) {
                return Status::Ok;
            }
            status = session.passcodeDelete(found.entry->type, found.entry->code);
            if (status != Status::Ok) {
                return status;
            }
            labels.keepOnly(numbersOf(ids));
            labels.remove(latchkey_util::passcodeIdNumber(found.id));
            cJSON* result = cJSON_CreateObject();
            addWarning(result, saveLabels(record, store::labels::Kind::Passcodes, labels));
            out = rpc::ok(result);
            return Status::Ok;
        });
    return withTarget(std::move(reply), mac);
}

rpc::Reply passcodesClear(const cJSON* params, const rpc::Context&) {
    std::string mac;
    if (!readLock(params, mac)) {
        return invalid(kLockMessage);
    }
    rpc::Reply gated = gate(mac, Feature::Passcode);
    if (!gated.error.empty()) {
        return withTarget(std::move(gated), mac);
    }
    rpc::Reply reply = lock_manager::runOnLock(
        mac, "lock.passcodes.clear", [](Session& session, const Record& record, rpc::Reply& out) {
            const Status status = session.passcodeClear();
            if (status != Status::Ok) {
                return status;
            }
            cJSON* result = cJSON_CreateObject();
            addWarning(result, saveLabels(record, store::labels::Kind::Passcodes, LabelTable{}));
            out = rpc::ok(result);
            return Status::Ok;
        });
    return withTarget(std::move(reply), mac);
}

bool readCredentialId(const cJSON* params, const Credentials& kind, uint64_t& out) {
    const cJSON* item = member(params, "id");
    return isText(item) && latchkey_util::parseCredentialId(item->valuestring, kind.maxId, out);
}

std::string credentialIdMessage(const Credentials& kind) {
    return std::string("id must be a ") + kind.noun + " id from " + kind.listMethod + ", as text";
}

bool credentialJson(cJSON* parent, const char* key, uint64_t id, const Validity& validity, const Label* label) {
    cJSON* entry = cJSON_CreateObject();
    cJSON_AddStringToObject(entry, "id", latchkey_util::formatCredentialId(id).c_str());
    cJSON_AddStringToObject(entry, "name", label != nullptr ? label->name.c_str() : "");
    bool ok = true;
    if (latchkey_util::isPermanent(validity)) {
        cJSON_AddNullToObject(entry, "validity");
    } else {
        cJSON* window = windowJson(validity, ok);
        cJSON_AddItemToObject(entry, "validity", ok ? window : cJSON_CreateNull());
    }
    if (label != nullptr && label->cycle.has_value()) {
        cJSON_AddItemToObject(entry, "cycle", cycleJson(*label->cycle));
    }
    if (key != nullptr) {
        cJSON_AddItemToObject(parent, key, entry);
    } else {
        cJSON_AddItemToArray(parent, entry);
    }
    return ok;
}

rpc::Reply credentialsList(const Credentials& kind, const cJSON* params) {
    std::string mac;
    if (!readLock(params, mac)) {
        return invalid(kLockMessage);
    }
    rpc::Reply gated = gate(mac, kind.feature);
    if (!gated.error.empty()) {
        return withTarget(std::move(gated), mac);
    }
    rpc::Reply reply =
        lock_manager::runOnLock(mac, kind.listMethod, [&kind](Session& session, const Record& record, rpc::Reply& out) {
            std::vector<ttlock::Credential> items;
            const Status status = (session.*kind.list)(items);
            if (status != Status::Ok) {
                return status;
            }
            LabelTable labels;
            if (!loadLabels(record, kind.labels, labels, out)) {
                return Status::Ok;
            }
            cJSON* result = cJSON_CreateObject();
            cJSON* list = cJSON_AddArrayToObject(result, kind.collection);
            std::vector<uint64_t> present;
            for (const ttlock::Credential& item : items) {
                present.push_back(item.id);
                if (!credentialJson(list, nullptr, item.id, item.validity, labels.find(item.id))) {
                    cJSON_Delete(result);
                    out = badWindow();
                    return Status::Ok;
                }
            }
            if (labels.keepOnly(present)) {
                saveLabels(record, kind.labels, labels);
            }
            out = rpc::ok(result);
            return Status::Ok;
        });
    return withTarget(std::move(reply), mac);
}

void publishProgress(const std::string& mac, const Credentials& kind, const char* stage, int scans,
                     std::optional<uint64_t> id) {
    cJSON* data = cJSON_CreateObject();
    cJSON_AddStringToObject(data, "lock", mac.c_str());
    cJSON_AddStringToObject(data, "kind", kind.noun);
    cJSON_AddStringToObject(data, "stage", stage);
    if (id.has_value()) {
        cJSON_AddStringToObject(data, "id", latchkey_util::formatCredentialId(*id).c_str());
    } else {
        cJSON_AddNumberToObject(data, "scans", scans);
        cJSON_AddNumberToObject(data, "total", kind.scans);
    }
    events::publish("enroll.progress", data);
}

rpc::Reply enrolmentEnded(const Credentials& kind, uint8_t scans, uint8_t lockError) {
    char message[120];
    std::snprintf(message, sizeof(message), "the lock ended the %s enrolment after %u of %u scans (lock error 0x%02x)",
                  kind.noun, static_cast<unsigned>(scans), static_cast<unsigned>(kind.scans), lockError);
    return rpc::fail("lock_error", message);
}

rpc::Reply credentialsEnroll(const Credentials& kind, const cJSON* params) {
    std::string mac;
    if (!readLock(params, mac)) {
        return invalid(kLockMessage);
    }
    std::string name;
    if (!readName(member(params, "name"), name)) {
        return withTarget(invalid(kNameMessage), mac);
    }
    Validity validity;
    const cJSON* window = member(params, "validity");
    if (!absent(window) && !readWindow(window, validity)) {
        return withTarget(invalid(kValidityMessage), mac);
    }
    rpc::Reply gated = gate(mac, kind.feature);
    if (!gated.error.empty()) {
        return withTarget(std::move(gated), mac);
    }
    rpc::Reply reply = lock_manager::runOnLock(
        mac, kind.enrollMethod,
        [&kind, mac, name, validity](Session& session, const Record& record, rpc::Reply& out) {
            LabelTable labels;
            if (!loadLabels(record, kind.labels, labels, out)) {
                return Status::Ok;
            }
            if (!name.empty() && labels.size() >= latchkey_util::kMaxLabels) {
                out = rpc::fail("too_many", kLabelsFullMessage);
                return Status::Ok;
            }
            bool entered = false;
            uint8_t scans = 0;
            const ttlock::EnrollCallback progress = [&mac, &kind, &entered,
                                                     &scans](const ttlock::EnrollProgress& step) {
                const bool waiting = step.stage == ttlock::EnrollStage::Waiting;
                entered = true;
                scans = step.scans;
                publishProgress(mac, kind, waiting ? "waiting" : "progress", step.scans, std::nullopt);
            };
            uint64_t id = 0;
            const Status status = (session.*kind.enroll)(validity, progress, id);
            if (status == Status::Timeout) {
                out = rpc::fail("timeout", kind.timeoutMessage);
            } else if (status == Status::LockError && entered) {
                out = enrolmentEnded(kind, scans, session.lockErrorCode());
            }
            if (status != Status::Ok) {
                return status;
            }
            publishProgress(mac, kind, "added", kind.scans, id);
            Label label;
            label.id = id;
            label.name = name;
            labels.put(label);
            const bool stored = saveLabels(record, kind.labels, labels);
            cJSON* result = cJSON_CreateObject();
            credentialJson(result, kind.noun, id, validity, labels.find(id));
            addWarning(result, stored);
            out = rpc::ok(result);
            return Status::Ok;
        });
    return withTarget(std::move(reply), mac);
}

Status applyCycle(const Credentials& kind, Session& session, uint64_t id, const std::optional<WeeklyWindow>& cycle,
                  const Label* old) {
    if (!cycle.has_value() && (old == nullptr || !old->cycle.has_value())) {
        return Status::Ok;
    }
    Status status = (session.*kind.clearCycles)(id);
    if (status != Status::Ok || !cycle.has_value()) {
        return status;
    }
    for (const ttlock::WeeklyCycle& day : latchkey_util::weeklyCycles(*cycle)) {
        status = (session.*kind.addCycle)(id, day);
        if (status != Status::Ok) {
            return status;
        }
    }
    return Status::Ok;
}

rpc::Reply credentialsSetValidity(const Credentials& kind, const cJSON* params) {
    std::string mac;
    if (!readLock(params, mac)) {
        return invalid(kLockMessage);
    }
    uint64_t id = 0;
    if (!readCredentialId(params, kind, id)) {
        return withTarget(invalid(credentialIdMessage(kind).c_str()), mac);
    }
    Validity validity;
    const cJSON* window = member(params, "validity");
    if (!absent(window) && !readWindow(window, validity)) {
        return withTarget(invalid(kValidityMessage), mac);
    }
    std::optional<WeeklyWindow> cycle;
    if (!readCycle(member(params, "cycle"), cycle)) {
        return withTarget(invalid(kCycleMessage), mac);
    }
    rpc::Reply gated = gate(mac, kind.feature);
    if (gated.error.empty() && cycle.has_value()) {
        gated = gate(mac, Feature::CyclicIcOrFingerPrint);
    }
    if (!gated.error.empty()) {
        return withTarget(std::move(gated), mac);
    }
    rpc::Reply reply = lock_manager::runOnLock(
        mac, kind.validityMethod,
        [&kind, id, validity, cycle](Session& session, const Record& record, rpc::Reply& out) {
            LabelTable labels;
            if (!loadLabels(record, kind.labels, labels, out)) {
                return Status::Ok;
            }
            const Label* old = labels.find(id);
            Label label = old != nullptr ? *old : Label{};
            label.id = id;
            label.cycle = cycle;
            if (!labels.hasRoomFor(id) && cycle.has_value()) {
                out = rpc::fail("too_many", kLabelsFullMessage);
                return Status::Ok;
            }
            Status status = (session.*kind.setValidity)(id, validity);
            if (status == Status::Ok) {
                status = applyCycle(kind, session, id, cycle, old);
            }
            if (status != Status::Ok) {
                return status;
            }
            labels.put(label);
            const bool stored = saveLabels(record, kind.labels, labels);
            cJSON* result = cJSON_CreateObject();
            credentialJson(result, kind.noun, id, validity, labels.find(id));
            addWarning(result, stored);
            out = rpc::ok(result);
            return Status::Ok;
        });
    return withTarget(std::move(reply), mac);
}

rpc::Reply credentialsDelete(const Credentials& kind, const cJSON* params) {
    std::string mac;
    if (!readLock(params, mac)) {
        return invalid(kLockMessage);
    }
    uint64_t id = 0;
    if (!readCredentialId(params, kind, id)) {
        return withTarget(invalid(credentialIdMessage(kind).c_str()), mac);
    }
    rpc::Reply gated = gate(mac, kind.feature);
    if (!gated.error.empty()) {
        return withTarget(std::move(gated), mac);
    }
    rpc::Reply reply = lock_manager::runOnLock(
        mac, kind.deleteMethod, [&kind, id](Session& session, const Record& record, rpc::Reply& out) {
            LabelTable labels;
            if (!loadLabels(record, kind.labels, labels, out)) {
                return Status::Ok;
            }
            const Status status = (session.*kind.remove)(id);
            if (status != Status::Ok) {
                return status;
            }
            cJSON* result = cJSON_CreateObject();
            if (labels.remove(id)) {
                addWarning(result, saveLabels(record, kind.labels, labels));
            }
            out = rpc::ok(result);
            return Status::Ok;
        });
    return withTarget(std::move(reply), mac);
}

rpc::Reply credentialsClear(const Credentials& kind, const cJSON* params) {
    std::string mac;
    if (!readLock(params, mac)) {
        return invalid(kLockMessage);
    }
    rpc::Reply gated = gate(mac, kind.feature);
    if (!gated.error.empty()) {
        return withTarget(std::move(gated), mac);
    }
    rpc::Reply reply = lock_manager::runOnLock(
        mac, kind.clearMethod, [&kind](Session& session, const Record& record, rpc::Reply& out) {
            const Status status = (session.*kind.clear)();
            if (status != Status::Ok) {
                return status;
            }
            cJSON* result = cJSON_CreateObject();
            addWarning(result, saveLabels(record, kind.labels, LabelTable{}));
            out = rpc::ok(result);
            return Status::Ok;
        });
    return withTarget(std::move(reply), mac);
}

struct AdminRequest {
    std::string mac;
    Secret code;
};

rpc::Reply readAdminSet(const cJSON* params, AdminRequest& out) {
    if (!readLock(params, out.mac)) {
        return invalid(kLockMessage);
    }
    if (!readCode(member(params, "code"), out.code)) {
        return withTarget(invalid(kCodeMessage), out.mac);
    }
    return withTarget(gate(out.mac, Feature::Passcode), out.mac);
}

rpc::Reply checkAdminSet(const cJSON* params, const rpc::Context&) {
    AdminRequest request;
    return readAdminSet(params, request);
}

rpc::Reply adminSet(const cJSON* params, const rpc::Context&) {
    AdminRequest request;
    rpc::Reply problem = readAdminSet(params, request);
    if (!problem.error.empty()) {
        return problem;
    }
    const bool generated = request.code.empty();
    const Secret code = generated ? Secret(randomDigits(ttlock::kAdminPasscodeDigits)) : request.code;
    rpc::Reply reply = lock_manager::runOnLock(
        request.mac, "lock.adminPasscode.set",
        [mac = request.mac, code, generated](Session& session, const Record&, rpc::Reply& out) {
            const Status status = session.setAdminPasscode(code.get());
            if (status != Status::Ok) {
                return status;
            }
            const bool stored = lock_manager::storeAdminPasscode(mac, code.get());
            cJSON* result = cJSON_CreateObject();
            if (generated) {
                cJSON_AddStringToObject(result, "code", code.get().c_str());
            }
            if (!stored) {
                cJSON_AddStringToObject(result, "warning",
                                        "the lock took the new admin passcode, but the board could not store its copy");
            }
            out = rpc::ok(result);
            return Status::Ok;
        });
    return withTarget(std::move(reply), request.mac);
}

rpc::Reply storedAdminCode(const Record& record) {
    if (!ttlock::isPasscode(record.adminPasscode)) {
        return rpc::fail("unavailable", "the board holds no admin passcode for this lock");
    }
    cJSON* result = cJSON_CreateObject();
    cJSON_AddStringToObject(result, "code", record.adminPasscode);
    cJSON_AddStringToObject(result, "source", "board");
    return rpc::ok(result);
}

rpc::Reply checkAdminGet(const cJSON* params, const rpc::Context&) {
    std::string mac;
    if (!readLock(params, mac)) {
        return invalid(kLockMessage);
    }
    if (!lock_manager::holds(mac)) {
        return withTarget(rpc::fail("not_paired", "the board has no keys for this lock"), mac);
    }
    return withTarget(rpc::ok(), mac);
}

rpc::Reply adminGet(const cJSON* params, const rpc::Context& context) {
    rpc::Reply problem = checkAdminGet(params, context);
    if (!problem.error.empty()) {
        return problem;
    }
    const std::string mac = problem.target;
    uint64_t mask = 0;
    rpc::Reply known = lock_manager::featureMask(mac, mask);
    if (!known.error.empty()) {
        return withTarget(std::move(known), mac);
    }
    if (!ttlock::hasFeature(mask, Feature::GetAdminCode)) {
        Snapshot snapshot;
        if (!lock_manager::record(mac, snapshot.record)) {
            return withTarget(rpc::fail("not_paired", "the board has no keys for this lock"), mac);
        }
        return withTarget(storedAdminCode(snapshot.record), mac);
    }
    rpc::Reply reply = lock_manager::runOnLock(
        mac, "lock.adminPasscode.get", [](Session& session, const Record& record, rpc::Reply& out) {
            Secret read;
            std::string code;
            const Status status = session.adminPasscodeGet(code);
            read = Secret(std::move(code));
            const bool usable = status == Status::Ok && ttlock::isPasscode(read.get());
            if (!usable && status != Status::Ok && status != Status::BadResponse && status != Status::LockError) {
                return status;
            }
            if (!usable) {
                ESP_LOGW(TAG, "the lock's admin passcode reply was not usable (%s): answering with the board's copy",
                         ttlock::toString(status));
                out = storedAdminCode(record);
                return Status::Ok;
            }
            cJSON* result = cJSON_CreateObject();
            cJSON_AddStringToObject(result, "code", read.get().c_str());
            cJSON_AddStringToObject(result, "source", "lock");
            cJSON_AddBoolToObject(result, "matchesBoard", read.get() == record.adminPasscode);
            out = rpc::ok(result);
            return Status::Ok;
        });
    return withTarget(std::move(reply), mac);
}

rpc::Reply adminRaw(const cJSON* params, const rpc::Context&) {
    std::string mac;
    if (!readLock(params, mac)) {
        return invalid(kLockMessage);
    }
    rpc::Reply gated = gate(mac, Feature::GetAdminCode);
    if (!gated.error.empty()) {
        return withTarget(std::move(gated), mac);
    }
    rpc::Reply reply =
        lock_manager::runOnLock(mac, "lock.adminPasscode.raw", [](Session& session, const Record&, rpc::Reply& out) {
            ttlock::Bytes data;
            const Status status = session.adminPasscodeGetRaw(data);
            if (status != Status::Ok) {
                return status;
            }
            std::string hex(2 * data.size(), '0');
            for (size_t i = 0; i < data.size(); ++i) {
                hex[2 * i] = kHexDigits[data[i] >> 4];
                hex[2 * i + 1] = kHexDigits[data[i] & 0x0F];
            }
            mbedtls_platform_zeroize(data.data(), data.size());
            cJSON* result = cJSON_CreateObject();
            cJSON_AddStringToObject(result, "reply", hex.c_str());
            mbedtls_platform_zeroize(hex.data(), hex.size());
            out = rpc::ok(result);
            return Status::Ok;
        });
    return withTarget(std::move(reply), mac);
}

rpc::Handler forKind(rpc::Reply (*method)(const Credentials&, const cJSON*), const Credentials& kind) {
    return [method, &kind](const cJSON* params, const rpc::Context&) { return method(kind, params); };
}

void registerCredentials(const Credentials& kind) {
    rpc::registerMethod(kind.listMethod, {.audited = false, .job = true}, forKind(credentialsList, kind));
    rpc::registerMethod(kind.enrollMethod, {.job = true}, forKind(credentialsEnroll, kind));
    rpc::registerMethod(kind.validityMethod, {.job = true}, forKind(credentialsSetValidity, kind));
    rpc::registerMethod(kind.deleteMethod, {.job = true}, forKind(credentialsDelete, kind));
    rpc::registerMethod(kind.clearMethod, {.job = true}, forKind(credentialsClear, kind));
}

}

void registerAccess() {
    rpc::registerMethod("lock.passcodes.list", {.audited = false, .job = true}, passcodesList);
    rpc::registerMethod("lock.passcodes.add", {.job = true}, passcodesAdd);
    rpc::registerMethod("lock.passcodes.update", {.job = true}, passcodesUpdate);
    rpc::registerMethod("lock.passcodes.delete", {.job = true}, passcodesDelete);
    rpc::registerMethod("lock.passcodes.clear", {.job = true}, passcodesClear);
    registerCredentials(kFingerprints);
    registerCredentials(kCards);
    rpc::registerMethod("lock.adminPasscode.set", {.needsButton = true, .job = true}, adminSet, checkAdminSet);
    rpc::registerMethod("lock.adminPasscode.get", {.needsButton = true, .job = true}, adminGet, checkAdminGet);
    rpc::registerMethod("lock.adminPasscode.raw", {.serialOnly = true, .audited = false}, adminRaw);
}

}
