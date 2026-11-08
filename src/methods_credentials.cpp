// SPDX-License-Identifier: GPL-3.0-or-later
#include <cstdint>
#include <cstdio>
#include <optional>
#include <string>
#include <utility>
#include <vector>

#include "access_requests.h"
#include "events.h"
#include "latchkey_util/access_json.h"
#include "latchkey_util/credential_id.h"
#include "latchkey_util/label_table.h"
#include "latchkey_util/lock_time.h"
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
using latchkey_util::WeeklyWindow;
using store::locks::Record;
using ttlock::Feature;
using ttlock::Session;
using ttlock::Status;
using ttlock::Validity;

constexpr uint64_t kProbeId = UINT64_MAX;

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
    "no finger was scanned and the lock sent nothing for 10 s, so the board stopped waiting",
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
    "no card was held to the lock and the lock sent nothing for 10 s, so the board stopped waiting",
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

std::string idMessage(const Credentials& kind) {
    return std::string("id must be a ") + kind.noun + " id from " + kind.listMethod + ", as text";
}

bool loadLabels(const std::string& mac, const Credentials& kind, LabelTable& out, rpc::Reply& reply) {
    const esp_err_t error = lock_manager::loadLabels(mac, kind.labels, out);
    if (error != ESP_OK) {
        reply = lock_access::labelsUnreadable(error);
        return false;
    }
    return true;
}

rpc::Reply checkRoom(const std::string& mac, const Credentials& kind, const Label& wanted) {
    LabelTable labels;
    rpc::Reply problem;
    if (!loadLabels(mac, kind, labels, problem)) {
        return problem;
    }
    if (!labels.put(wanted)) {
        return rpc::fail("too_many", lock_access::kLabelsFullMessage);
    }
    return lock_manager::labelsFit(mac, kind.labels, labels) ? rpc::ok() : lock_access::storageFull();
}

bool appendEntry(std::string& out, uint64_t id, const Validity& validity, const Label* label) {
    latchkey_util::CredentialView view;
    view.id = id;
    view.name = label != nullptr ? std::string_view(label->name) : std::string_view();
    if (label != nullptr) {
        view.cycle = label->cycle;
    }
    if (!latchkey_util::isPermanent(validity)) {
        latchkey_util::UtcWindow window;
        if (!lock_access::utcWindow(validity, window)) {
            return false;
        }
        view.window = window;
    }
    latchkey_util::appendCredentialJson(out, view);
    return true;
}

rpc::Reply badWindow() {
    return rpc::fail("bad_response", "the lock sent a validity window with a date that cannot exist");
}

rpc::Reply entryResult(const Credentials& kind, uint64_t id, const Validity& validity, const Label* label,
                       bool stored) {
    std::string text;
    if (!appendEntry(text, id, validity, label)) {
        return badWindow();
    }
    cJSON* result = cJSON_CreateObject();
    cJSON_AddItemToObject(result, kind.noun, lock_access::rawJson(text));
    lock_access::addWarnings(result, {stored ? "" : lock_access::kNamesNotStored});
    return rpc::ok(result);
}

rpc::Reply credentialsList(const Credentials& kind, const cJSON* params) {
    std::string mac;
    if (!lock_access::readLock(params, mac)) {
        return lock_access::invalid(lock_access::kLockMessage);
    }
    rpc::Reply gated = lock_access::gate(mac, {kind.feature});
    if (!gated.error.empty()) {
        return lock_access::withTarget(std::move(gated), mac);
    }
    rpc::Reply reply = lock_manager::runOnLock(
        mac, kind.listMethod, [&kind, mac](Session& session, const Record&, rpc::Reply& out) {
            std::vector<ttlock::Credential> items;
            const Status status = (session.*kind.list)(items);
            if (status != Status::Ok) {
                return status;
            }
            LabelTable labels;
            if (!loadLabels(mac, kind, labels, out)) {
                return Status::Ok;
            }
            size_t bound = 2;
            std::vector<uint64_t> present;
            present.reserve(items.size());
            for (const ttlock::Credential& item : items) {
                const Label* label = labels.find(item.id);
                bound += latchkey_util::credentialJsonBound(label != nullptr ? label->name.size() : 0);
                present.push_back(item.id);
            }
            if (!lock_access::listFits(bound)) {
                out = lock_access::tooLarge(items.size(), kind.collection);
                return Status::Ok;
            }
            std::string text;
            text.reserve(bound);
            text += '[';
            for (size_t i = 0; i < items.size(); ++i) {
                if (i > 0) {
                    text += ',';
                }
                if (!appendEntry(text, items[i].id, items[i].validity, labels.find(items[i].id))) {
                    out = badWindow();
                    return Status::Ok;
                }
            }
            text += ']';
            if (labels.keepOnly(present)) {
                lock_manager::saveLabels(mac, kind.labels, labels);
            }
            cJSON* result = cJSON_CreateObject();
            cJSON_AddItemToObject(result, kind.collection, lock_access::rawJson(text));
            out = rpc::ok(result);
            return Status::Ok;
        });
    return lock_access::withTarget(std::move(reply), mac);
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
    if (!lock_access::readLock(params, mac)) {
        return lock_access::invalid(lock_access::kLockMessage);
    }
    std::string name;
    if (!lock_access::readName(lock_access::member(params, "name"), name)) {
        return lock_access::withTarget(lock_access::invalid(lock_access::kNameMessage), mac);
    }
    Validity validity;
    const cJSON* window = lock_access::member(params, "validity");
    if (!lock_access::absent(window) && !lock_access::readWindow(window, validity)) {
        return lock_access::withTarget(lock_access::invalid(lock_access::kValidityMessage), mac);
    }
    rpc::Reply gated = lock_access::gate(mac, {kind.feature});
    if (!gated.error.empty()) {
        return lock_access::withTarget(std::move(gated), mac);
    }
    Label probe;
    probe.id = kProbeId;
    probe.name = name;
    rpc::Reply room = checkRoom(mac, kind, probe);
    if (!room.error.empty()) {
        return lock_access::withTarget(std::move(room), mac);
    }
    rpc::Reply reply = lock_manager::runOnLock(
        mac, kind.enrollMethod, [&kind, mac, name, validity](Session& session, const Record&, rpc::Reply& out) {
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
            LabelTable labels;
            bool stored = true;
            if (!name.empty()) {
                Label label;
                label.id = id;
                label.name = name;
                stored = lock_manager::loadLabels(mac, kind.labels, labels) == ESP_OK && labels.put(label) &&
                         lock_manager::saveLabels(mac, kind.labels, labels) == ESP_OK;
            }
            out = entryResult(kind, id, validity, labels.find(id), stored);
            return Status::Ok;
        });
    return lock_access::withTarget(std::move(reply), mac);
}

Status applyCycle(const Credentials& kind, Session& session, uint64_t id, const std::optional<WeeklyWindow>& cycle,
                  bool hadCycle) {
    if (!cycle.has_value() && !hadCycle) {
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
    if (!lock_access::readLock(params, mac)) {
        return lock_access::invalid(lock_access::kLockMessage);
    }
    uint64_t id = 0;
    if (!lock_access::readCredentialId(lock_access::member(params, "id"), kind.maxId, id)) {
        return lock_access::withTarget(lock_access::invalid(idMessage(kind).c_str()), mac);
    }
    Validity validity;
    const cJSON* window = lock_access::member(params, "validity");
    if (!lock_access::absent(window) && !lock_access::readWindow(window, validity)) {
        return lock_access::withTarget(lock_access::invalid(lock_access::kValidityMessage), mac);
    }
    std::optional<WeeklyWindow> cycle;
    if (!lock_access::readCycle(lock_access::member(params, "cycle"), cycle)) {
        return lock_access::withTarget(lock_access::invalid(lock_access::kCycleMessage), mac);
    }
    rpc::Reply gated = cycle.has_value() ? lock_access::gate(mac, {kind.feature, Feature::CyclicIcOrFingerPrint})
                                         : lock_access::gate(mac, {kind.feature});
    if (!gated.error.empty()) {
        return lock_access::withTarget(std::move(gated), mac);
    }
    if (cycle.has_value()) {
        Label probe;
        probe.id = kProbeId;
        probe.cycle = cycle;
        rpc::Reply room = checkRoom(mac, kind, probe);
        if (!room.error.empty()) {
            return lock_access::withTarget(std::move(room), mac);
        }
    }
    rpc::Reply reply = lock_manager::runOnLock(
        mac, kind.validityMethod,
        [&kind, mac, id, validity, cycle](Session& session, const Record&, rpc::Reply& out) {
            LabelTable labels;
            if (!loadLabels(mac, kind, labels, out)) {
                return Status::Ok;
            }
            const Label* old = labels.find(id);
            const bool hadCycle = old != nullptr && old->cycle.has_value();
            Label label = old != nullptr ? *old : Label{};
            label.id = id;
            label.cycle = cycle;
            LabelTable next = labels;
            if (!next.put(label)) {
                out = rpc::fail("too_many", lock_access::kLabelsFullMessage);
                return Status::Ok;
            }
            if (!lock_manager::labelsFit(mac, kind.labels, next)) {
                out = lock_access::storageFull();
                return Status::Ok;
            }
            Status status = (session.*kind.setValidity)(id, validity);
            if (status == Status::Ok) {
                status = applyCycle(kind, session, id, cycle, hadCycle);
            }
            if (status != Status::Ok) {
                return status;
            }
            const bool stored = lock_manager::saveLabels(mac, kind.labels, next) == ESP_OK;
            out = entryResult(kind, id, validity, next.find(id), stored);
            return Status::Ok;
        });
    return lock_access::withTarget(std::move(reply), mac);
}

rpc::Reply credentialsDelete(const Credentials& kind, const cJSON* params) {
    std::string mac;
    if (!lock_access::readLock(params, mac)) {
        return lock_access::invalid(lock_access::kLockMessage);
    }
    uint64_t id = 0;
    if (!lock_access::readCredentialId(lock_access::member(params, "id"), kind.maxId, id)) {
        return lock_access::withTarget(lock_access::invalid(idMessage(kind).c_str()), mac);
    }
    rpc::Reply gated = lock_access::gate(mac, {kind.feature});
    if (!gated.error.empty()) {
        return lock_access::withTarget(std::move(gated), mac);
    }
    rpc::Reply reply = lock_manager::runOnLock(
        mac, kind.deleteMethod, [&kind, mac, id](Session& session, const Record&, rpc::Reply& out) {
            LabelTable labels;
            if (!loadLabels(mac, kind, labels, out)) {
                return Status::Ok;
            }
            const Status status = (session.*kind.remove)(id);
            if (status != Status::Ok) {
                return status;
            }
            const bool stored = !labels.remove(id) || lock_manager::saveLabels(mac, kind.labels, labels) == ESP_OK;
            cJSON* result = cJSON_CreateObject();
            lock_access::addWarnings(result, {stored ? "" : lock_access::kNamesNotStored});
            out = rpc::ok(result);
            return Status::Ok;
        });
    return lock_access::withTarget(std::move(reply), mac);
}

rpc::Reply credentialsClear(const Credentials& kind, const cJSON* params) {
    std::string mac;
    if (!lock_access::readLock(params, mac)) {
        return lock_access::invalid(lock_access::kLockMessage);
    }
    rpc::Reply gated = lock_access::gate(mac, {kind.feature});
    if (!gated.error.empty()) {
        return lock_access::withTarget(std::move(gated), mac);
    }
    rpc::Reply reply = lock_manager::runOnLock(
        mac, kind.clearMethod, [&kind, mac](Session& session, const Record&, rpc::Reply& out) {
            const Status status = (session.*kind.clear)();
            if (status != Status::Ok) {
                return status;
            }
            const bool stored = lock_manager::saveLabels(mac, kind.labels, LabelTable{}) == ESP_OK;
            cJSON* result = cJSON_CreateObject();
            lock_access::addWarnings(result, {stored ? "" : lock_access::kNamesNotStored});
            out = rpc::ok(result);
            return Status::Ok;
        });
    return lock_access::withTarget(std::move(reply), mac);
}

rpc::Handler forKind(rpc::Reply (*method)(const Credentials&, const cJSON*), const Credentials& kind) {
    return [method, &kind](const cJSON* params, const rpc::Context&) { return method(kind, params); };
}

void registerKind(const Credentials& kind) {
    rpc::registerMethod(kind.listMethod, {.audited = false, .job = true}, forKind(credentialsList, kind));
    rpc::registerMethod(kind.enrollMethod, {.job = true}, forKind(credentialsEnroll, kind));
    rpc::registerMethod(kind.validityMethod, {.job = true}, forKind(credentialsSetValidity, kind));
    rpc::registerMethod(kind.deleteMethod, {.job = true}, forKind(credentialsDelete, kind));
    rpc::registerMethod(kind.clearMethod, {.job = true}, forKind(credentialsClear, kind));
}

}

void registerCredentials() {
    registerKind(kFingerprints);
    registerKind(kCards);
}

}
