// SPDX-License-Identifier: GPL-3.0-or-later
#include <cstdint>
#include <cstring>
#include <string>
#include <string_view>
#include <utility>
#include <vector>

#include "esp_log.h"
#include "esp_random.h"
#include "mbedtls/platform_util.h"

#include "access_requests.h"
#include "latchkey_util/passcode_rules.h"
#include "lock_manager.h"
#include "methods.h"
#include "rpc.h"
#include "store.h"
#include "ttlock/features.h"
#include "ttlock/session.h"
#include "ttlock/types.h"

namespace methods {

namespace {

using lock_access::Secret;
using store::locks::Record;
using ttlock::Feature;
using ttlock::Session;
using ttlock::Status;

constexpr const char* TAG = "access";
constexpr uint32_t kRandomCeiling = 4294967290u;
constexpr char kHexDigits[] = "0123456789abcdef";

struct Snapshot {
    Record record;

    ~Snapshot() { mbedtls_platform_zeroize(&record, sizeof(record)); }
};

struct Listed {
    std::vector<ttlock::Passcode> items;

    ~Listed() {
        for (ttlock::Passcode& item : items) {
            lock_access::wipe(item.code);
        }
    }
};

Secret randomCode(size_t digits) {
    std::string text(digits, '0');
    for (char& digit : text) {
        uint32_t value = esp_random();
        while (value >= kRandomCeiling) {
            value = esp_random();
        }
        digit = static_cast<char>('0' + value % 10);
    }
    const Secret code(text);
    lock_access::wipe(text);
    return code;
}

struct AdminRequest {
    std::string mac;
    Secret code;
};

rpc::Reply readAdminSet(const cJSON* params, AdminRequest& out) {
    if (!lock_access::readLock(params, out.mac)) {
        return lock_access::invalid(lock_access::kLockMessage);
    }
    if (!lock_access::readCode(lock_access::member(params, "code"), out.code)) {
        return lock_access::withTarget(lock_access::invalid(lock_access::kCodeMessage), out.mac);
    }
    return lock_access::withTarget(lock_access::gate(out.mac, {Feature::Passcode}), out.mac);
}

rpc::Reply checkAdminSet(const cJSON* params, const rpc::Context&) {
    AdminRequest request;
    return readAdminSet(params, request);
}

Status setAdminPasscode(const std::string& mac, const Secret& code, bool generated, Session& session,
                        rpc::Reply& out) {
    Listed listed;
    Status status = session.passcodeList(listed.items);
    if (status != Status::Ok) {
        return status;
    }
    std::vector<latchkey_util::ListedCode> codes;
    for (const ttlock::Passcode& item : listed.items) {
        codes.push_back(latchkey_util::ListedCode{0, item.code});
    }
    if (latchkey_util::isListedCode(codes, code.get())) {
        out = rpc::fail("lock_error", lock_access::kInUseMessage);
        return Status::Ok;
    }
    lock_manager::AdminPasscodeCopy previous;
    if (!lock_manager::stageAdminPasscode(mac, code.get(), previous)) {
        out = rpc::fail("internal", "cannot store the new admin passcode on the board before sending it");
        return Status::Ok;
    }
    status = session.setAdminPasscode(code.get());
    if (status == Status::LockError && !lock_manager::restoreAdminPasscode(mac, previous)) {
        ESP_LOGE(TAG, "the lock refused the admin passcode, and the board could not put its old copy back");
    }
    if (status != Status::Ok) {
        return status;
    }
    const bool confirmed = lock_manager::confirmAdminPasscode(mac);
    cJSON* result = cJSON_CreateObject();
    if (generated) {
        cJSON_AddStringToObject(result, "code", code.get().c_str());
    }
    lock_access::addWarnings(
        result, {confirmed ? "" : "the lock took the new admin passcode, but the board could not mark its copy as taken",
                 generated ? std::string() : lock_access::easyCodeWarning(code.get())});
    out = rpc::ok(result);
    return Status::Ok;
}

rpc::Reply adminSet(const cJSON* params, const rpc::Context&) {
    AdminRequest request;
    rpc::Reply problem = readAdminSet(params, request);
    if (!problem.error.empty()) {
        return problem;
    }
    const bool generated = request.code.empty();
    const Secret code = generated ? randomCode(ttlock::kAdminPasscodeDigits) : request.code;
    rpc::Reply reply = lock_manager::runOnLock(
        request.mac, "lock.adminPasscode.set",
        [mac = request.mac, code, generated](Session& session, const Record&, rpc::Reply& out) {
            return setAdminPasscode(mac, code, generated, session, out);
        });
    return lock_access::withTarget(std::move(reply), request.mac);
}

rpc::Reply storedAdminCode(const Record& record) {
    if (!ttlock::isPasscode(std::string_view(record.adminPasscode, strnlen(record.adminPasscode,
                                                                           sizeof(record.adminPasscode))))) {
        return rpc::fail("unavailable", "the board holds no admin passcode for this lock");
    }
    cJSON* result = cJSON_CreateObject();
    cJSON_AddStringToObject(result, "code", record.adminPasscode);
    cJSON_AddStringToObject(result, "source", "board");
    return rpc::ok(result);
}

rpc::Reply checkAdminGet(const cJSON* params, const rpc::Context&) {
    std::string mac;
    if (!lock_access::readLock(params, mac)) {
        return lock_access::invalid(lock_access::kLockMessage);
    }
    if (!lock_manager::holds(mac)) {
        return lock_access::withTarget(rpc::fail("not_paired", "the board has no keys for this lock"), mac);
    }
    return lock_access::withTarget(rpc::ok(), mac);
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
        return lock_access::withTarget(std::move(known), mac);
    }
    if (!ttlock::hasFeature(mask, Feature::GetAdminCode)) {
        Snapshot snapshot;
        if (!lock_manager::record(mac, snapshot.record)) {
            return lock_access::withTarget(rpc::fail("not_paired", "the board has no keys for this lock"), mac);
        }
        return lock_access::withTarget(storedAdminCode(snapshot.record), mac);
    }
    rpc::Reply reply = lock_manager::runOnLock(
        mac, "lock.adminPasscode.get", [](Session& session, const Record& record, rpc::Reply& out) {
            std::string code;
            const Status status = session.adminPasscodeGet(code);
            const Secret read(code);
            lock_access::wipe(code);
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
    return lock_access::withTarget(std::move(reply), mac);
}

rpc::Reply adminRaw(const cJSON* params, const rpc::Context&) {
    std::string mac;
    if (!lock_access::readLock(params, mac)) {
        return lock_access::invalid(lock_access::kLockMessage);
    }
    rpc::Reply gated = lock_access::gate(mac, {Feature::GetAdminCode});
    if (!gated.error.empty()) {
        return lock_access::withTarget(std::move(gated), mac);
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
            lock_access::wipe(hex);
            out = rpc::ok(result);
            return Status::Ok;
        });
    return lock_access::withTarget(std::move(reply), mac);
}

}

void registerAdminPasscode() {
    rpc::registerMethod("lock.adminPasscode.set", {.needsButton = true, .job = true}, adminSet, checkAdminSet);
    rpc::registerMethod("lock.adminPasscode.get", {.needsButton = true, .job = true}, adminGet, checkAdminGet);
    rpc::registerMethod("lock.adminPasscode.raw", {.serialOnly = true, .audited = false}, adminRaw);
}

}
