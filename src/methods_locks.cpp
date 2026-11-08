// SPDX-License-Identifier: GPL-3.0-or-later
#include <cmath>
#include <cstdint>
#include <cstring>
#include <string>

#include "latchkey_util/ble_adv.h"
#include "latchkey_util/label.h"
#include "lock_manager.h"
#include "methods.h"
#include "rpc.h"
#include "store.h"

namespace methods {

namespace {

constexpr size_t kMaxNameCodePoints = 32;
constexpr size_t kMaxNameBytes = sizeof(store::locks::Record::name) - 1;
constexpr uint32_t kDefaultScanSeconds = 10;
constexpr uint32_t kMaxScanSeconds = 30;
constexpr uint32_t kDefaultPairWaitSeconds = 30;
constexpr uint32_t kMaxPairWaitSeconds = 600;
constexpr const char* kDefaultLockName = "New lock";
constexpr const char* kMacMessage = "must be a Bluetooth address like AA:BB:CC:DD:EE:FF";
constexpr const char* kNameMessage = "name must be 1 to 32 characters (at most 99 bytes)";

static_assert(kMaxNameCodePoints == 32 && kMaxNameBytes == 99, "kNameMessage states these limits");

using LockCall = rpc::Reply (*)(const std::string& mac);

rpc::Reply invalid(const std::string& message) { return rpc::fail("invalid_argument", message.c_str()); }

const cJSON* member(const cJSON* params, const char* key) { return cJSON_GetObjectItemCaseSensitive(params, key); }

bool absent(const cJSON* item) { return item == nullptr || cJSON_IsNull(item); }

bool readMac(const cJSON* params, const char* key, std::string& out) {
    const cJSON* item = member(params, key);
    uint8_t address[latchkey_util::kBleAddressSize];
    if (!cJSON_IsString(item) || item->valuestring == nullptr ||
        !latchkey_util::parseBleAddress(item->valuestring, address)) {
        return false;
    }
    out = latchkey_util::formatBleAddress(address);
    return true;
}

bool readSeconds(const cJSON* item, uint32_t fallback, uint32_t maximum, uint32_t& out) {
    if (absent(item)) {
        out = fallback;
        return true;
    }
    if (!cJSON_IsNumber(item) || std::floor(item->valuedouble) != item->valuedouble || item->valuedouble < 1 ||
        item->valuedouble > maximum) {
        return false;
    }
    out = static_cast<uint32_t>(item->valuedouble);
    return true;
}

bool readName(const cJSON* item, std::string& out) {
    return cJSON_IsString(item) && item->valuestring != nullptr &&
           latchkey_util::normalizeLabel(item->valuestring, kMaxNameCodePoints, out) && out.size() <= kMaxNameBytes;
}

bool isBlank(const char* text) {
    for (const char* c = text; *c != '\0'; ++c) {
        if (std::strchr(" \t\r\n\f\v", *c) == nullptr) {
            return false;
        }
    }
    return true;
}

bool readOptionalName(const cJSON* item, std::string& out) {
    if (absent(item)) {
        out = kDefaultLockName;
        return true;
    }
    if (!cJSON_IsString(item) || item->valuestring == nullptr) {
        return false;
    }
    if (isBlank(item->valuestring)) {
        out = kDefaultLockName;
        return true;
    }
    return readName(item, out);
}

rpc::Reply withTarget(rpc::Reply reply, const std::string& mac) {
    reply.target = mac;
    return reply;
}

rpc::Handler forLock(LockCall call) {
    return [call](const cJSON* params, const rpc::Context&) {
        std::string mac;
        if (!readMac(params, "lock", mac)) {
            return invalid(std::string("lock ") + kMacMessage);
        }
        return withTarget(call(mac), mac);
    };
}

rpc::Reply scan(const cJSON* params, const rpc::Context&) {
    uint32_t seconds = 0;
    if (!readSeconds(member(params, "seconds"), kDefaultScanSeconds, kMaxScanSeconds, seconds)) {
        return invalid("seconds must be a whole number from 1 to 30");
    }
    return lock_manager::scan(seconds);
}

rpc::Reply list(const cJSON*, const rpc::Context&) { return lock_manager::list(); }

struct PairRequest {
    std::string mac;
    std::string name;
    uint32_t wait = 0;
};

rpc::Reply readPair(const cJSON* params, PairRequest& out) {
    if (!readMac(params, "mac", out.mac)) {
        return invalid(std::string("mac ") + kMacMessage);
    }
    if (!readOptionalName(member(params, "name"), out.name)) {
        return withTarget(invalid(kNameMessage), out.mac);
    }
    if (!readSeconds(member(params, "wait"), kDefaultPairWaitSeconds, kMaxPairWaitSeconds, out.wait)) {
        return withTarget(invalid("wait must be a whole number of seconds from 1 to 600"), out.mac);
    }
    return withTarget(rpc::ok(), out.mac);
}

rpc::Reply checkPair(const cJSON* params, const rpc::Context&) {
    PairRequest request;
    return readPair(params, request);
}

rpc::Reply pair(const cJSON* params, const rpc::Context&) {
    PairRequest request;
    rpc::Reply problem = readPair(params, request);
    if (!problem.error.empty()) {
        return problem;
    }
    return withTarget(lock_manager::pair(request.mac, request.name, request.wait), request.mac);
}

rpc::Reply checkHeldLock(const cJSON* params, const rpc::Context&) {
    std::string mac;
    if (!readMac(params, "lock", mac)) {
        return invalid(std::string("lock ") + kMacMessage);
    }
    if (!lock_manager::holds(mac)) {
        return withTarget(rpc::fail("not_paired", "the board has no keys for this lock"), mac);
    }
    return withTarget(rpc::ok(), mac);
}

rpc::Reply rename(const cJSON* params, const rpc::Context&) {
    std::string mac;
    if (!readMac(params, "lock", mac)) {
        return invalid(std::string("lock ") + kMacMessage);
    }
    std::string name;
    if (!readName(member(params, "name"), name)) {
        return withTarget(invalid(kNameMessage), mac);
    }
    return withTarget(lock_manager::rename(mac, name), mac);
}

}

void registerLocks() {
    rpc::registerMethod("locks.scan", {.audited = false, .job = true}, scan);
    rpc::registerMethod("locks.list", {.audited = false}, list);
    rpc::registerMethod("locks.rename", {}, rename);
    rpc::registerMethod("locks.forget", {}, forLock(lock_manager::forget));
    rpc::registerMethod("locks.pair", {.needsButton = true, .job = true}, pair, checkPair);
    rpc::registerMethod("lock.status", {.audited = false, .job = true}, forLock(lock_manager::status));
    rpc::registerMethod("lock.info", {.audited = false, .job = true}, forLock(lock_manager::info));
    rpc::registerMethod("lock.features", {.audited = false, .job = true}, forLock(lock_manager::features));
    rpc::registerMethod("lock.unlock", {.job = true}, forLock(lock_manager::unlock));
    rpc::registerMethod("lock.lock", {.job = true}, forLock(lock_manager::lock));
    rpc::registerMethod("lock.time.sync", {.job = true}, forLock(lock_manager::syncTime));
    rpc::registerMethod("lock.factoryReset", {.needsButton = true, .job = true}, forLock(lock_manager::factoryReset),
                        checkHeldLock);
}

}
