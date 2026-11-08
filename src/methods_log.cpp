// SPDX-License-Identifier: GPL-3.0-or-later
#include <cmath>
#include <cstdint>
#include <optional>
#include <string>

#include "access_requests.h"
#include "latchkey_util/lock_log.h"
#include "lock_manager.h"
#include "methods.h"
#include "rpc.h"

namespace methods {

namespace {

constexpr const char* kSinceMessage = "since must be a log record number from 0 to 65534";

bool readSince(const cJSON* item, std::optional<uint16_t>& out) {
    if (lock_access::absent(item)) {
        out.reset();
        return true;
    }
    if (!cJSON_IsNumber(item) || std::floor(item->valuedouble) != item->valuedouble || item->valuedouble < 0 ||
        item->valuedouble > latchkey_util::kLastLogSlot) {
        return false;
    }
    out = static_cast<uint16_t>(item->valuedouble);
    return true;
}

rpc::Reply logFetch(const cJSON* params, const rpc::Context&) {
    std::string mac;
    if (!lock_access::readLock(params, mac)) {
        return lock_access::invalid(lock_access::kLockMessage);
    }
    std::optional<uint16_t> since;
    if (!readSince(lock_access::member(params, "since"), since)) {
        return lock_access::withTarget(lock_access::invalid(kSinceMessage), mac);
    }
    return lock_access::withTarget(lock_manager::readLog(mac, since), mac);
}

}

void registerLog() { rpc::registerMethod("lock.log.fetch", {.audited = false, .job = true}, logFetch); }

}
