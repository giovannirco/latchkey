// SPDX-License-Identifier: GPL-3.0-or-later
// Ported from kind3r/ttlock-sdk-js (GPL-3.0) src/device/TTLock.ts and src/device/TTLockApi.ts: the status, device
// info, feature, operation log and factory reset flows. The operation-log paging follows roquerodrigo/ttlock-ble
// (MIT) client.py.
#include "ttlock/session.h"

#include <set>
#include <string>
#include <utility>
#include <vector>

#include "session_internal.h"
#include "ttlock/commands.h"

namespace ttlock {

Status Session::status(LockStatus& out) {
    Status result = requireKeys();
    if (result != Status::Ok) {
        return result;
    }
    Bytes data;
    result = request(command::kSearchStatus, buildSearchStatus(), data);
    if (result != Status::Ok) {
        return result;
    }
    return parseLockStatus(data, out) ? Status::Ok : Status::BadResponse;
}

Status Session::deviceInfo(DeviceInfo& out) {
    Status status = beginAdmin();
    if (status != Status::Ok) {
        return status;
    }
    DeviceInfo info;
    const std::pair<DeviceInfoItem, std::string*> items[] = {
        {DeviceInfoItem::Model, &info.model},
        {DeviceInfoItem::Hardware, &info.hardware},
        {DeviceInfoItem::Firmware, &info.firmware},
        {DeviceInfoItem::ManufactureDate, &info.manufactureDate},
    };
    for (const auto& [item, field] : items) {
        Bytes data;
        status = request(command::kReadDeviceInfo, buildReadDeviceInfo(item), data);
        if (status != Status::Ok) {
            return status;
        }
        *field = parseDeviceInfoString(data);
    }
    out = std::move(info);
    return Status::Ok;
}

Status Session::features(uint64_t& out) {
    Status status = beginAdmin();
    if (status != Status::Ok) {
        return status;
    }
    Bytes data;
    status = request(command::kSearchDeviceFeature, noPayload(), data);
    if (status != Status::Ok) {
        return status;
    }
    uint64_t mask = 0;
    if (!parseFeatures(data, mask)) {
        return Status::BadResponse;
    }
    keys_.features = mask;
    out = mask;
    return Status::Ok;
}

Status Session::fetchLog(uint16_t fromSequence, std::vector<LogEntry>& out) {
    const Status status = requireKeys();
    if (status != Status::Ok) {
        return status;
    }
    std::vector<LogEntry> entries;
    std::set<uint16_t> seen;
    uint16_t next = fromSequence;
    for (size_t pages = 0; pages < kMaxListPages; ++pages) {
        Bytes data;
        const Status fetched = request(command::kGetOperateLog, buildOperateLogRequest(next), data);
        if (fetched != Status::Ok) {
            return fetched;
        }
        LogPage page;
        if (!parseLogPage(data, page)) {
            return Status::BadResponse;
        }
        size_t fresh = 0;
        for (LogEntry& entry : page.entries) {
            if (seen.insert(entry.recordNumber).second) {
                entries.push_back(std::move(entry));
                ++fresh;
            }
        }
        if (fresh == 0 || page.sequence == 0 || page.sequence == next) {
            break;
        }
        next = page.sequence;
    }
    out = std::move(entries);
    return Status::Ok;
}

Status Session::factoryReset() {
    Status status = beginAdmin();
    if (status != Status::Ok) {
        return status;
    }
    status = sendCommand(command::kResetLock, noPayload());
    if (status != Status::Ok) {
        return status;
    }
    Bytes plain;
    status = awaitPlain(command::kResetLock, kCommandTimeoutMs, true, plain);
    if (status != Status::Ok) {
        return status;
    }
    if (!plain.empty()) {
        Reply reply;
        if (!parseReply(plain, reply)) {
            return Status::BadResponse;
        }
        if (reply.status != kReplySuccess) {
            lockErrorCode_ = reply.data.empty() ? 0 : reply.data[0];
            return Status::LockError;
        }
    }
    attached_ = false;
    keys_ = LockKeys{};
    return Status::Ok;
}

}
