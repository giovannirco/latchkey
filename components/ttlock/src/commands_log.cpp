// SPDX-License-Identifier: GPL-3.0-or-later
// Ported from kind3r/ttlock-sdk-js (GPL-3.0) src/api/Commands/OperationLogCommand.ts. The record-type buckets,
// the record numbering and the 0x14 push layouts follow roquerodrigo/ttlock-ble (MIT) commands/log_record.py,
// commands/operate_log.py and models/lock_event.py.
#include <algorithm>
#include <cstdio>
#include <initializer_list>
#include <string>
#include <utility>

#include "ttlock/commands.h"
#include "wire_format.h"

namespace ttlock {
namespace {

constexpr size_t kRecordHeaderSize = 1 + wire::kDateTimeSize + 1;
constexpr size_t kUidRecordSize = 8;
constexpr size_t kMacSize = 6;
constexpr size_t kSixByteIdSize = 6;
constexpr size_t kShortIdSize = 2;
constexpr size_t kMaxNumberSize = 8;
constexpr size_t kStatePushSize = 3;
constexpr size_t kLogPushSize = 15;

enum class Tail : uint8_t {
    None,
    UidRecord,
    PasscodePair,
    PasscodeOnly,
    ClearAllPasscodes,
    CardNumber,
    MacOnly,
    SixByteId,
    AccessoryBattery,
    RemoteControlKey,
    KeyFob,
    WirelessKeypad,
    ShortId,
    AddedPasscode,
};

bool in(uint8_t type, std::initializer_list<uint8_t> types) {
    for (uint8_t candidate : types) {
        if (candidate == type) {
            return true;
        }
    }
    return false;
}

Tail tailOf(uint8_t type) {
    if (in(type, {1, 26, 28, 41, 52, 75, 76, 77})) {
        return Tail::UidRecord;
    }
    if (in(type, {4, 5, 6, 9, 10, 11, 12, 13, 34, 38, 78, 92})) {
        return Tail::PasscodePair;
    }
    if (type == 7) {
        return Tail::PasscodeOnly;
    }
    if (type == 8) {
        return Tail::ClearAllPasscodes;
    }
    if (in(type, {15, 17, 18, 25, 35, 39, 51, 74, 80, 91})) {
        return Tail::CardNumber;
    }
    if (in(type, {19, 94, 95, 96, 97, 98, 99, 100})) {
        return Tail::MacOnly;
    }
    if (in(type, {20, 21, 22, 23, 33, 40, 79, 67, 68, 69, 70, 71, 72, 81, 83, 84, 85, 86, 87, 88, 89})) {
        return Tail::SixByteId;
    }
    if (in(type, {30, 31})) {
        return Tail::AccessoryBattery;
    }
    if (type == 37) {
        return Tail::RemoteControlKey;
    }
    if (in(type, {55, 82})) {
        return Tail::KeyFob;
    }
    if (type == 56) {
        return Tail::WirelessKeypad;
    }
    if (in(type, {57, 58, 61, 62})) {
        return Tail::ShortId;
    }
    if (type == 93) {
        return Tail::AddedPasscode;
    }
    return Tail::None;
}

std::string mac(const uint8_t* data) {
    char buffer[18];
    std::snprintf(buffer, sizeof(buffer), "%02x:%02x:%02x:%02x:%02x:%02x", data[5], data[4], data[3], data[2],
                  data[1], data[0]);
    return buffer;
}

std::string number(const uint8_t* data, size_t size) {
    return std::to_string(wire::readBe(data, size));
}

size_t readPasscode(const uint8_t* data, size_t size, std::string& out) {
    if (size == 0 || 1 + static_cast<size_t>(data[0]) > size) {
        return 0;
    }
    out.assign(data + 1, data + 1 + data[0]);
    return 1 + data[0];
}

void readPasscodePair(const uint8_t* data, size_t size, LogEntry& entry) {
    const size_t used = readPasscode(data, size, entry.credential);
    if (used > 0 && used < size) {
        readPasscode(data + used, size - used, entry.newCredential);
    }
}

void decodeTail(const uint8_t* data, size_t size, LogEntry& entry) {
    switch (tailOf(entry.type)) {
        case Tail::UidRecord:
            if (size >= kUidRecordSize) {
                entry.uid = wire::readBe32(data);
                entry.recordId = wire::readBe32(data + 4);
            }
            return;
        case Tail::RemoteControlKey:
            if (size > kUidRecordSize) {
                entry.uid = wire::readBe32(data);
                entry.recordId = wire::readBe32(data + 4);
                entry.keyId = data[kUidRecordSize];
            }
            return;
        case Tail::PasscodePair:
            readPasscodePair(data, size, entry);
            return;
        case Tail::PasscodeOnly:
        case Tail::AddedPasscode:
            readPasscode(data, size, entry.credential);
            return;
        case Tail::ClearAllPasscodes:
            if (size > wire::kDateSize) {
                readPasscode(data + wire::kDateSize, size - wire::kDateSize, entry.credential);
            }
            return;
        case Tail::CardNumber:
            if (size > 0 && size <= kMaxNumberSize) {
                entry.credential = number(data, size);
            }
            return;
        case Tail::MacOnly:
            if (size >= kMacSize) {
                entry.credential = mac(data);
            }
            return;
        case Tail::SixByteId:
            if (size >= kSixByteIdSize) {
                entry.credential = number(data, kSixByteIdSize);
            }
            return;
        case Tail::AccessoryBattery:
            if (size >= 1) {
                entry.accessoryBattery = data[0];
            }
            return;
        case Tail::KeyFob:
            if (size >= kMacSize) {
                entry.credential = mac(data);
                entry.keyId = size > kMacSize ? data[kMacSize] : -1;
                entry.accessoryBattery = size > kMacSize + 1 ? data[kMacSize + 1] : -1;
            }
            return;
        case Tail::WirelessKeypad:
            if (size >= kMacSize) {
                entry.credential = mac(data);
                entry.accessoryBattery = size > kMacSize ? data[kMacSize] : -1;
            }
            return;
        case Tail::ShortId:
            if (size >= kShortIdSize) {
                entry.credential = number(data, kShortIdSize);
            }
            return;
        case Tail::None:
            return;
    }
}

}

Bytes buildOperateLogRequest(uint16_t sequence) {
    Bytes out;
    wire::appendBe(out, sequence, 2);
    return out;
}

bool parseLogPage(const Bytes& data, LogPage& out) {
    if (data.size() < 2) {
        return false;
    }
    LogPage page;
    if (wire::readBe16(data.data()) == 0) {
        out = std::move(page);
        return true;
    }
    if (data.size() < 4) {
        return false;
    }
    page.sequence = wire::readBe16(data.data() + 2);
    size_t offset = 4;
    while (offset < data.size()) {
        const size_t recordSize = data[offset];
        const size_t recordStart = offset + 1;
        if (recordStart + recordSize > data.size() || recordSize < kRecordHeaderSize) {
            break;
        }
        const uint8_t* record = data.data() + recordStart;
        LogEntry entry;
        entry.recordNumber = static_cast<uint16_t>(page.sequence - page.entries.size() - 1);
        entry.type = record[0];
        entry.time = wire::readTime(record + 1, true);
        entry.battery = record[1 + wire::kDateTimeSize];
        decodeTail(record + kRecordHeaderSize, recordSize - kRecordHeaderSize, entry);
        page.entries.push_back(std::move(entry));
        offset = recordStart + recordSize;
    }
    out = std::move(page);
    return true;
}

bool isLogPush(const Reply& reply) {
    return reply.command == command::kSearchStatus && reply.data.size() >= kLogPushSize;
}

LockEvent parseLockEvent(const Reply& reply) {
    LockEvent event;
    event.command = reply.command;
    event.status = reply.status;
    event.data = reply.data;
    if (reply.command != command::kSearchStatus || reply.status != kReplySuccess || reply.data.empty()) {
        return event;
    }
    event.battery = reply.data[0];
    if (reply.data.size() == kStatePushSize) {
        LockStatus status;
        parseLockStatus(reply.data, status);
        event.state = status.state;
    }
    if (isLogPush(reply)) {
        event.hasRecord = true;
        event.uid = wire::readBe32(reply.data.data() + 1);
        event.recordId = wire::readBe32(reply.data.data() + 5);
        event.time = wire::readTime(reply.data.data() + 9, true);
    }
    return event;
}

}
