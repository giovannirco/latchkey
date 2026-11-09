// SPDX-License-Identifier: GPL-3.0-or-later
// Ported from kind3r/ttlock-sdk-js (GPL-3.0) src/device/TTLock.ts and src/device/TTLockApi.ts: the admin login of
// macro_adminLogin and the lock and unlock flows. Matching replies on the echoed opcode and the admin handshake per
// call follow roquerodrigo/ttlock-ble (MIT) client.py and ble/transport.py. The lock type a reply must keep is the one
// src/api/CommandEnvelope.ts generateLockType derives from the frame header.
#include "ttlock/session.h"

#include <utility>

#include "session_internal.h"
#include "ttlock/aes.h"
#include "ttlock/commands.h"

namespace ttlock {
namespace {

constexpr uint8_t kV3ProtocolType = 5;
constexpr uint8_t kV3ProtocolVersion = 3;
constexpr uint8_t kCarScene = 7;

bool isCarLock(const LockVersion& version) {
    return version.protocolType == kV3ProtocolType && version.protocolVersion == kV3ProtocolVersion &&
           version.scene == kCarScene;
}

bool sameLockType(const LockVersion& reply, const LockVersion& paired) {
    return reply.protocolType == paired.protocolType && reply.protocolVersion == paired.protocolVersion &&
           isCarLock(reply) == isCarLock(paired);
}

}

Session::Session(Transport& transport, Clock& clock, Random& random)
    : transport_(transport), clock_(clock), random_(random) {}

void Session::setEventSink(EventSink sink) {
    sink_ = std::move(sink);
}

const LockKeys& Session::keys() const {
    return keys_;
}

uint8_t Session::lockErrorCode() const {
    return lockErrorCode_;
}

size_t Session::droppedFrames() const {
    return droppedFrames_;
}

size_t Session::lockTypeMismatches() const {
    return lockTypeMismatches_;
}

LockVersion Session::lastMismatchedVersion() const {
    return lastMismatchedVersion_;
}

Status Session::attach(const LockKeys& keys) {
    attached_ = false;
    lockErrorCode_ = 0;
    if (!usesV3Frames(keys.version)) {
        return Status::Unsupported;
    }
    if (keys.aesKey == kDefaultAesKey) {
        return Status::InvalidArgument;
    }
    keys_ = keys;
    attached_ = true;
    return Status::Ok;
}

Status Session::requireKeys() const {
    return attached_ ? Status::Ok : Status::NotPaired;
}

Status Session::requireFeature(Feature feature) const {
    const Status status = requireKeys();
    if (status != Status::Ok) {
        return status;
    }
    return hasFeature(keys_.features, feature) ? Status::Ok : Status::Unsupported;
}

bool Session::timeUsable() {
    return clock_.synced() && clock_.utcSeconds() >= kEarliestUsableUtc;
}

LockTime Session::localNow() {
    return lockTimeFromEpoch(clock_.utcSeconds() + clock_.utcOffsetSeconds());
}

Status Session::sendCommand(uint8_t command, const Bytes& payload) {
    lockErrorCode_ = 0;
    const Bytes frame = encodeFrame(keys_.version, command, payload, keys_.aesKey);
    if (frame.empty()) {
        return Status::InvalidArgument;
    }
    return transport_.send(frame);
}

void Session::deliver(const Reply& reply) {
    if (sink_) {
        sink_(parseLockEvent(reply));
    }
}

Status Session::nextFrame(uint32_t timeoutMs, size_t& budget, DecodedFrame& frame) {
    while (budget > 0) {
        --budget;
        Bytes raw;
        const Status received = transport_.receive(raw, timeoutMs);
        if (received != Status::Ok) {
            return received;
        }
        if (decodeFrame(raw, keys_.aesKey, frame) == Status::Ok) {
            if (sameLockType(frame.version, keys_.version)) {
                return Status::Ok;
            }
            ++lockTypeMismatches_;
            lastMismatchedVersion_ = frame.version;
        }
        ++droppedFrames_;
    }
    return Status::Timeout;
}

Status Session::awaitPlain(uint8_t command, uint32_t timeoutMs, bool acceptEmpty, Bytes& plain) {
    size_t budget = kMaxFramesPerReply;
    while (true) {
        DecodedFrame frame;
        const Status received = nextFrame(timeoutMs, budget, frame);
        if (received != Status::Ok) {
            return received;
        }
        if (frame.payload.empty() && !acceptEmpty) {
            ++droppedFrames_;
            continue;
        }
        Reply reply;
        const bool enveloped = parseReply(frame.payload, reply);
        const bool logPush = enveloped && command == command::kSearchStatus && isLogPush(reply);
        const bool answers = frame.payload.empty() || (frame.payload[0] == command && !logPush);
        if (!answers) {
            if (enveloped && frame.crcOk) {
                deliver(reply);
            } else {
                ++droppedFrames_;
            }
            continue;
        }
        if (!frame.crcOk) {
            return Status::BadCrc;
        }
        plain = std::move(frame.payload);
        return Status::Ok;
    }
}

Status Session::awaitData(uint8_t command, uint32_t timeoutMs, Bytes& data) {
    Bytes plain;
    const Status status = awaitPlain(command, timeoutMs, false, plain);
    if (status != Status::Ok) {
        return status;
    }
    Reply reply;
    if (!parseReply(plain, reply)) {
        return Status::BadResponse;
    }
    if (reply.status != kReplySuccess) {
        lockErrorCode_ = reply.data.empty() ? 0 : reply.data[0];
        return Status::LockError;
    }
    data = std::move(reply.data);
    return Status::Ok;
}

Status Session::request(uint8_t command, const Bytes& payload, Bytes& data, uint32_t timeoutMs) {
    const Status sent = sendCommand(command, payload);
    if (sent != Status::Ok) {
        return sent;
    }
    return awaitData(command, timeoutMs, data);
}

Status Session::optionalRead(uint8_t command, const Bytes& payload) {
    Bytes data;
    const Status status = request(command, payload, data);
    return status == Status::LockError ? Status::Ok : status;
}

Status Session::adminLogin() {
    Bytes data;
    Status status = request(command::kCheckAdmin, buildCheckAdmin(keys_.adminPs, keys_.lockFlagPos, 0), data);
    if (status != Status::Ok) {
        return status;
    }
    uint32_t psFromLock = 0;
    if (!parsePsFromLock(data, psFromLock)) {
        return Status::BadResponse;
    }
    return request(command::kCheckRandom, buildCheckRandom(psFromLock, keys_.unlockKey), data);
}

Status Session::beginAdmin() {
    const Status status = requireKeys();
    return status == Status::Ok ? adminLogin() : status;
}

Status Session::beginAdmin(Feature feature) {
    const Status status = requireFeature(feature);
    return status == Status::Ok ? adminLogin() : status;
}

Status Session::adminRequest(Feature feature, uint8_t command, const Bytes& payload, Bytes& data) {
    const Status status = beginAdmin(feature);
    return status == Status::Ok ? request(command, payload, data) : status;
}

Status Session::unlock(OperationResult& out) {
    return controlLock(command::kUnlock, out);
}

Status Session::lock(OperationResult& out) {
    return controlLock(command::kLock, out);
}

Status Session::controlLock(uint8_t command, OperationResult& out) {
    Status status = requireKeys();
    if (status != Status::Ok) {
        return status;
    }
    if (!timeUsable()) {
        return Status::TimeUnsynced;
    }
    Bytes data;
    status = request(command::kCheckUserTime, buildCheckUserTime(keys_.lockFlagPos, 0), data);
    if (status != Status::Ok) {
        return status;
    }
    uint32_t psFromLock = 0;
    if (!parsePsFromLock(data, psFromLock)) {
        return Status::BadResponse;
    }
    const auto utcSeconds = static_cast<uint32_t>(clock_.utcSeconds());
    status = request(command, buildLockControl(psFromLock, keys_.unlockKey, utcSeconds), data);
    if (status != Status::Ok) {
        return status;
    }
    out = parseOperationResult(data);
    return Status::Ok;
}

Status Session::receiveEvent(uint32_t timeoutMs) {
    const Status status = requireKeys();
    if (status != Status::Ok) {
        return status;
    }
    size_t budget = kMaxFramesPerReply;
    while (true) {
        DecodedFrame frame;
        const Status received = nextFrame(timeoutMs, budget, frame);
        if (received != Status::Ok) {
            return received;
        }
        Reply reply;
        if (!frame.crcOk || !parseReply(frame.payload, reply)) {
            ++droppedFrames_;
            continue;
        }
        deliver(reply);
        return Status::Ok;
    }
}

}
