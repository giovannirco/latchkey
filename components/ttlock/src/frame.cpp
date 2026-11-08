// SPDX-License-Identifier: GPL-3.0-or-later
// Ported from kind3r/ttlock-sdk-js (GPL-3.0) src/api/CommandEnvelope.ts and src/device/TTBluetoothDevice.ts.
#include "ttlock/frame.h"

#include <algorithm>
#include <utility>

#include "ttlock/aes.h"
#include "ttlock/crc8.h"

namespace ttlock {
namespace {

constexpr uint8_t kMagic0 = 0x7F;
constexpr uint8_t kMagic1 = 0x5A;
constexpr uint8_t kAppCommand = 0xAA;
constexpr uint8_t kCr = 0x0D;
constexpr uint8_t kLf = 0x0A;
constexpr uint8_t kFirstV3ProtocolType = 5;
constexpr size_t kProtocolTypeIndex = 2;
constexpr size_t kProtocolVersionIndex = 3;
constexpr size_t kSceneIndex = 4;
constexpr size_t kGroupIdIndex = 5;
constexpr size_t kOrgIdIndex = 7;
constexpr size_t kCommandIndex = 9;
constexpr size_t kLengthIndex = 11;
constexpr size_t kHeaderSize = 12;
constexpr size_t kCrcSize = 1;
constexpr size_t kCrlfSize = 2;

bool hasV3Layout(uint8_t protocolType) {
    return protocolType == 0 || protocolType >= kFirstV3ProtocolType;
}

bool startsWithMagic(const Bytes& bytes) {
    return bytes.size() >= 2 && bytes[0] == kMagic0 && bytes[1] == kMagic1;
}

bool endsWithCrlf(const Bytes& bytes) {
    return bytes.size() >= kCrlfSize && bytes[bytes.size() - 2] == kCr && bytes.back() == kLf;
}

size_t declaredWireSize(const Bytes& bytes) {
    if (bytes.size() < kHeaderSize || !startsWithMagic(bytes) || !hasV3Layout(bytes[kProtocolTypeIndex])) {
        return 0;
    }
    return kHeaderSize + bytes[kLengthIndex] + kCrcSize + kCrlfSize;
}

uint16_t readBe16(const Bytes& bytes, size_t index) {
    return static_cast<uint16_t>(bytes[index] << 8 | bytes[index + 1]);
}

LockVersion headerVersion(const Bytes& raw) {
    return LockVersion{raw[kProtocolTypeIndex], raw[kProtocolVersionIndex], raw[kSceneIndex],
                       readBe16(raw, kGroupIdIndex), readBe16(raw, kOrgIdIndex)};
}

}

Bytes encodeFrame(const LockVersion& version, uint8_t command, const Bytes& payload, const AesKey& key) {
    if (payload.size() > kMaxFramePayload) {
        return {};
    }
    const Bytes data = payload.empty() ? Bytes{} : aesEncrypt(payload, key);
    Bytes frame{kMagic0,
                kMagic1,
                version.protocolType,
                version.protocolVersion,
                version.scene,
                static_cast<uint8_t>(version.groupId >> 8),
                static_cast<uint8_t>(version.groupId),
                static_cast<uint8_t>(version.orgId >> 8),
                static_cast<uint8_t>(version.orgId),
                command,
                kAppCommand,
                static_cast<uint8_t>(data.size())};
    frame.insert(frame.end(), data.begin(), data.end());
    frame.push_back(crc8(frame.data(), frame.size()));
    frame.push_back(kCr);
    frame.push_back(kLf);
    return frame;
}

Status decodeFrame(const Bytes& rawWithoutCrlf, const AesKey& key, DecodedFrame& out) {
    const Bytes& raw = rawWithoutCrlf;
    if (raw.size() <= kProtocolTypeIndex || !startsWithMagic(raw)) {
        return Status::BadResponse;
    }
    if (!hasV3Layout(raw[kProtocolTypeIndex])) {
        return Status::Unsupported;
    }
    if (raw.size() < kHeaderSize + kCrcSize) {
        return Status::BadResponse;
    }
    const size_t length = raw[kLengthIndex];
    if (raw.size() != kHeaderSize + length + kCrcSize) {
        return Status::BadResponse;
    }
    DecodedFrame decoded;
    decoded.command = raw[kCommandIndex];
    decoded.crcOk = crc8(raw.data(), raw.size() - kCrcSize) == raw.back();
    decoded.version = headerVersion(raw);
    if (length > 0) {
        const Bytes cipher(raw.data() + kHeaderSize, raw.data() + kHeaderSize + length);
        if (!aesDecrypt(cipher, key, decoded.payload)) {
            return Status::BadResponse;
        }
    }
    out = std::move(decoded);
    return Status::Ok;
}

std::vector<Bytes> chunk(const Bytes& frame, size_t mtu) {
    std::vector<Bytes> chunks;
    if (mtu == 0) {
        return chunks;
    }
    for (size_t offset = 0; offset < frame.size(); offset += mtu) {
        const size_t end = std::min(frame.size(), offset + mtu);
        chunks.emplace_back(frame.data() + offset, frame.data() + end);
    }
    return chunks;
}

bool Reassembler::feed(const uint8_t* data, size_t len, Bytes& frameOut) {
    status_ = Status::Ok;
    if (buffer_.size() + len > kMaxFrameBytes) {
        reset();
        status_ = Status::BadResponse;
        return false;
    }
    buffer_.insert(buffer_.end(), data, data + len);
    if (!endsWithCrlf(buffer_) || declaredWireSize(buffer_) > buffer_.size()) {
        return false;
    }
    frameOut.assign(buffer_.begin(), buffer_.end() - kCrlfSize);
    buffer_.clear();
    return true;
}

void Reassembler::reset() {
    buffer_.clear();
    status_ = Status::Ok;
}

Status Reassembler::status() const {
    return status_;
}

}
