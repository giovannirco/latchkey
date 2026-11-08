// SPDX-License-Identifier: GPL-3.0-or-later
#pragma once

#include <cstddef>
#include <cstdint>
#include <vector>

#include "ttlock/bytes.h"
#include "ttlock/status.h"

namespace ttlock {

struct LockVersion {
    uint8_t protocolType = 0;
    uint8_t protocolVersion = 0;
    uint8_t scene = 0;
    uint16_t groupId = 0;
    uint16_t orgId = 0;
};

struct DecodedFrame {
    uint8_t command = 0;
    Bytes payload;
    bool crcOk = false;
    LockVersion version;
};

constexpr size_t kMaxFramePayload = 239;
constexpr size_t kMaxFrameBytes = 512;

Bytes encodeFrame(const LockVersion& version, uint8_t command, const Bytes& payload, const AesKey& key);
Status decodeFrame(const Bytes& rawWithoutCrlf, const AesKey& key, DecodedFrame& out);

std::vector<Bytes> chunk(const Bytes& frame, size_t mtu = 20);

class Reassembler {
public:
    bool feed(const uint8_t* data, size_t len, Bytes& frameOut);
    void reset();
    Status status() const;

private:
    Bytes buffer_;
    Status status_ = Status::Ok;
};

}
