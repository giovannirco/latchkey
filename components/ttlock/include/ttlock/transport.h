// SPDX-License-Identifier: GPL-3.0-or-later
#pragma once

#include <cstddef>
#include <cstdint>

#include "ttlock/bytes.h"
#include "ttlock/status.h"

namespace ttlock {

class Transport {
public:
    virtual ~Transport() = default;
    virtual Status send(const Bytes& wireFrameWithCrlf) = 0;
    virtual Status receive(Bytes& frameWithoutCrlf, uint32_t timeoutMs) = 0;
};

class Clock {
public:
    virtual ~Clock() = default;
    virtual bool synced() = 0;
    virtual int64_t utcSeconds() = 0;
    virtual int32_t utcOffsetSeconds() = 0;
};

class Random {
public:
    virtual ~Random() = default;
    virtual void fill(uint8_t* data, size_t len) = 0;
};

}
