// SPDX-License-Identifier: GPL-3.0-or-later
#pragma once

#include <cstddef>
#include <cstdint>

#include "ttlock/bytes.h"
#include "ttlock/types.h"

namespace ttlock::wire {

inline constexpr size_t kDateSize = 5;
inline constexpr size_t kDateTimeSize = 6;
inline constexpr uint16_t kCenturyStart = 2000;

inline void appendBe(Bytes& out, uint64_t value, size_t width) {
    for (size_t i = width; i > 0; --i) {
        out.push_back(static_cast<uint8_t>(value >> (8 * (i - 1))));
    }
}

inline uint64_t readBe(const uint8_t* data, size_t width) {
    uint64_t value = 0;
    for (size_t i = 0; i < width; ++i) {
        value = value << 8 | data[i];
    }
    return value;
}

inline uint16_t readBe16(const uint8_t* data) {
    return static_cast<uint16_t>(readBe(data, 2));
}

inline uint32_t readBe32(const uint8_t* data) {
    return static_cast<uint32_t>(readBe(data, 4));
}

inline void appendTime(Bytes& out, const LockTime& time, bool withSeconds) {
    out.push_back(static_cast<uint8_t>(time.year - kCenturyStart));
    out.push_back(time.month);
    out.push_back(time.day);
    out.push_back(time.hour);
    out.push_back(time.minute);
    if (withSeconds) {
        out.push_back(time.second);
    }
}

inline LockTime readTime(const uint8_t* data, bool withSeconds) {
    LockTime time;
    time.year = static_cast<uint16_t>(kCenturyStart + data[0]);
    time.month = data[1];
    time.day = data[2];
    time.hour = data[3];
    time.minute = data[4];
    time.second = withSeconds ? data[5] : 0;
    return time;
}

inline void appendValidity(Bytes& out, const Validity& validity) {
    appendTime(out, validity.start, false);
    appendTime(out, validity.end, false);
}

inline Validity readValidity(const uint8_t* data) {
    return Validity{readTime(data, false), readTime(data + kDateSize, false)};
}

}
