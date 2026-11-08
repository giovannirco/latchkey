// SPDX-License-Identifier: GPL-3.0-or-later
#pragma once

#include <cstddef>
#include <cstdint>
#include <vector>

namespace latchkey_util::big_endian {

inline void append(std::vector<uint8_t>& out, uint64_t value, size_t width) {
    for (size_t i = width; i > 0; --i) {
        out.push_back(static_cast<uint8_t>(value >> (8 * (i - 1))));
    }
}

inline void write(uint8_t* out, uint64_t value, size_t width) {
    for (size_t i = 0; i < width; ++i) {
        out[i] = static_cast<uint8_t>(value >> (8 * (width - 1 - i)));
    }
}

inline uint64_t read(const uint8_t* data, size_t width) {
    uint64_t value = 0;
    for (size_t i = 0; i < width; ++i) {
        value = value << 8 | data[i];
    }
    return value;
}

}
