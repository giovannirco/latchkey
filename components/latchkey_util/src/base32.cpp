// SPDX-License-Identifier: GPL-3.0-or-later
#include "latchkey_util/base32.h"

namespace latchkey_util {

namespace {

constexpr char kAlphabet[] = "ABCDEFGHIJKLMNOPQRSTUVWXYZ234567";
constexpr unsigned kBitsPerSymbol = 5;

}

std::string base32Encode(const uint8_t* data, size_t length) {
    std::string out;
    out.reserve((length * 8 + kBitsPerSymbol - 1) / kBitsPerSymbol);
    uint32_t buffer = 0;
    unsigned bits = 0;
    for (size_t i = 0; i < length; ++i) {
        buffer = (buffer << 8) | data[i];
        bits += 8;
        while (bits >= kBitsPerSymbol) {
            bits -= kBitsPerSymbol;
            out += kAlphabet[(buffer >> bits) & 0x1F];
        }
    }
    if (bits > 0) {
        out += kAlphabet[(buffer << (kBitsPerSymbol - bits)) & 0x1F];
    }
    return out;
}

}
