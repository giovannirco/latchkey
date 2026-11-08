// SPDX-License-Identifier: GPL-3.0-or-later
// Table quirk from roquerodrigo/ttlock-ble (MIT) crypto.py, matching kind3r/ttlock-sdk-js "Bad CRC quest" captures.
#include "ttlock/crc8.h"

#include <array>

namespace ttlock {
namespace {

constexpr uint8_t kReflectedPolynomial = 0x8C;
constexpr uint8_t kQuirkIndex = 0x21;
constexpr uint8_t kQuirkValue = 0x07;

constexpr std::array<uint8_t, 256> makeTable() {
    std::array<uint8_t, 256> table{};
    for (size_t i = 0; i < table.size(); ++i) {
        uint8_t crc = static_cast<uint8_t>(i);
        for (int bit = 0; bit < 8; ++bit) {
            crc = (crc & 1) ? static_cast<uint8_t>((crc >> 1) ^ kReflectedPolynomial) : static_cast<uint8_t>(crc >> 1);
        }
        table[i] = crc;
    }
    table[kQuirkIndex] = kQuirkValue;
    return table;
}

constexpr std::array<uint8_t, 256> kTable = makeTable();

static_assert(kTable[0x01] == 0x5E);
static_assert(kTable[kQuirkIndex] == kQuirkValue);

}

uint8_t crc8(const uint8_t* data, size_t len) {
    uint8_t crc = 0;
    for (size_t i = 0; i < len; ++i) {
        crc = kTable[crc ^ data[i]];
    }
    return crc;
}

}
