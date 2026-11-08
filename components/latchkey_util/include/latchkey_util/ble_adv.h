// SPDX-License-Identifier: GPL-3.0-or-later
#pragma once

#include <cstddef>
#include <cstdint>
#include <string>
#include <string_view>

namespace latchkey_util {

inline constexpr uint8_t kAdTypeIncompleteUuid16 = 0x02;
inline constexpr uint8_t kAdTypeCompleteUuid16 = 0x03;
inline constexpr uint8_t kAdTypeShortName = 0x08;
inline constexpr uint8_t kAdTypeCompleteName = 0x09;
inline constexpr uint8_t kAdTypeManufacturer = 0xFF;
inline constexpr size_t kBleAddressSize = 6;

struct AdField {
    uint8_t type = 0;
    const uint8_t* data = nullptr;
    size_t size = 0;
};

bool findAdField(const uint8_t* payload, size_t length, uint8_t type, AdField& out);

bool hasUuid16(const uint8_t* payload, size_t length, uint16_t uuid);

std::string formatBleAddress(const uint8_t (&littleEndian)[kBleAddressSize]);

bool parseBleAddress(std::string_view text, uint8_t (&littleEndian)[kBleAddressSize]);

}
