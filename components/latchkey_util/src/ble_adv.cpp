// SPDX-License-Identifier: GPL-3.0-or-later
#include "latchkey_util/ble_adv.h"

#include <initializer_list>

namespace latchkey_util {

namespace {

constexpr char kHexDigits[] = "0123456789ABCDEF";
constexpr size_t kAddressText = 3 * kBleAddressSize - 1;

int hexValue(char digit) {
    if (digit >= '0' && digit <= '9') {
        return digit - '0';
    }
    if (digit >= 'A' && digit <= 'F') {
        return digit - 'A' + 10;
    }
    if (digit >= 'a' && digit <= 'f') {
        return digit - 'a' + 10;
    }
    return -1;
}

}

bool findAdField(const uint8_t* payload, size_t length, uint8_t type, AdField& out) {
    if (payload == nullptr) {
        return false;
    }
    size_t offset = 0;
    while (offset < length) {
        const size_t fieldLength = payload[offset];
        if (fieldLength == 0 || offset + 1 + fieldLength > length) {
            return false;
        }
        if (payload[offset + 1] == type) {
            out = AdField{type, payload + offset + 2, fieldLength - 1};
            return true;
        }
        offset += 1 + fieldLength;
    }
    return false;
}

bool hasUuid16(const uint8_t* payload, size_t length, uint16_t uuid) {
    for (const uint8_t type : {kAdTypeIncompleteUuid16, kAdTypeCompleteUuid16}) {
        AdField field;
        if (!findAdField(payload, length, type, field)) {
            continue;
        }
        for (size_t i = 0; i + 1 < field.size; i += 2) {
            if ((field.data[i] | field.data[i + 1] << 8) == uuid) {
                return true;
            }
        }
    }
    return false;
}

std::string formatBleAddress(const uint8_t (&littleEndian)[kBleAddressSize]) {
    std::string text;
    text.reserve(kAddressText);
    for (size_t i = kBleAddressSize; i > 0; --i) {
        const uint8_t octet = littleEndian[i - 1];
        if (i < kBleAddressSize) {
            text.push_back(':');
        }
        text.push_back(kHexDigits[octet >> 4]);
        text.push_back(kHexDigits[octet & 0x0F]);
    }
    return text;
}

bool parseBleAddress(std::string_view text, uint8_t (&littleEndian)[kBleAddressSize]) {
    if (text.size() != kAddressText) {
        return false;
    }
    uint8_t parsed[kBleAddressSize];
    for (size_t octet = 0; octet < kBleAddressSize; ++octet) {
        const size_t at = octet * 3;
        if (octet > 0 && text[at - 1] != ':') {
            return false;
        }
        const int high = hexValue(text[at]);
        const int low = hexValue(text[at + 1]);
        if (high < 0 || low < 0) {
            return false;
        }
        parsed[kBleAddressSize - 1 - octet] = static_cast<uint8_t>(high << 4 | low);
    }
    for (size_t i = 0; i < kBleAddressSize; ++i) {
        littleEndian[i] = parsed[i];
    }
    return true;
}

}
