// SPDX-License-Identifier: GPL-3.0-or-later
#include "latchkey_util/ipv4.h"

namespace latchkey_util {

namespace {

constexpr int kOctets = 4;
constexpr int kMinPrefix = 1;
constexpr int kMaxPrefix = 30;

bool parseOctet(std::string_view text, uint32_t& value) {
    if (text.empty() || text.size() > 3 || (text.size() > 1 && text[0] == '0')) {
        return false;
    }
    value = 0;
    for (char c : text) {
        if (c < '0' || c > '9') {
            return false;
        }
        value = value * 10 + static_cast<uint32_t>(c - '0');
    }
    return value <= 255;
}

int prefixLength(uint32_t mask) {
    int length = 0;
    while (length < 32 && (mask & (0x80000000u >> length)) != 0) {
        ++length;
    }
    return length;
}

bool isHost(uint32_t address, uint32_t mask) {
    const uint32_t host = address & ~mask;
    return host != 0 && host != ~mask;
}

}

bool parseIpv4(std::string_view text, uint32_t& address) {
    uint32_t result = 0;
    for (int index = 0; index < kOctets; ++index) {
        const size_t dot = text.find('.');
        const bool last = index == kOctets - 1;
        if (last != (dot == std::string_view::npos)) {
            return false;
        }
        uint32_t octet = 0;
        if (!parseOctet(text.substr(0, dot), octet)) {
            return false;
        }
        result = (result << 8) | octet;
        text = last ? std::string_view() : text.substr(dot + 1);
    }
    address = result;
    return true;
}

bool isNetmask(uint32_t mask) {
    const int length = prefixLength(mask);
    const uint32_t contiguous = length == 0 ? 0 : 0xFFFFFFFFu << (32 - length);
    return mask == contiguous && length >= kMinPrefix && length <= kMaxPrefix;
}

bool isStaticIpv4(uint32_t address, uint32_t gateway, uint32_t netmask) {
    return isNetmask(netmask) && (address & netmask) == (gateway & netmask) && address != gateway &&
           isHost(address, netmask) && isHost(gateway, netmask);
}

}
