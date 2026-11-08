// SPDX-License-Identifier: GPL-3.0-or-later
#include "latchkey_util/otpauth.h"

#include "latchkey_util/base32.h"

namespace latchkey_util {

namespace {

constexpr char kHex[] = "0123456789ABCDEF";

bool isUnreserved(unsigned char c) {
    return (c >= 'A' && c <= 'Z') || (c >= 'a' && c <= 'z') || (c >= '0' && c <= '9') || c == '-' || c == '.' ||
           c == '_' || c == '~';
}

std::string percentEncode(std::string_view text) {
    std::string out;
    out.reserve(text.size());
    for (unsigned char c : text) {
        if (isUnreserved(c)) {
            out += static_cast<char>(c);
            continue;
        }
        out += '%';
        out += kHex[c >> 4];
        out += kHex[c & 0x0F];
    }
    return out;
}

}

std::string otpauthUri(std::string_view account, const uint8_t* secret, size_t length) {
    return "otpauth://totp/Latchkey:" + percentEncode(account) + "?secret=" + base32Encode(secret, length) +
           "&issuer=Latchkey&algorithm=SHA1&digits=6&period=30";
}

}
