// SPDX-License-Identifier: GPL-3.0-or-later
#include "latchkey_util/certificate.h"

#include <cstdio>
#include <utility>

#include "latchkey_util/tz.h"

namespace latchkey_util {

namespace {

constexpr size_t kIdentityHeaderSize = 3;
constexpr size_t kMaxCertificateSize = 0xFFFF;
constexpr size_t kStampDigits = 14;
constexpr int kValidityYears = 10;
constexpr char kHexDigits[] = "0123456789ABCDEF";

std::string x509Time(int64_t utcSeconds) {
    std::string digits;
    for (char c : localTimestamp(utcSeconds, 0)) {
        if (digits.size() == kStampDigits) {
            break;
        }
        if (c >= '0' && c <= '9') {
            digits += c;
        }
    }
    return digits;
}

std::string yearsLater(const std::string& stamp, int years) {
    int year = 0;
    for (size_t i = 0; i < 4; ++i) {
        year = year * 10 + (stamp[i] - '0');
    }
    char prefix[12];
    std::snprintf(prefix, sizeof(prefix), "%04d", year + years);
    std::string later = prefix + stamp.substr(4);
    if (later.compare(4, 4, "0229") == 0) {
        later.replace(4, 4, "0228");
    }
    return later;
}

}

CertificateValidity certificateValidity(int64_t utcSeconds) {
    const std::string notBefore = x509Time(utcSeconds);
    return CertificateValidity{notBefore, yearsLater(notBefore, kValidityYears)};
}

std::string formatFingerprint(const uint8_t (&digest)[kFingerprintDigestSize]) {
    std::string text;
    text.reserve(kFingerprintDigestSize * 3 - 1);
    for (size_t i = 0; i < kFingerprintDigestSize; ++i) {
        if (i > 0) {
            text += ':';
        }
        text += kHexDigits[digest[i] >> 4];
        text += kHexDigits[digest[i] & 0x0F];
    }
    return text;
}

std::vector<uint8_t> encodeTlsIdentity(const TlsIdentity& identity) {
    const size_t certificateSize = identity.certificate.size();
    if (certificateSize == 0 || certificateSize > kMaxCertificateSize || identity.key.empty()) {
        return {};
    }
    std::vector<uint8_t> bytes;
    bytes.reserve(kIdentityHeaderSize + certificateSize + identity.key.size());
    bytes.push_back(kTlsIdentityVersion);
    bytes.push_back(static_cast<uint8_t>(certificateSize & 0xFF));
    bytes.push_back(static_cast<uint8_t>(certificateSize >> 8));
    bytes.insert(bytes.end(), identity.certificate.begin(), identity.certificate.end());
    bytes.insert(bytes.end(), identity.key.begin(), identity.key.end());
    return bytes;
}

bool decodeTlsIdentity(const uint8_t* data, size_t length, TlsIdentity& out) {
    if (length < kIdentityHeaderSize || data[0] != kTlsIdentityVersion) {
        return false;
    }
    const size_t certificateSize = static_cast<size_t>(data[1]) | (static_cast<size_t>(data[2]) << 8);
    if (certificateSize == 0 || length <= kIdentityHeaderSize + certificateSize) {
        return false;
    }
    TlsIdentity identity;
    identity.certificate.assign(data + kIdentityHeaderSize, data + kIdentityHeaderSize + certificateSize);
    identity.key.assign(data + kIdentityHeaderSize + certificateSize, data + length);
    out = std::move(identity);
    return true;
}

}
