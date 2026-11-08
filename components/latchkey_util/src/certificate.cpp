// SPDX-License-Identifier: GPL-3.0-or-later
#include "latchkey_util/certificate.h"

#include <utility>

namespace latchkey_util {

namespace {

constexpr size_t kIdentityHeaderSize = 3;
constexpr size_t kMaxCertificateSize = 0xFFFF;
constexpr const char* kNotBefore = "20240101000000";
constexpr const char* kNoWellDefinedExpiration = "99991231235959";
constexpr char kHexDigits[] = "0123456789ABCDEF";

}

CertificateValidity certificateValidity() { return CertificateValidity{kNotBefore, kNoWellDefinedExpiration}; }

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
