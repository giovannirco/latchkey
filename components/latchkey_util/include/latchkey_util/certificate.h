// SPDX-License-Identifier: GPL-3.0-or-later
#pragma once

#include <cstddef>
#include <cstdint>
#include <string>
#include <vector>

namespace latchkey_util {

inline constexpr size_t kFingerprintDigestSize = 32;
inline constexpr uint8_t kTlsIdentityVersion = 2;

struct CertificateValidity {
    std::string notBefore;
    std::string notAfter;
};

struct TlsIdentity {
    std::vector<uint8_t> certificate;
    std::vector<uint8_t> key;
};

CertificateValidity certificateValidity();

std::string formatFingerprint(const uint8_t (&digest)[kFingerprintDigestSize]);

std::vector<uint8_t> encodeTlsIdentity(const TlsIdentity& identity);

bool decodeTlsIdentity(const uint8_t* data, size_t length, TlsIdentity& out);

}
