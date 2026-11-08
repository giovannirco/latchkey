// SPDX-License-Identifier: GPL-3.0-or-later
#include "latchkey_util/totp.h"

#include "latchkey_util/constant_time.h"

namespace latchkey_util {

namespace {

constexpr size_t kCodeDigits = 6;
constexpr uint32_t kCodeModulus = 1000000;

void bigEndian(uint64_t value, uint8_t (&out)[8]) {
    for (size_t i = 0; i < sizeof(out); ++i) {
        out[i] = static_cast<uint8_t>(value >> (56 - 8 * i));
    }
}

void bigEndian(uint32_t value, uint8_t (&out)[4]) {
    for (size_t i = 0; i < sizeof(out); ++i) {
        out[i] = static_cast<uint8_t>(value >> (24 - 8 * i));
    }
}

}

uint64_t totpStep(int64_t unixSeconds) {
    return unixSeconds < 0 ? 0 : static_cast<uint64_t>(unixSeconds / kTotpStepSeconds);
}

bool totpCode(const uint8_t* secret, size_t secretLength, uint64_t step, HmacSha1 hmac, uint32_t& code) {
    uint8_t counter[8];
    bigEndian(step, counter);
    uint8_t digest[kHmacSha1Size];
    if (!hmac(secret, secretLength, counter, sizeof(counter), digest)) {
        return false;
    }
    const size_t offset = digest[kHmacSha1Size - 1] & 0x0F;
    const uint32_t truncated = static_cast<uint32_t>(digest[offset] & 0x7F) << 24 |
                               static_cast<uint32_t>(digest[offset + 1]) << 16 |
                               static_cast<uint32_t>(digest[offset + 2]) << 8 | digest[offset + 3];
    code = truncated % kCodeModulus;
    return true;
}

TotpVerdict totpVerify(const uint8_t* secret, size_t secretLength, int64_t unixSeconds, uint32_t code,
                       uint64_t lastStep, HmacSha1 hmac, uint64_t& acceptedStep) {
    const uint64_t current = totpStep(unixSeconds);
    uint8_t presented[4];
    bigEndian(code, presented);
    uint64_t matched = 0;
    uint8_t found = 0;
    for (uint64_t candidate = current == 0 ? 0 : current - 1; candidate <= current + 1; ++candidate) {
        uint32_t expected = 0;
        if (!totpCode(secret, secretLength, candidate, hmac, expected)) {
            return TotpVerdict::HmacFailed;
        }
        uint8_t computed[4];
        bigEndian(expected, computed);
        const uint8_t hit =
            static_cast<uint8_t>(constantTimeEqual(computed, presented, sizeof(computed)) & (candidate > lastStep));
        const uint64_t mask = 0 - static_cast<uint64_t>(hit);
        matched = (candidate & mask) | (matched & ~mask);
        found = static_cast<uint8_t>(found | hit);
    }
    if (found == 0) {
        return TotpVerdict::Rejected;
    }
    acceptedStep = matched;
    return TotpVerdict::Accepted;
}

bool parseTotpCode(std::string_view text, uint32_t& code) {
    if (text.size() != kCodeDigits) {
        return false;
    }
    uint32_t value = 0;
    for (char c : text) {
        if (c < '0' || c > '9') {
            return false;
        }
        value = value * 10 + static_cast<uint32_t>(c - '0');
    }
    code = value;
    return true;
}

}
