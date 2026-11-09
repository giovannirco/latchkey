// SPDX-License-Identifier: GPL-3.0-or-later
#include "latchkey_util/pbkdf2.h"

#include <cstring>
#include <memory>
#include <new>
#include <span>

namespace latchkey_util {

namespace {

constexpr size_t kBlockIndexSize = 4;
constexpr uint64_t kMaxBlocks = 0xFFFFFFFFu;

void wipe(uint8_t* data, size_t length) {
    volatile uint8_t* bytes = data;
    for (size_t i = 0; i < length; ++i) {
        bytes[i] = 0;
    }
}

struct Digest {
    uint8_t bytes[kHmacSha256Size] = {};

    ~Digest() { wipe(bytes, sizeof(bytes)); }
};

class Derivation {
public:
    Derivation(const KeyedHmacSha256& hmac, uint32_t iterations, uint32_t yieldEvery, const Pbkdf2Yield& yield)
        : hmac_(hmac), iterations_(iterations), yieldEvery_(yieldEvery), yield_(yield) {}

    bool block(std::span<uint8_t> saltAndIndex, uint32_t index, uint8_t (&out)[kHmacSha256Size]) {
        const size_t at = saltAndIndex.size() - kBlockIndexSize;
        for (size_t i = 0; i < kBlockIndexSize; ++i) {
            saltAndIndex[at + i] = static_cast<uint8_t>(index >> (8 * (kBlockIndexSize - 1 - i)));
        }
        Digest previous;
        if (!prf(saltAndIndex.data(), saltAndIndex.size(), previous.bytes)) {
            return false;
        }
        std::memcpy(out, previous.bytes, sizeof(out));
        Digest next;
        for (uint32_t round = 1; round < iterations_; ++round) {
            if (!prf(previous.bytes, sizeof(previous.bytes), next.bytes)) {
                return false;
            }
            for (size_t i = 0; i < kHmacSha256Size; ++i) {
                out[i] ^= next.bytes[i];
            }
            std::memcpy(previous.bytes, next.bytes, sizeof(previous.bytes));
        }
        return true;
    }

private:
    bool prf(const uint8_t* message, size_t length, uint8_t (&digest)[kHmacSha256Size]) {
        if (!hmac_(message, length, digest)) {
            return false;
        }
        if (++calls_ % yieldEvery_ == 0) {
            yield_();
        }
        return true;
    }

    const KeyedHmacSha256& hmac_;
    uint32_t iterations_;
    uint32_t yieldEvery_;
    const Pbkdf2Yield& yield_;
    uint64_t calls_ = 0;
};

}

bool pbkdf2HmacSha256(const KeyedHmacSha256& passwordHmac, const uint8_t* salt, size_t saltLength, uint32_t iterations,
                      uint32_t yieldEvery, const Pbkdf2Yield& yield, uint8_t* out, size_t outLength) {
    if (!passwordHmac || !yield || iterations == 0 || yieldEvery == 0 || out == nullptr || outLength == 0 ||
        (salt == nullptr && saltLength > 0) || (outLength - 1) / kHmacSha256Size >= kMaxBlocks) {
        return false;
    }
    if (saltLength > SIZE_MAX - kBlockIndexSize) {
        wipe(out, outLength);
        return false;
    }
    const size_t scratchSize = saltLength + kBlockIndexSize;
    const std::unique_ptr<uint8_t[]> saltAndIndex(new (std::nothrow) uint8_t[scratchSize]);
    if (saltAndIndex == nullptr) {
        wipe(out, outLength);
        return false;
    }
    if (saltLength > 0) {
        std::memcpy(saltAndIndex.get(), salt, saltLength);
    }
    Derivation derivation(passwordHmac, iterations, yieldEvery, yield);
    Digest block;
    uint32_t index = 1;
    for (size_t written = 0; written < outLength; written += kHmacSha256Size, ++index) {
        if (!derivation.block({saltAndIndex.get(), scratchSize}, index, block.bytes)) {
            wipe(out, outLength);
            return false;
        }
        const size_t take = outLength - written < kHmacSha256Size ? outLength - written : kHmacSha256Size;
        std::memcpy(out + written, block.bytes, take);
    }
    return true;
}

}
