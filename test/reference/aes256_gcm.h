// SPDX-License-Identifier: GPL-3.0-or-later
#pragma once

#include <algorithm>
#include <array>
#include <cstdint>
#include <cstring>
#include <span>

namespace reference {
namespace aes256 {

#define AES256 1
#define CBC 0
#define CTR 0
#include "../../components/ttlock/src/third_party/aes/aes.c"
#undef AES256
#undef AES128
#undef CBC
#undef CTR
#undef ECB
#undef Nb
#undef Nk
#undef Nr
#undef Multiply
#undef getSBoxValue
#undef getSBoxInvert
#undef AES_KEYLEN
#undef AES_keyExpSize
#undef AES_BLOCKLEN
#undef MULTIPLY_AS_A_FUNCTION

}

using GcmBlock = std::array<uint8_t, 16>;

inline void multiplyGcm(GcmBlock& block, const GcmBlock& hashKey) {
    GcmBlock product{};
    GcmBlock factor = hashKey;
    for (size_t bit = 0; bit < 128; ++bit) {
        if ((block[bit / 8] & (0x80 >> (bit % 8))) != 0) {
            for (size_t i = 0; i < 16; ++i) product[i] ^= factor[i];
        }
        const bool reduce = (factor[15] & 1) != 0;
        for (size_t i = 15; i > 0; --i) factor[i] = static_cast<uint8_t>((factor[i] >> 1) | (factor[i - 1] << 7));
        factor[0] >>= 1;
        if (reduce) factor[0] ^= 0xE1;
    }
    block = product;
}

inline void hashGcm(GcmBlock& hash, const GcmBlock& hashKey, std::span<const uint8_t> bytes) {
    for (size_t offset = 0; offset < bytes.size(); offset += 16) {
        for (size_t i = 0; i < std::min(size_t{16}, bytes.size() - offset); ++i) hash[i] ^= bytes[offset + i];
        multiplyGcm(hash, hashKey);
    }
}

inline GcmBlock tagGcm(const aes256::AES_ctx& aes, std::span<const uint8_t, 12> nonce,
                       std::span<const uint8_t> aad, std::span<const uint8_t> ciphertext) {
    GcmBlock hashKey{};
    aes256::AES_ECB_encrypt(&aes, hashKey.data());
    GcmBlock hash{};
    hashGcm(hash, hashKey, aad);
    hashGcm(hash, hashKey, ciphertext);
    GcmBlock lengths{};
    for (size_t i = 0; i < 8; ++i) {
        lengths[i] = static_cast<uint8_t>((static_cast<uint64_t>(aad.size()) * 8) >> ((7 - i) * 8));
        lengths[8 + i] = static_cast<uint8_t>((static_cast<uint64_t>(ciphertext.size()) * 8) >> ((7 - i) * 8));
    }
    hashGcm(hash, hashKey, lengths);
    GcmBlock mask{};
    std::copy(nonce.begin(), nonce.end(), mask.begin());
    mask[15] = 1;
    aes256::AES_ECB_encrypt(&aes, mask.data());
    for (size_t i = 0; i < 16; ++i) hash[i] ^= mask[i];
    return hash;
}

inline void cryptGcm(const aes256::AES_ctx& aes, std::span<const uint8_t, 12> nonce, std::span<uint8_t> bytes) {
    GcmBlock counter{};
    std::copy(nonce.begin(), nonce.end(), counter.begin());
    counter[15] = 1;
    for (size_t offset = 0; offset < bytes.size(); offset += 16) {
        for (size_t i = 16; i > 12; --i) if (++counter[i - 1] != 0) break;
        GcmBlock stream = counter;
        aes256::AES_ECB_encrypt(&aes, stream.data());
        for (size_t i = 0; i < std::min(size_t{16}, bytes.size() - offset); ++i) bytes[offset + i] ^= stream[i];
    }
}

inline bool sealGcm(std::span<const uint8_t, 32> key, std::span<const uint8_t, 12> nonce,
                    std::span<const uint8_t> aad, std::span<uint8_t> plaintextAndTag) {
    if (plaintextAndTag.size() < 16) return false;
    aes256::AES_ctx aes;
    aes256::AES_init_ctx(&aes, key.data());
    auto plaintext = plaintextAndTag.first(plaintextAndTag.size() - 16);
    cryptGcm(aes, nonce, plaintext);
    const GcmBlock tag = tagGcm(aes, nonce, aad, plaintext);
    std::copy(tag.begin(), tag.end(), plaintextAndTag.end() - 16);
    return true;
}

inline bool openGcm(std::span<const uint8_t, 32> key, std::span<const uint8_t, 12> nonce,
                    std::span<const uint8_t> aad, std::span<uint8_t> ciphertextAndTag) {
    if (ciphertextAndTag.size() < 16) return false;
    aes256::AES_ctx aes;
    aes256::AES_init_ctx(&aes, key.data());
    auto ciphertext = ciphertextAndTag.first(ciphertextAndTag.size() - 16);
    const GcmBlock expected = tagGcm(aes, nonce, aad, ciphertext);
    if (!std::equal(expected.begin(), expected.end(), ciphertextAndTag.end() - 16)) return false;
    cryptGcm(aes, nonce, ciphertext);
    return true;
}

}
