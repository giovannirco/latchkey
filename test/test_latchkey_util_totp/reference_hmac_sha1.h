// SPDX-License-Identifier: GPL-3.0-or-later
#pragma once

#include <cstddef>
#include <cstdint>
#include <cstring>
#include <vector>

namespace reference {

inline uint32_t rotateLeft(uint32_t value, unsigned bits) { return (value << bits) | (value >> (32 - bits)); }

inline void sha1(const uint8_t* data, size_t length, uint8_t (&out)[20]) {
    uint32_t state[5] = {0x67452301, 0xEFCDAB89, 0x98BADCFE, 0x10325476, 0xC3D2E1F0};
    std::vector<uint8_t> message(data, data + length);
    const uint64_t bits = static_cast<uint64_t>(length) * 8;
    message.push_back(0x80);
    while (message.size() % 64 != 56) {
        message.push_back(0);
    }
    for (int shift = 56; shift >= 0; shift -= 8) {
        message.push_back(static_cast<uint8_t>(bits >> shift));
    }
    for (size_t block = 0; block < message.size(); block += 64) {
        uint32_t words[80];
        for (size_t i = 0; i < 16; ++i) {
            const uint8_t* word = &message[block + i * 4];
            words[i] = static_cast<uint32_t>(word[0]) << 24 | static_cast<uint32_t>(word[1]) << 16 |
                       static_cast<uint32_t>(word[2]) << 8 | word[3];
        }
        for (size_t i = 16; i < 80; ++i) {
            words[i] = rotateLeft(words[i - 3] ^ words[i - 8] ^ words[i - 14] ^ words[i - 16], 1);
        }
        uint32_t a = state[0];
        uint32_t b = state[1];
        uint32_t c = state[2];
        uint32_t d = state[3];
        uint32_t e = state[4];
        for (size_t i = 0; i < 80; ++i) {
            uint32_t mix = 0;
            uint32_t constant = 0;
            if (i < 20) {
                mix = (b & c) | (~b & d);
                constant = 0x5A827999;
            } else if (i < 40) {
                mix = b ^ c ^ d;
                constant = 0x6ED9EBA1;
            } else if (i < 60) {
                mix = (b & c) | (b & d) | (c & d);
                constant = 0x8F1BBCDC;
            } else {
                mix = b ^ c ^ d;
                constant = 0xCA62C1D6;
            }
            const uint32_t next = rotateLeft(a, 5) + mix + e + constant + words[i];
            e = d;
            d = c;
            c = rotateLeft(b, 30);
            b = a;
            a = next;
        }
        state[0] += a;
        state[1] += b;
        state[2] += c;
        state[3] += d;
        state[4] += e;
    }
    for (size_t i = 0; i < 5; ++i) {
        out[i * 4] = static_cast<uint8_t>(state[i] >> 24);
        out[i * 4 + 1] = static_cast<uint8_t>(state[i] >> 16);
        out[i * 4 + 2] = static_cast<uint8_t>(state[i] >> 8);
        out[i * 4 + 3] = static_cast<uint8_t>(state[i]);
    }
}

inline bool hmacSha1(const uint8_t* key, size_t keyLength, const uint8_t* message, size_t messageLength,
                     uint8_t (&digest)[20]) {
    uint8_t block[64] = {};
    if (keyLength > sizeof(block)) {
        uint8_t hashed[20];
        sha1(key, keyLength, hashed);
        std::memcpy(block, hashed, sizeof(hashed));
    } else {
        std::memcpy(block, key, keyLength);
    }
    std::vector<uint8_t> inner(sizeof(block) + messageLength);
    for (size_t i = 0; i < sizeof(block); ++i) {
        inner[i] = block[i] ^ 0x36;
    }
    std::memcpy(inner.data() + sizeof(block), message, messageLength);
    uint8_t innerDigest[20];
    sha1(inner.data(), inner.size(), innerDigest);
    uint8_t outer[sizeof(block) + sizeof(innerDigest)];
    for (size_t i = 0; i < sizeof(block); ++i) {
        outer[i] = block[i] ^ 0x5C;
    }
    std::memcpy(outer + sizeof(block), innerDigest, sizeof(innerDigest));
    sha1(outer, sizeof(outer), digest);
    return true;
}

}
