// SPDX-License-Identifier: GPL-3.0-or-later
#pragma once

#include <cstddef>
#include <cstdint>
#include <cstring>
#include <vector>

namespace reference {

inline uint32_t rotateRight(uint32_t value, unsigned bits) { return (value >> bits) | (value << (32 - bits)); }

inline void sha256(const uint8_t* data, size_t length, uint8_t (&out)[32]) {
    static const uint32_t kRound[64] = {
        0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5, 0x3956c25b, 0x59f111f1, 0x923f82a4, 0xab1c5ed5,
        0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3, 0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174,
        0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc, 0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da,
        0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7, 0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967,
        0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13, 0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85,
        0xa2bfe8a1, 0xa81a664b, 0xc24b8b70, 0xc76c51a3, 0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070,
        0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5, 0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3,
        0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208, 0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2,
    };
    uint32_t state[8] = {0x6a09e667, 0xbb67ae85, 0x3c6ef372, 0xa54ff53a,
                         0x510e527f, 0x9b05688c, 0x1f83d9ab, 0x5be0cd19};
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
        uint32_t words[64];
        for (size_t i = 0; i < 16; ++i) {
            const uint8_t* word = &message[block + i * 4];
            words[i] = static_cast<uint32_t>(word[0]) << 24 | static_cast<uint32_t>(word[1]) << 16 |
                       static_cast<uint32_t>(word[2]) << 8 | word[3];
        }
        for (size_t i = 16; i < 64; ++i) {
            const uint32_t s0 = rotateRight(words[i - 15], 7) ^ rotateRight(words[i - 15], 18) ^ (words[i - 15] >> 3);
            const uint32_t s1 = rotateRight(words[i - 2], 17) ^ rotateRight(words[i - 2], 19) ^ (words[i - 2] >> 10);
            words[i] = words[i - 16] + s0 + words[i - 7] + s1;
        }
        uint32_t a = state[0];
        uint32_t b = state[1];
        uint32_t c = state[2];
        uint32_t d = state[3];
        uint32_t e = state[4];
        uint32_t f = state[5];
        uint32_t g = state[6];
        uint32_t h = state[7];
        for (size_t i = 0; i < 64; ++i) {
            const uint32_t sum1 = rotateRight(e, 6) ^ rotateRight(e, 11) ^ rotateRight(e, 25);
            const uint32_t choose = (e & f) ^ (~e & g);
            const uint32_t first = h + sum1 + choose + kRound[i] + words[i];
            const uint32_t sum0 = rotateRight(a, 2) ^ rotateRight(a, 13) ^ rotateRight(a, 22);
            const uint32_t majority = (a & b) ^ (a & c) ^ (b & c);
            const uint32_t second = sum0 + majority;
            h = g;
            g = f;
            f = e;
            e = d + first;
            d = c;
            c = b;
            b = a;
            a = first + second;
        }
        state[0] += a;
        state[1] += b;
        state[2] += c;
        state[3] += d;
        state[4] += e;
        state[5] += f;
        state[6] += g;
        state[7] += h;
    }
    for (size_t i = 0; i < 8; ++i) {
        out[i * 4] = static_cast<uint8_t>(state[i] >> 24);
        out[i * 4 + 1] = static_cast<uint8_t>(state[i] >> 16);
        out[i * 4 + 2] = static_cast<uint8_t>(state[i] >> 8);
        out[i * 4 + 3] = static_cast<uint8_t>(state[i]);
    }
}

inline bool hmacSha256(const uint8_t* key, size_t keyLength, const uint8_t* message, size_t messageLength,
                       uint8_t (&digest)[32]) {
    uint8_t block[64] = {};
    if (keyLength > sizeof(block)) {
        uint8_t hashed[32];
        sha256(key, keyLength, hashed);
        std::memcpy(block, hashed, sizeof(hashed));
    } else if (keyLength > 0) {
        std::memcpy(block, key, keyLength);
    }
    std::vector<uint8_t> inner(sizeof(block) + messageLength);
    for (size_t i = 0; i < sizeof(block); ++i) {
        inner[i] = block[i] ^ 0x36;
    }
    if (messageLength > 0) {
        std::memcpy(inner.data() + sizeof(block), message, messageLength);
    }
    uint8_t innerDigest[32];
    sha256(inner.data(), inner.size(), innerDigest);
    uint8_t outer[sizeof(block) + sizeof(innerDigest)];
    for (size_t i = 0; i < sizeof(block); ++i) {
        outer[i] = block[i] ^ 0x5C;
    }
    std::memcpy(outer + sizeof(block), innerDigest, sizeof(innerDigest));
    sha256(outer, sizeof(outer), digest);
    return true;
}

}
