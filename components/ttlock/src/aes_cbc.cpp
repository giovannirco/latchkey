// SPDX-License-Identifier: GPL-3.0-or-later
#include "ttlock/aes.h"

#include <cstddef>
#include <utility>

#include "third_party/aes/aes.hpp"

namespace ttlock {

const AesKey kDefaultAesKey = {0x98, 0x76, 0x23, 0xE8, 0xA9, 0x23, 0xA1, 0xBB,
                               0x3D, 0x9E, 0x7D, 0x03, 0x78, 0x12, 0x45, 0x88};

Bytes aesEncrypt(const Bytes& plain, const AesKey& key) {
    const size_t padding = AES_BLOCKLEN - plain.size() % AES_BLOCKLEN;
    Bytes buffer(plain);
    buffer.insert(buffer.end(), padding, static_cast<uint8_t>(padding));
    AES_ctx ctx;
    AES_init_ctx_iv(&ctx, key.data(), key.data());
    AES_CBC_encrypt_buffer(&ctx, buffer.data(), buffer.size());
    return buffer;
}

bool aesDecrypt(const Bytes& cipher, const AesKey& key, Bytes& out) {
    if (cipher.empty() || cipher.size() % AES_BLOCKLEN != 0) {
        return false;
    }
    Bytes buffer(cipher);
    AES_ctx ctx;
    AES_init_ctx_iv(&ctx, key.data(), key.data());
    AES_CBC_decrypt_buffer(&ctx, buffer.data(), buffer.size());
    const uint8_t padding = buffer.back();
    if (padding == 0 || padding > AES_BLOCKLEN) {
        return false;
    }
    for (size_t i = buffer.size() - padding; i < buffer.size(); ++i) {
        if (buffer[i] != padding) {
            return false;
        }
    }
    buffer.resize(buffer.size() - padding);
    out = std::move(buffer);
    return true;
}

}
