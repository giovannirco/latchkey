// SPDX-License-Identifier: GPL-3.0-or-later
#pragma once

#include "aes256_gcm.h"
#include "hmac_sha256.h"
#include "latchkey_util/key_backup.h"
#include "latchkey_util/pbkdf2.h"

class ReferenceCrypto : public latchkey_util::BackupCrypto {
public:
    size_t randomCalls = 0;
    size_t derivations = 0;
    size_t yields = 0;
    size_t seals = 0;
    size_t opens = 0;
    unsigned failAt = 0;

    bool random(std::span<uint8_t> bytes) override {
        ++randomCalls;
        for (auto& byte : bytes) byte = next_++;
        return failAt != 1;
    }

    bool deriveKey(std::string_view password, std::span<const uint8_t, 16> salt,
                    std::span<uint8_t, 32> key) override {
        ++derivations;
        const latchkey_util::KeyedHmacSha256 hmac = [password](const uint8_t* message, size_t size, uint8_t (&digest)[32]) {
            return reference::hmacSha256(reinterpret_cast<const uint8_t*>(password.data()), password.size(),
                                         message, size, digest);
        };
        const bool result = latchkey_util::pbkdf2HmacSha256(hmac, salt.data(), salt.size(), latchkey_util::kBackupIterations, 1000,
                                             [this]() { ++yields; }, key.data(), key.size());
        return result && failAt != 2;
    }

    bool seal(std::span<const uint8_t, 32> key, std::span<const uint8_t, 12> nonce,
               std::span<const uint8_t> aad, std::span<uint8_t> bytes) override {
        ++seals;
        return reference::sealGcm(key, nonce, aad, bytes) && failAt != 3;
    }

    bool open(std::span<const uint8_t, 32> key, std::span<const uint8_t, 12> nonce,
               std::span<const uint8_t> aad, std::span<uint8_t> bytes) override {
        ++opens;
        return reference::openGcm(key, nonce, aad, bytes) && failAt != 4;
    }

private:
    uint8_t next_ = 0;
};
