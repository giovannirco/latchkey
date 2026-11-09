// SPDX-License-Identifier: GPL-3.0-or-later
#pragma once

#include "latchkey_util/key_backup.h"

namespace backup_crypto {

class PsaCrypto final : public latchkey_util::BackupCrypto {
public:
    bool random(std::span<uint8_t> bytes) override;
    bool deriveKey(std::string_view password, std::span<const uint8_t, 16> salt,
                    std::span<uint8_t, 32> key) override;
    bool seal(std::span<const uint8_t, 32> key, std::span<const uint8_t, 12> nonce,
               std::span<const uint8_t> aad, std::span<uint8_t> plaintextAndTag) override;
    bool open(std::span<const uint8_t, 32> key, std::span<const uint8_t, 12> nonce,
               std::span<const uint8_t> aad, std::span<uint8_t> ciphertextAndTag) override;
};

}
