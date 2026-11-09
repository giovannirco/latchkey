// SPDX-License-Identifier: GPL-3.0-or-later
#include "backup_crypto.h"

#include "freertos/FreeRTOS.h"
#include "freertos/task.h"
#include "latchkey_util/pbkdf2.h"
#include "psa/crypto.h"

namespace backup_crypto {
namespace {

static_assert(PSA_AEAD_TAG_LENGTH(PSA_KEY_TYPE_AES, 256, PSA_ALG_GCM) == latchkey_util::kBackupTagSize);

class PsaKey {
public:
    ~PsaKey() { psa_destroy_key(id_); }

    bool import(psa_key_type_t type, psa_algorithm_t algorithm, psa_key_usage_t usage,
                 std::span<const uint8_t> bytes) {
        psa_key_attributes_t attributes = PSA_KEY_ATTRIBUTES_INIT;
        psa_set_key_type(&attributes, type);
        psa_set_key_bits(&attributes, PSA_BYTES_TO_BITS(bytes.size()));
        psa_set_key_usage_flags(&attributes, usage);
        psa_set_key_algorithm(&attributes, algorithm);
        const psa_status_t status = psa_import_key(&attributes, bytes.data(), bytes.size(), &id_);
        psa_reset_key_attributes(&attributes);
        return status == PSA_SUCCESS;
    }

    mbedtls_svc_key_id_t id() const { return id_; }

private:
    mbedtls_svc_key_id_t id_ = MBEDTLS_SVC_KEY_ID_INIT;
};

}

bool PsaCrypto::random(std::span<uint8_t> bytes) {
    return psa_generate_random(bytes.data(), bytes.size()) == PSA_SUCCESS;
}

bool PsaCrypto::deriveKey(std::string_view password, std::span<const uint8_t, 16> salt,
                          std::span<uint8_t, 32> key) {
    PsaKey passwordKey;
    constexpr psa_algorithm_t algorithm = PSA_ALG_HMAC(PSA_ALG_SHA_256);
    if (!passwordKey.import(PSA_KEY_TYPE_HMAC, algorithm, PSA_KEY_USAGE_SIGN_MESSAGE,
                             {reinterpret_cast<const uint8_t*>(password.data()), password.size()})) return false;
    const latchkey_util::KeyedHmacSha256 hmac = [&passwordKey](const uint8_t* message, size_t size,
                                                             uint8_t (&digest)[32]) {
        size_t length = 0;
        return psa_mac_compute(passwordKey.id(), algorithm, message, size, digest, sizeof(digest), &length) ==
                   PSA_SUCCESS && length == sizeof(digest);
    };
    return latchkey_util::pbkdf2HmacSha256(hmac, salt.data(), salt.size(), latchkey_util::kBackupIterations, 1000,
                                           []() { vTaskDelay(1); }, key.data(), key.size());
}

bool PsaCrypto::seal(std::span<const uint8_t, 32> key, std::span<const uint8_t, 12> nonce,
                     std::span<const uint8_t> aad, std::span<uint8_t> plaintextAndTag) {
    if (plaintextAndTag.size() < latchkey_util::kBackupTagSize) return false;
    PsaKey aes;
    if (!aes.import(PSA_KEY_TYPE_AES, PSA_ALG_GCM, PSA_KEY_USAGE_ENCRYPT, key)) return false;
    size_t length = 0;
    return psa_aead_encrypt(aes.id(), PSA_ALG_GCM, nonce.data(), nonce.size(), aad.data(), aad.size(),
                             plaintextAndTag.data(), plaintextAndTag.size() - latchkey_util::kBackupTagSize,
                             plaintextAndTag.data(), plaintextAndTag.size(), &length) == PSA_SUCCESS &&
           length == plaintextAndTag.size();
}

bool PsaCrypto::open(std::span<const uint8_t, 32> key, std::span<const uint8_t, 12> nonce,
                     std::span<const uint8_t> aad, std::span<uint8_t> ciphertextAndTag) {
    if (ciphertextAndTag.size() < latchkey_util::kBackupTagSize) return false;
    PsaKey aes;
    if (!aes.import(PSA_KEY_TYPE_AES, PSA_ALG_GCM, PSA_KEY_USAGE_DECRYPT, key)) return false;
    size_t length = 0;
    const size_t plainSize = ciphertextAndTag.size() - latchkey_util::kBackupTagSize;
    return psa_aead_decrypt(aes.id(), PSA_ALG_GCM, nonce.data(), nonce.size(), aad.data(), aad.size(),
                             ciphertextAndTag.data(), ciphertextAndTag.size(), ciphertextAndTag.data(), plainSize,
                             &length) == PSA_SUCCESS && length == plainSize;
}

}
