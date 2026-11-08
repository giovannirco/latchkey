// SPDX-License-Identifier: GPL-3.0-or-later
#include "hmac.h"

#include "psa/crypto.h"

namespace hmac {

namespace {

bool compute(psa_algorithm_t hash, const uint8_t* key, size_t keyLength, const uint8_t* message, size_t messageLength,
             uint8_t* digest, size_t digestSize) {
    psa_key_attributes_t attributes = PSA_KEY_ATTRIBUTES_INIT;
    psa_set_key_type(&attributes, PSA_KEY_TYPE_HMAC);
    psa_set_key_bits(&attributes, PSA_BYTES_TO_BITS(keyLength));
    psa_set_key_usage_flags(&attributes, PSA_KEY_USAGE_SIGN_MESSAGE);
    psa_set_key_algorithm(&attributes, PSA_ALG_HMAC(hash));
    mbedtls_svc_key_id_t keyId = MBEDTLS_SVC_KEY_ID_INIT;
    const psa_status_t imported = psa_import_key(&attributes, key, keyLength, &keyId);
    psa_reset_key_attributes(&attributes);
    if (imported != PSA_SUCCESS) {
        return false;
    }
    size_t length = 0;
    const psa_status_t computed =
        psa_mac_compute(keyId, PSA_ALG_HMAC(hash), message, messageLength, digest, digestSize, &length);
    psa_destroy_key(keyId);
    return computed == PSA_SUCCESS && length == digestSize;
}

}

bool sha1(const uint8_t* key, size_t keyLength, const uint8_t* message, size_t messageLength,
          uint8_t (&digest)[latchkey_util::kHmacSha1Size]) {
    return compute(PSA_ALG_SHA_1, key, keyLength, message, messageLength, digest, sizeof(digest));
}

bool sha256(const uint8_t* key, size_t keyLength, const uint8_t* message, size_t messageLength,
            uint8_t (&digest)[latchkey_util::kHmacSha256Size]) {
    return compute(PSA_ALG_SHA_256, key, keyLength, message, messageLength, digest, sizeof(digest));
}

}
