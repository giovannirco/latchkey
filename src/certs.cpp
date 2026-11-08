// SPDX-License-Identifier: GPL-3.0-or-later
#include "certs.h"

#include <mutex>
#include <string>
#include <vector>

#include "esp_log.h"
#include "esp_random.h"
#include "esp_timer.h"
#include "mbedtls/pk.h"
#include "mbedtls/platform_util.h"
#include "mbedtls/x509_crt.h"
#include "psa/crypto.h"

#include "board.h"
#include "store.h"

namespace certs {

namespace {

constexpr const char* TAG = "certs";
constexpr size_t kSerialSize = 16;
constexpr size_t kDerBuffer = 1024;

std::mutex s_mutex;
std::optional<std::string> s_fingerprint;

std::optional<std::string> fingerprintOf(const std::vector<uint8_t>& certificate) {
    uint8_t digest[latchkey_util::kFingerprintDigestSize];
    size_t length = 0;
    if (psa_hash_compute(PSA_ALG_SHA_256, certificate.data(), certificate.size(), digest, sizeof(digest), &length) !=
            PSA_SUCCESS ||
        length != sizeof(digest)) {
        return std::nullopt;
    }
    return latchkey_util::formatFingerprint(digest);
}

void remember(const std::vector<uint8_t>& certificate) {
    std::optional<std::string> text = fingerprintOf(certificate);
    if (!text.has_value()) {
        ESP_LOGE(TAG, "cannot compute the certificate fingerprint");
        return;
    }
    ESP_LOGI(TAG, "HTTPS certificate SHA-256 %s", text->c_str());
    std::lock_guard<std::mutex> lock(s_mutex);
    s_fingerprint = std::move(text);
}

bool copyDer(int written, const std::vector<uint8_t>& buffer, std::vector<uint8_t>& out) {
    if (written <= 0) {
        return false;
    }
    out.assign(buffer.end() - written, buffer.end());
    return true;
}

bool newKey(mbedtls_pk_context& key) {
    psa_key_attributes_t attributes = PSA_KEY_ATTRIBUTES_INIT;
    psa_set_key_type(&attributes, PSA_KEY_TYPE_ECC_KEY_PAIR(PSA_ECC_FAMILY_SECP_R1));
    psa_set_key_bits(&attributes, 256);
    psa_set_key_usage_flags(&attributes, PSA_KEY_USAGE_SIGN_HASH | PSA_KEY_USAGE_EXPORT);
    psa_set_key_algorithm(&attributes, PSA_ALG_ECDSA(PSA_ALG_SHA_256));
    mbedtls_svc_key_id_t keyId = MBEDTLS_SVC_KEY_ID_INIT;
    const psa_status_t generated = psa_generate_key(&attributes, &keyId);
    psa_reset_key_attributes(&attributes);
    if (generated != PSA_SUCCESS) {
        ESP_LOGE(TAG, "key generation failed: %d", static_cast<int>(generated));
        return false;
    }
    const int copied = mbedtls_pk_copy_from_psa(keyId, &key);
    psa_destroy_key(keyId);
    if (copied != 0) {
        ESP_LOGE(TAG, "key copy failed: -0x%04x", static_cast<unsigned>(-copied));
        return false;
    }
    return true;
}

bool writeCertificate(mbedtls_pk_context& key, uint32_t ipv4, std::vector<uint8_t>& buffer,
                      std::vector<uint8_t>& out) {
    const std::string name = std::string("CN=") + board::name();
    const latchkey_util::CertificateValidity validity = latchkey_util::certificateValidity();
    uint8_t serial[kSerialSize];
    esp_fill_random(serial, sizeof(serial));
    serial[0] = static_cast<uint8_t>((serial[0] & 0x3F) | 0x40);
    uint8_t address[4] = {static_cast<uint8_t>(ipv4 >> 24), static_cast<uint8_t>(ipv4 >> 16),
                          static_cast<uint8_t>(ipv4 >> 8), static_cast<uint8_t>(ipv4)};
    mbedtls_x509_san_list san{};
    san.node.type = MBEDTLS_X509_SAN_IP_ADDRESS;
    san.node.san.unstructured_name.p = address;
    san.node.san.unstructured_name.len = sizeof(address);
    san.next = nullptr;
    mbedtls_x509write_cert certificate;
    mbedtls_x509write_crt_init(&certificate);
    mbedtls_x509write_crt_set_version(&certificate, MBEDTLS_X509_CRT_VERSION_3);
    mbedtls_x509write_crt_set_md_alg(&certificate, MBEDTLS_MD_SHA256);
    mbedtls_x509write_crt_set_subject_key(&certificate, &key);
    mbedtls_x509write_crt_set_issuer_key(&certificate, &key);
    const bool configured =
        mbedtls_x509write_crt_set_serial_raw(&certificate, serial, sizeof(serial)) == 0 &&
        mbedtls_x509write_crt_set_subject_name(&certificate, name.c_str()) == 0 &&
        mbedtls_x509write_crt_set_issuer_name(&certificate, name.c_str()) == 0 &&
        mbedtls_x509write_crt_set_validity(&certificate, validity.notBefore.c_str(), validity.notAfter.c_str()) ==
            0 &&
        mbedtls_x509write_crt_set_basic_constraints(&certificate, 0, -1) == 0 &&
        mbedtls_x509write_crt_set_subject_key_identifier(&certificate) == 0 &&
        mbedtls_x509write_crt_set_key_usage(&certificate, MBEDTLS_X509_KU_DIGITAL_SIGNATURE) == 0 &&
        mbedtls_x509write_crt_set_subject_alternative_name(&certificate, &san) == 0;
    const int written =
        configured ? mbedtls_x509write_crt_der(&certificate, buffer.data(), buffer.size()) : -1;
    mbedtls_x509write_crt_free(&certificate);
    if (!copyDer(written, buffer, out)) {
        ESP_LOGE(TAG, "certificate writing failed: %d", written);
        return false;
    }
    return true;
}

esp_err_t generate(uint32_t ipv4, latchkey_util::TlsIdentity& out) {
    const int64_t started = esp_timer_get_time();
    mbedtls_pk_context key;
    mbedtls_pk_init(&key);
    std::vector<uint8_t> buffer(kDerBuffer);
    latchkey_util::TlsIdentity identity;
    const bool made = newKey(key) && writeCertificate(key, ipv4, buffer, identity.certificate) &&
                      copyDer(mbedtls_pk_write_key_der(&key, buffer.data(), buffer.size()), buffer, identity.key);
    mbedtls_pk_free(&key);
    mbedtls_platform_zeroize(buffer.data(), buffer.size());
    if (!made) {
        mbedtls_platform_zeroize(identity.key.data(), identity.key.size());
        return ESP_FAIL;
    }
    const esp_err_t stored = store::cfg::saveTlsIdentity(identity);
    if (stored != ESP_OK) {
        mbedtls_platform_zeroize(identity.key.data(), identity.key.size());
        ESP_LOGE(TAG, "cannot store the certificate: %s", esp_err_to_name(stored));
        return stored;
    }
    ESP_LOGI(TAG, "new P-256 key and self-signed certificate (%u bytes) in %lld ms",
             static_cast<unsigned>(identity.certificate.size()),
             static_cast<long long>((esp_timer_get_time() - started) / 1000));
    out = std::move(identity);
    return ESP_OK;
}

}

void init() {
    latchkey_util::TlsIdentity identity;
    if (store::cfg::loadTlsIdentity(identity)) {
        remember(identity.certificate);
    }
    mbedtls_platform_zeroize(identity.key.data(), identity.key.size());
}

esp_err_t ensure(uint32_t ipv4, latchkey_util::TlsIdentity& out) {
    latchkey_util::TlsIdentity identity;
    if (!store::cfg::loadTlsIdentity(identity)) {
        const esp_err_t generated = generate(ipv4, identity);
        if (generated != ESP_OK) {
            return generated;
        }
    }
    remember(identity.certificate);
    out = std::move(identity);
    return ESP_OK;
}

std::optional<std::string> fingerprint() {
    std::lock_guard<std::mutex> lock(s_mutex);
    return s_fingerprint;
}

}
