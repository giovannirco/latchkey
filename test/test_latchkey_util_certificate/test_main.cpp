// SPDX-License-Identifier: GPL-3.0-or-later
#include <unity.h>

#include <cstdint>
#include <vector>

#include "latchkey_util/certificate.h"

using latchkey_util::CertificateValidity;
using latchkey_util::TlsIdentity;

void setUp() {}

void tearDown() {}

static void test_the_certificate_has_no_well_defined_expiration() {
    const CertificateValidity validity = latchkey_util::certificateValidity();
    TEST_ASSERT_EQUAL_STRING("20240101000000", validity.notBefore.c_str());
    TEST_ASSERT_EQUAL_STRING("99991231235959", validity.notAfter.c_str());
}

static void test_the_fingerprint_is_colon_separated_uppercase_hex() {
    uint8_t digest[latchkey_util::kFingerprintDigestSize];
    for (size_t i = 0; i < sizeof(digest); ++i) {
        digest[i] = static_cast<uint8_t>(i * 8 + 1);
    }
    const std::string text = latchkey_util::formatFingerprint(digest);
    TEST_ASSERT_EQUAL_size_t(95, text.size());
    TEST_ASSERT_EQUAL_STRING("01:09:11:19", text.substr(0, 11).c_str());
    TEST_ASSERT_EQUAL_STRING("F1:F9", text.substr(90).c_str());
}

static TlsIdentity sample() {
    TlsIdentity identity;
    identity.certificate = {0x30, 0x82, 0x01, 0x02, 0x03};
    identity.key = {0x30, 0x77, 0x02};
    return identity;
}

static void test_the_identity_is_one_versioned_blob() {
    const std::vector<uint8_t> bytes = latchkey_util::encodeTlsIdentity(sample());
    const std::vector<uint8_t> expected = {2, 5, 0, 0x30, 0x82, 0x01, 0x02, 0x03, 0x30, 0x77, 0x02};
    TEST_ASSERT_EQUAL_size_t(expected.size(), bytes.size());
    TEST_ASSERT_EQUAL_HEX8_ARRAY(expected.data(), bytes.data(), expected.size());
}

static void test_an_identity_survives_a_round_trip() {
    const std::vector<uint8_t> bytes = latchkey_util::encodeTlsIdentity(sample());
    TlsIdentity decoded;
    TEST_ASSERT_TRUE(latchkey_util::decodeTlsIdentity(bytes.data(), bytes.size(), decoded));
    TEST_ASSERT_TRUE(decoded.certificate == sample().certificate);
    TEST_ASSERT_TRUE(decoded.key == sample().key);
}

static void test_a_damaged_identity_is_refused() {
    std::vector<uint8_t> bytes = latchkey_util::encodeTlsIdentity(sample());
    TlsIdentity decoded;
    TEST_ASSERT_FALSE(latchkey_util::decodeTlsIdentity(bytes.data(), 0, decoded));
    TEST_ASSERT_FALSE(latchkey_util::decodeTlsIdentity(bytes.data(), 2, decoded));
    TEST_ASSERT_FALSE(latchkey_util::decodeTlsIdentity(bytes.data(), 3 + 5, decoded));
    TEST_ASSERT_FALSE(latchkey_util::decodeTlsIdentity(bytes.data(), 3 + 4, decoded));
    bytes[0] = 3;
    TEST_ASSERT_FALSE(latchkey_util::decodeTlsIdentity(bytes.data(), bytes.size(), decoded));
    bytes[0] = 2;
    bytes[1] = 0;
    TEST_ASSERT_FALSE(latchkey_util::decodeTlsIdentity(bytes.data(), bytes.size(), decoded));
    TEST_ASSERT_TRUE(decoded.certificate.empty() && decoded.key.empty());
}

static void test_an_identity_from_before_the_fixed_window_is_refused() {
    std::vector<uint8_t> bytes = latchkey_util::encodeTlsIdentity(sample());
    bytes[0] = 1;
    TlsIdentity decoded;
    TEST_ASSERT_FALSE(latchkey_util::decodeTlsIdentity(bytes.data(), bytes.size(), decoded));
}

static void test_an_identity_without_a_key_or_too_large_a_certificate_has_no_blob() {
    TlsIdentity keyless = sample();
    keyless.key.clear();
    TEST_ASSERT_TRUE(latchkey_util::encodeTlsIdentity(keyless).empty());
    TlsIdentity large = sample();
    large.certificate.assign(0x10000, 0x30);
    TEST_ASSERT_TRUE(latchkey_util::encodeTlsIdentity(large).empty());
}

int main() {
    UNITY_BEGIN();
    RUN_TEST(test_the_certificate_has_no_well_defined_expiration);
    RUN_TEST(test_the_fingerprint_is_colon_separated_uppercase_hex);
    RUN_TEST(test_the_identity_is_one_versioned_blob);
    RUN_TEST(test_an_identity_survives_a_round_trip);
    RUN_TEST(test_a_damaged_identity_is_refused);
    RUN_TEST(test_an_identity_from_before_the_fixed_window_is_refused);
    RUN_TEST(test_an_identity_without_a_key_or_too_large_a_certificate_has_no_blob);
    return UNITY_END();
}
