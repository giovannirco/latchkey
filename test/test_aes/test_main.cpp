// SPDX-License-Identifier: GPL-3.0-or-later
#include <unity.h>

#include <algorithm>
#include <cstddef>
#include <cstdint>

#include "../vectors/aes_vectors.h"
#include "ttlock/aes.h"

void setUp() {}

void tearDown() {}

static ttlock::AesKey toKey(const uint8_t* bytes) {
    ttlock::AesKey key{};
    std::copy(bytes, bytes + key.size(), key.begin());
    return key;
}

static ttlock::Bytes toBytes(const uint8_t* data, size_t size) {
    return size == 0 ? ttlock::Bytes{} : ttlock::Bytes(data, data + size);
}

static void assertBytes(const uint8_t* expected, size_t expectedSize, const ttlock::Bytes& actual, const char* name) {
    TEST_ASSERT_EQUAL_UINT_MESSAGE(expectedSize, actual.size(), name);
    if (expectedSize > 0) {
        TEST_ASSERT_EQUAL_HEX8_ARRAY_MESSAGE(expected, actual.data(), expectedSize, name);
    }
}

static void test_default_key_is_the_factory_key() {
    TEST_ASSERT_EQUAL_HEX8_ARRAY(vectors::aes::kDefaultKey, ttlock::kDefaultAesKey.data(), 16);
}

static void test_encrypt_matches_ttlock_ble() {
    for (const auto& c : vectors::aes::kCases) {
        const ttlock::Bytes cipher = ttlock::aesEncrypt(toBytes(c.plain, c.plainSize), toKey(c.key));
        assertBytes(c.cipher, c.cipherSize, cipher, c.name);
    }
}

static void test_decrypt_matches_ttlock_ble() {
    for (const auto& c : vectors::aes::kCases) {
        ttlock::Bytes plain;
        TEST_ASSERT_TRUE_MESSAGE(ttlock::aesDecrypt(toBytes(c.cipher, c.cipherSize), toKey(c.key), plain), c.name);
        assertBytes(c.plain, c.plainSize, plain, c.name);
    }
}

static void test_ciphertext_size_follows_pkcs7() {
    const ttlock::AesKey key = ttlock::kDefaultAesKey;
    TEST_ASSERT_EQUAL_UINT(16, ttlock::aesEncrypt(ttlock::Bytes(0), key).size());
    TEST_ASSERT_EQUAL_UINT(16, ttlock::aesEncrypt(ttlock::Bytes(15), key).size());
    TEST_ASSERT_EQUAL_UINT(32, ttlock::aesEncrypt(ttlock::Bytes(16), key).size());
    TEST_ASSERT_EQUAL_UINT(32, ttlock::aesEncrypt(ttlock::Bytes(17), key).size());
    TEST_ASSERT_EQUAL_UINT(240, ttlock::aesEncrypt(ttlock::Bytes(239), key).size());
}

static void test_bad_padding_is_rejected() {
    for (const auto& c : vectors::aes::kBadPadding) {
        ttlock::Bytes plain;
        TEST_ASSERT_FALSE_MESSAGE(ttlock::aesDecrypt(toBytes(c.cipher, c.size), ttlock::kDefaultAesKey, plain),
                                  c.name);
    }
}

static void test_ciphertext_not_a_multiple_of_16_is_rejected() {
    ttlock::Bytes plain;
    TEST_ASSERT_FALSE(ttlock::aesDecrypt(ttlock::Bytes(15, 0x11), ttlock::kDefaultAesKey, plain));
    TEST_ASSERT_FALSE(ttlock::aesDecrypt(ttlock::Bytes(17, 0x11), ttlock::kDefaultAesKey, plain));
}

static void test_empty_ciphertext_is_rejected() {
    ttlock::Bytes plain;
    TEST_ASSERT_FALSE(ttlock::aesDecrypt(ttlock::Bytes{}, ttlock::kDefaultAesKey, plain));
}

static void test_failed_decrypt_leaves_output_untouched() {
    ttlock::Bytes plain{0xAB, 0xCD};
    const auto& bad = vectors::aes::kBadPadding[0];
    TEST_ASSERT_FALSE(ttlock::aesDecrypt(toBytes(bad.cipher, bad.size), ttlock::kDefaultAesKey, plain));
    TEST_ASSERT_EQUAL_UINT(2, plain.size());
    TEST_ASSERT_EQUAL_HEX8(0xAB, plain[0]);
    TEST_ASSERT_EQUAL_HEX8(0xCD, plain[1]);
}

int main() {
    UNITY_BEGIN();
    RUN_TEST(test_default_key_is_the_factory_key);
    RUN_TEST(test_encrypt_matches_ttlock_ble);
    RUN_TEST(test_decrypt_matches_ttlock_ble);
    RUN_TEST(test_ciphertext_size_follows_pkcs7);
    RUN_TEST(test_bad_padding_is_rejected);
    RUN_TEST(test_ciphertext_not_a_multiple_of_16_is_rejected);
    RUN_TEST(test_empty_ciphertext_is_rejected);
    RUN_TEST(test_failed_decrypt_leaves_output_untouched);
    return UNITY_END();
}
