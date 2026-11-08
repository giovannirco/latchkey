// SPDX-License-Identifier: GPL-3.0-or-later
#include <unity.h>

#include <cstddef>
#include <cstdint>
#include <cstdio>
#include <string>

#include "../reference/hmac_sha256.h"
#include "latchkey_util/hmac_sha256.h"
#include "latchkey_util/passcode_id.h"

using latchkey_util::LockAesKey;
using latchkey_util::PasscodeId;

void setUp() {}

void tearDown() {}

static const LockAesKey kLockKey{0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77,
                                 0x88, 0x99, 0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF};
static const LockAesKey kOtherLockKey{0x0F, 0x0E, 0x0D, 0x0C, 0x0B, 0x0A, 0x09, 0x08,
                                      0x07, 0x06, 0x05, 0x04, 0x03, 0x02, 0x01, 0x00};
static const LockAesKey kDefaultKey{0x98, 0x76, 0x23, 0xE8, 0xA9, 0x23, 0xA1, 0xBB,
                                    0x3D, 0x9E, 0x7D, 0x03, 0x78, 0x12, 0x45, 0x88};

static unsigned s_hmacCalls = 0;

static bool referenceHmac(const uint8_t* key, size_t keyLength, const uint8_t* message, size_t messageLength,
                          uint8_t (&digest)[latchkey_util::kHmacSha256Size]) {
    ++s_hmacCalls;
    return reference::hmacSha256(key, keyLength, message, messageLength, digest);
}

static bool failingHmac(const uint8_t*, size_t, const uint8_t*, size_t, uint8_t (&)[latchkey_util::kHmacSha256Size]) {
    return false;
}

static std::string hex(const PasscodeId& id) {
    char text[2 * latchkey_util::kPasscodeIdSize + 1];
    for (size_t i = 0; i < id.size(); ++i) {
        std::snprintf(text + 2 * i, 3, "%02x", id[i]);
    }
    return text;
}

static PasscodeId idOf(const LockAesKey& key, const std::string& code) {
    PasscodeId id{};
    TEST_ASSERT_TRUE(latchkey_util::passcodeId(key, code, referenceHmac, id));
    return id;
}

static std::string fourDigits(unsigned value) {
    char text[5];
    std::snprintf(text, sizeof(text), "%04u", value);
    return text;
}

static void test_the_id_is_six_bytes_of_a_labelled_hmac_under_the_lock_key() {
    TEST_ASSERT_EQUAL_UINT(6, latchkey_util::kPasscodeIdSize);
    TEST_ASSERT_EQUAL_STRING("01235252d4d1", hex(idOf(kLockKey, "1234")).c_str());
    TEST_ASSERT_EQUAL_STRING("13ec081e65d7", hex(idOf(kLockKey, "123456789")).c_str());
    TEST_ASSERT_NOT_EQUAL(0, hex(idOf(kLockKey, "1234")).compare("2e2632aed65c"));
}

static void test_the_same_lock_record_gives_the_same_id_on_any_board() {
    const PasscodeId first = idOf(kLockKey, "246810");
    LockAesKey restored{};
    for (size_t i = 0; i < restored.size(); ++i) {
        restored[i] = kLockKey[i];
    }
    TEST_ASSERT_EQUAL_STRING(hex(first).c_str(), hex(idOf(restored, "246810")).c_str());
}

static void test_different_locks_give_different_ids_for_the_same_code() {
    TEST_ASSERT_EQUAL_STRING("63a43652436b", hex(idOf(kOtherLockKey, "1234")).c_str());
    TEST_ASSERT_NOT_EQUAL(0, hex(idOf(kLockKey, "1234")).compare(hex(idOf(kOtherLockKey, "1234"))));
}

static void test_different_codes_give_different_ids_on_one_lock() {
    TEST_ASSERT_NOT_EQUAL(0, hex(idOf(kLockKey, "1234")).compare(hex(idOf(kLockKey, "4321"))));
    TEST_ASSERT_NOT_EQUAL(0, hex(idOf(kLockKey, "1234")).compare(hex(idOf(kLockKey, "12345"))));
}

static void test_without_the_lock_key_a_search_of_every_code_finds_nothing() {
    const PasscodeId target = idOf(kLockKey, "1234");
    const std::string wanted = hex(target);
    unsigned withoutKey = 0;
    unsigned withKey = 0;
    std::string found;
    for (unsigned value = 0; value < 10000; ++value) {
        const std::string code = fourDigits(value);
        withoutKey += hex(idOf(kDefaultKey, code)) == wanted ? 1 : 0;
        if (hex(idOf(kLockKey, code)) == wanted) {
            ++withKey;
            found = code;
        }
    }
    TEST_ASSERT_EQUAL_UINT(0, withoutKey);
    TEST_ASSERT_EQUAL_UINT(1, withKey);
    TEST_ASSERT_EQUAL_STRING("1234", found.c_str());
    TEST_ASSERT_TRUE(wanted.find("31323334") == std::string::npos);
}

static void test_failures_and_bad_input_give_no_id() {
    PasscodeId id{0xAB, 0xAB, 0xAB, 0xAB, 0xAB, 0xAB};
    TEST_ASSERT_FALSE(latchkey_util::passcodeId(kLockKey, "1234", failingHmac, id));
    TEST_ASSERT_FALSE(latchkey_util::passcodeId(kLockKey, "1234", nullptr, id));
    s_hmacCalls = 0;
    TEST_ASSERT_FALSE(latchkey_util::passcodeId(kLockKey, "", referenceHmac, id));
    TEST_ASSERT_EQUAL_UINT(0, s_hmacCalls);
    TEST_ASSERT_EQUAL_STRING("abababababab", hex(id).c_str());
}

int main() {
    UNITY_BEGIN();
    RUN_TEST(test_the_id_is_six_bytes_of_a_labelled_hmac_under_the_lock_key);
    RUN_TEST(test_the_same_lock_record_gives_the_same_id_on_any_board);
    RUN_TEST(test_different_locks_give_different_ids_for_the_same_code);
    RUN_TEST(test_different_codes_give_different_ids_on_one_lock);
    RUN_TEST(test_without_the_lock_key_a_search_of_every_code_finds_nothing);
    RUN_TEST(test_failures_and_bad_input_give_no_id);
    return UNITY_END();
}
