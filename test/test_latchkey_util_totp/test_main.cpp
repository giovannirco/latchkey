// SPDX-License-Identifier: GPL-3.0-or-later
#include <unity.h>

#include <cstdint>
#include <cstring>

#include "latchkey_util/totp.h"
#include "reference_hmac_sha1.h"

using latchkey_util::TotpVerdict;

void setUp() {}

void tearDown() {}

static const uint8_t kRfc6238Secret[] = {'1', '2', '3', '4', '5', '6', '7', '8', '9', '0',
                                         '1', '2', '3', '4', '5', '6', '7', '8', '9', '0'};

static unsigned s_hmacCalls = 0;

static bool countingHmac(const uint8_t* key, size_t keyLength, const uint8_t* message, size_t messageLength,
                         uint8_t (&digest)[latchkey_util::kHmacSha1Size]) {
    ++s_hmacCalls;
    return reference::hmacSha1(key, keyLength, message, messageLength, digest);
}

static bool failingHmac(const uint8_t*, size_t, const uint8_t*, size_t, uint8_t (&)[latchkey_util::kHmacSha1Size]) {
    return false;
}

static void assertDigest(const char* expectedHex, const uint8_t (&digest)[20]) {
    char hex[41];
    for (size_t i = 0; i < 20; ++i) {
        static const char kDigits[] = "0123456789abcdef";
        hex[i * 2] = kDigits[digest[i] >> 4];
        hex[i * 2 + 1] = kDigits[digest[i] & 0x0F];
    }
    hex[40] = '\0';
    TEST_ASSERT_EQUAL_STRING(expectedHex, hex);
}

static uint32_t codeAt(int64_t unixSeconds) {
    uint32_t code = 0;
    TEST_ASSERT_TRUE(latchkey_util::totpCode(kRfc6238Secret, sizeof(kRfc6238Secret),
                                             latchkey_util::totpStep(unixSeconds), countingHmac, code));
    return code;
}

static TotpVerdict verify(int64_t now, uint32_t code, uint64_t lastStep, uint64_t& accepted) {
    return latchkey_util::totpVerify(kRfc6238Secret, sizeof(kRfc6238Secret), now, code, lastStep, countingHmac,
                                     accepted);
}

static void test_reference_sha1_matches_fips_180() {
    uint8_t digest[20];
    reference::sha1(reinterpret_cast<const uint8_t*>("abc"), 3, digest);
    assertDigest("a9993e364706816aba3e25717850c26c9cd0d89d", digest);
}

static void test_reference_hmac_matches_rfc_2202() {
    uint8_t key[20];
    std::memset(key, 0x0B, sizeof(key));
    uint8_t digest[20];
    reference::hmacSha1(key, sizeof(key), reinterpret_cast<const uint8_t*>("Hi There"), 8, digest);
    assertDigest("b617318655057264e28bc0b6fb378c8ef146be00", digest);
    uint8_t longKey[80];
    std::memset(longKey, 0xAA, sizeof(longKey));
    const char* data = "Test Using Larger Than Block-Size Key - Hash Key First";
    reference::hmacSha1(longKey, sizeof(longKey), reinterpret_cast<const uint8_t*>(data), std::strlen(data), digest);
    assertDigest("aa4ae5e15272d00e95705637ce8a3b55ed402112", digest);
}

static void test_steps_are_30_second_counters() {
    TEST_ASSERT_EQUAL_UINT64(0, latchkey_util::totpStep(0));
    TEST_ASSERT_EQUAL_UINT64(0, latchkey_util::totpStep(29));
    TEST_ASSERT_EQUAL_UINT64(1, latchkey_util::totpStep(30));
    TEST_ASSERT_EQUAL_UINT64(1, latchkey_util::totpStep(59));
    TEST_ASSERT_EQUAL_UINT64(0x23523EC, latchkey_util::totpStep(1111111109));
    TEST_ASSERT_EQUAL_UINT64(0x27BC86AA, latchkey_util::totpStep(20000000000LL));
    TEST_ASSERT_EQUAL_UINT64(0, latchkey_util::totpStep(-1));
}

static void test_rfc_6238_sha1_vectors_truncated_to_six_digits() {
    TEST_ASSERT_EQUAL_UINT32(287082, codeAt(59));
    TEST_ASSERT_EQUAL_UINT32(81804, codeAt(1111111109));
    TEST_ASSERT_EQUAL_UINT32(50471, codeAt(1111111111));
    TEST_ASSERT_EQUAL_UINT32(5924, codeAt(1234567890));
    TEST_ASSERT_EQUAL_UINT32(279037, codeAt(2000000000));
    TEST_ASSERT_EQUAL_UINT32(353130, codeAt(20000000000LL));
}

static void test_the_current_step_is_accepted_and_reported() {
    uint64_t accepted = 0;
    TEST_ASSERT_EQUAL(TotpVerdict::Accepted, verify(1111111111, 50471, 0, accepted));
    TEST_ASSERT_EQUAL_UINT64(0x23523ED, accepted);
}

static void test_one_step_of_drift_either_way_is_accepted() {
    uint64_t accepted = 0;
    TEST_ASSERT_EQUAL(TotpVerdict::Accepted, verify(1111111111, 81804, 0, accepted));
    TEST_ASSERT_EQUAL_UINT64(0x23523EC, accepted);
    const uint32_t next = codeAt(1111111111 + 30);
    TEST_ASSERT_EQUAL(TotpVerdict::Accepted, verify(1111111111, next, 0, accepted));
    TEST_ASSERT_EQUAL_UINT64(0x23523EE, accepted);
}

static void test_two_steps_away_is_rejected() {
    uint64_t accepted = 7;
    TEST_ASSERT_EQUAL(TotpVerdict::Rejected, verify(1111111111, codeAt(1111111111 - 60), 0, accepted));
    TEST_ASSERT_EQUAL(TotpVerdict::Rejected, verify(1111111111, codeAt(1111111111 + 60), 0, accepted));
    TEST_ASSERT_EQUAL_UINT64(7, accepted);
}

static void test_a_wrong_code_is_rejected() {
    uint64_t accepted = 0;
    TEST_ASSERT_EQUAL(TotpVerdict::Rejected, verify(1111111111, 50472, 0, accepted));
    TEST_ASSERT_EQUAL(TotpVerdict::Rejected, verify(1111111111, 1000000 + 50471, 0, accepted));
}

static void test_a_step_already_accepted_is_refused() {
    uint64_t accepted = 0;
    TEST_ASSERT_EQUAL(TotpVerdict::Accepted, verify(1111111111, 50471, 0, accepted));
    const uint64_t last = accepted;
    TEST_ASSERT_EQUAL(TotpVerdict::Rejected, verify(1111111111, 50471, last, accepted));
    TEST_ASSERT_EQUAL(TotpVerdict::Rejected, verify(1111111111 + 25, 50471, last, accepted));
}

static void test_an_earlier_step_is_refused_after_a_later_one() {
    uint64_t accepted = 0;
    const uint32_t next = codeAt(1111111111 + 30);
    TEST_ASSERT_EQUAL(TotpVerdict::Accepted, verify(1111111111, next, 0, accepted));
    const uint64_t last = accepted;
    TEST_ASSERT_EQUAL(TotpVerdict::Rejected, verify(1111111111, 50471, last, accepted));
    TEST_ASSERT_EQUAL(TotpVerdict::Rejected, verify(1111111111, 81804, last, accepted));
}

static void test_a_later_step_is_accepted_after_an_earlier_one() {
    uint64_t accepted = 0;
    TEST_ASSERT_EQUAL(TotpVerdict::Accepted, verify(1111111111, 81804, 0, accepted));
    const uint64_t last = accepted;
    TEST_ASSERT_EQUAL(TotpVerdict::Accepted, verify(1111111111, 50471, last, accepted));
    TEST_ASSERT_EQUAL_UINT64(last + 1, accepted);
}

static void test_every_step_of_the_window_is_computed() {
    uint64_t accepted = 0;
    s_hmacCalls = 0;
    verify(1111111111, 81804, 0, accepted);
    TEST_ASSERT_EQUAL_UINT(3, s_hmacCalls);
    s_hmacCalls = 0;
    verify(1111111111, 999999, 0, accepted);
    TEST_ASSERT_EQUAL_UINT(3, s_hmacCalls);
}

static void test_the_window_starts_at_step_zero() {
    uint64_t accepted = 9;
    uint32_t code = 0;
    TEST_ASSERT_TRUE(latchkey_util::totpCode(kRfc6238Secret, sizeof(kRfc6238Secret), 0, countingHmac, code));
    TEST_ASSERT_EQUAL(TotpVerdict::Rejected, verify(10, code, 0, accepted));
    TEST_ASSERT_EQUAL(TotpVerdict::Accepted, verify(59, 287082, 0, accepted));
    TEST_ASSERT_EQUAL_UINT64(1, accepted);
}

static void test_an_hmac_failure_is_reported() {
    uint64_t accepted = 5;
    uint32_t code = 0;
    TEST_ASSERT_FALSE(latchkey_util::totpCode(kRfc6238Secret, sizeof(kRfc6238Secret), 1, failingHmac, code));
    TEST_ASSERT_EQUAL(TotpVerdict::HmacFailed, latchkey_util::totpVerify(kRfc6238Secret, sizeof(kRfc6238Secret),
                                                                         59, 287082, 0, failingHmac, accepted));
    TEST_ASSERT_EQUAL_UINT64(5, accepted);
}

static void test_codes_parse_as_exactly_six_digits() {
    uint32_t code = 0;
    TEST_ASSERT_TRUE(latchkey_util::parseTotpCode("287082", code));
    TEST_ASSERT_EQUAL_UINT32(287082, code);
    TEST_ASSERT_TRUE(latchkey_util::parseTotpCode("005924", code));
    TEST_ASSERT_EQUAL_UINT32(5924, code);
    TEST_ASSERT_TRUE(latchkey_util::parseTotpCode("000000", code));
    TEST_ASSERT_EQUAL_UINT32(0, code);
    TEST_ASSERT_FALSE(latchkey_util::parseTotpCode("", code));
    TEST_ASSERT_FALSE(latchkey_util::parseTotpCode("28708", code));
    TEST_ASSERT_FALSE(latchkey_util::parseTotpCode("2870821", code));
    TEST_ASSERT_FALSE(latchkey_util::parseTotpCode("28708a", code));
    TEST_ASSERT_FALSE(latchkey_util::parseTotpCode(" 87082", code));
    TEST_ASSERT_FALSE(latchkey_util::parseTotpCode("+87082", code));
    TEST_ASSERT_FALSE(latchkey_util::parseTotpCode("-87082", code));
}

int main() {
    UNITY_BEGIN();
    RUN_TEST(test_reference_sha1_matches_fips_180);
    RUN_TEST(test_reference_hmac_matches_rfc_2202);
    RUN_TEST(test_steps_are_30_second_counters);
    RUN_TEST(test_rfc_6238_sha1_vectors_truncated_to_six_digits);
    RUN_TEST(test_the_current_step_is_accepted_and_reported);
    RUN_TEST(test_one_step_of_drift_either_way_is_accepted);
    RUN_TEST(test_two_steps_away_is_rejected);
    RUN_TEST(test_a_wrong_code_is_rejected);
    RUN_TEST(test_a_step_already_accepted_is_refused);
    RUN_TEST(test_an_earlier_step_is_refused_after_a_later_one);
    RUN_TEST(test_a_later_step_is_accepted_after_an_earlier_one);
    RUN_TEST(test_every_step_of_the_window_is_computed);
    RUN_TEST(test_the_window_starts_at_step_zero);
    RUN_TEST(test_an_hmac_failure_is_reported);
    RUN_TEST(test_codes_parse_as_exactly_six_digits);
    return UNITY_END();
}
