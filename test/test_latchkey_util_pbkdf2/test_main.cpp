// SPDX-License-Identifier: GPL-3.0-or-later
#include <unity.h>

#include <cstddef>
#include <cstdint>
#include <cstring>
#include <string>
#include <vector>

#include "../reference/allocation_failure.h"
#include "../reference/hmac_sha256.h"
#include "latchkey_util/hmac_sha256.h"
#include "latchkey_util/pbkdf2.h"

void setUp() { allocation_failure::reset(); }

void tearDown() { allocation_failure::resume(); }

static std::string hex(const uint8_t* data, size_t length) {
    static const char kDigits[] = "0123456789abcdef";
    std::string text;
    for (size_t i = 0; i < length; ++i) {
        text.push_back(kDigits[data[i] >> 4]);
        text.push_back(kDigits[data[i] & 0x0F]);
    }
    return text;
}

static const uint8_t* bytesOf(const char* text) { return reinterpret_cast<const uint8_t*>(text); }

struct Counter {
    size_t hmacCalls = 0;
    std::vector<size_t> yieldsAt;
    size_t failAt = 0;
};

static latchkey_util::KeyedHmacSha256 hmacUnder(const std::string& password, Counter& counter) {
    return [password, &counter](const uint8_t* message, size_t length,
                                uint8_t (&digest)[latchkey_util::kHmacSha256Size]) {
        ++counter.hmacCalls;
        if (counter.failAt != 0 && counter.hmacCalls == counter.failAt) {
            return false;
        }
        return reference::hmacSha256(bytesOf(password.c_str()), password.size(), message, length, digest);
    };
}

static latchkey_util::Pbkdf2Yield yieldInto(Counter& counter) {
    return [&counter]() { counter.yieldsAt.push_back(counter.hmacCalls); };
}

static std::string derive(const char* password, const char* salt, uint32_t iterations, size_t length,
                          uint32_t yieldEvery, Counter& counter) {
    std::vector<uint8_t> out(length, 0xEE);
    TEST_ASSERT_TRUE(latchkey_util::pbkdf2HmacSha256(hmacUnder(password, counter), bytesOf(salt), std::strlen(salt),
                                                     iterations, yieldEvery, yieldInto(counter), out.data(),
                                                     out.size()));
    return hex(out.data(), out.size());
}

static const char kRfc7914One[] =
    "55ac046e56e3089fec1691c22544b605f94185216dde0465e68b9d57c20dacbc"
    "49ca9cccf179b645991664b39d77ef317c71b845b1e30bd509112041d3a19783";
static const char kRfc7914Two[] =
    "4ddcd8f60b98be21830cee5ef22701f9641a4418d04c0414aeff08876b34ab56"
    "a1d425a1225833549adb841b51c9b3176a272bdebba1d078478f62b397f33c8d";

static void test_reference_sha256_matches_fips_180_4() {
    uint8_t digest[32];
    reference::sha256(bytesOf("abc"), 3, digest);
    TEST_ASSERT_EQUAL_STRING("ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad", hex(digest, 32).c_str());
    reference::sha256(nullptr, 0, digest);
    TEST_ASSERT_EQUAL_STRING("e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855", hex(digest, 32).c_str());
    const char* twoBlocks = "abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq";
    reference::sha256(bytesOf(twoBlocks), std::strlen(twoBlocks), digest);
    TEST_ASSERT_EQUAL_STRING("248d6a61d20638b8e5c026930c3e6039a33ce45964ff2167f6ecedd419db06c1", hex(digest, 32).c_str());
}

static void test_reference_hmac_matches_rfc_4231() {
    uint8_t digest[32];
    uint8_t key[131];
    std::memset(key, 0x0B, 20);
    reference::hmacSha256(key, 20, bytesOf("Hi There"), 8, digest);
    TEST_ASSERT_EQUAL_STRING("b0344c61d8db38535ca8afceaf0bf12b881dc200c9833da726e9376c2e32cff7", hex(digest, 32).c_str());
    const char* question = "what do ya want for nothing?";
    reference::hmacSha256(bytesOf("Jefe"), 4, bytesOf(question), std::strlen(question), digest);
    TEST_ASSERT_EQUAL_STRING("5bdcc146bf60754e6a042426089575c75a003f089d2739839dec58b964ec3843", hex(digest, 32).c_str());
    std::memset(key, 0xAA, sizeof(key));
    const char* longKey = "Test Using Larger Than Block-Size Key - Hash Key First";
    reference::hmacSha256(key, sizeof(key), bytesOf(longKey), std::strlen(longKey), digest);
    TEST_ASSERT_EQUAL_STRING("60e431591ee0b67f0d8a26aacbf5b77f8e0bc6213728c5140546040f0ee37f54", hex(digest, 32).c_str());
}

static void test_rfc_7914_section_11_one_iteration() {
    Counter counter;
    TEST_ASSERT_EQUAL_STRING(kRfc7914One, derive("passwd", "salt", 1, 64, 1000, counter).c_str());
    TEST_ASSERT_EQUAL_UINT(2, counter.hmacCalls);
    TEST_ASSERT_EQUAL_UINT(0, counter.yieldsAt.size());
}

static void test_rfc_7914_section_11_80000_iterations_yield_160_times() {
    Counter counter;
    TEST_ASSERT_EQUAL_STRING(kRfc7914Two, derive("Password", "NaCl", 80000, 64, 1000, counter).c_str());
    TEST_ASSERT_EQUAL_UINT(160000, counter.hmacCalls);
    TEST_ASSERT_EQUAL_UINT(160, counter.yieldsAt.size());
    TEST_ASSERT_EQUAL_UINT(1000, counter.yieldsAt.front());
    TEST_ASSERT_EQUAL_UINT(160000, counter.yieldsAt.back());
}

static void test_yield_fires_after_every_nth_hmac_call() {
    Counter counter;
    TEST_ASSERT_EQUAL_STRING("2e540f133e81a760340ff38424be206e0d793cd9fa5412bfdb529e7e84fbccae",
                             derive("Password", "NaCl", 2500, 32, 1000, counter).c_str());
    TEST_ASSERT_EQUAL_UINT(2500, counter.hmacCalls);
    TEST_ASSERT_EQUAL_UINT(2, counter.yieldsAt.size());
    TEST_ASSERT_EQUAL_UINT(1000, counter.yieldsAt[0]);
    TEST_ASSERT_EQUAL_UINT(2000, counter.yieldsAt[1]);

    Counter everyCall;
    derive("passwd", "salt", 3, 32, 1, everyCall);
    TEST_ASSERT_EQUAL_UINT(3, everyCall.yieldsAt.size());
    TEST_ASSERT_EQUAL_UINT(3, everyCall.yieldsAt.back());
}

static void test_output_lengths_off_the_block_size_take_the_stream_prefix() {
    Counter counter;
    const std::string prefix20 = derive("passwd", "salt", 1, 20, 1000, counter);
    TEST_ASSERT_EQUAL_STRING(std::string(kRfc7914One, 40).c_str(), prefix20.c_str());
    const std::string prefix33 = derive("passwd", "salt", 1, 33, 1000, counter);
    TEST_ASSERT_EQUAL_STRING(std::string(kRfc7914One, 66).c_str(), prefix33.c_str());
}

static void test_a_failing_hmac_stops_and_wipes_the_output() {
    Counter counter;
    counter.failAt = 3;
    std::vector<uint8_t> out(64, 0xEE);
    TEST_ASSERT_FALSE(latchkey_util::pbkdf2HmacSha256(hmacUnder("Password", counter), bytesOf("NaCl"), 4, 2, 1000,
                                                      yieldInto(counter), out.data(), out.size()));
    TEST_ASSERT_EQUAL_UINT(3, counter.hmacCalls);
    for (uint8_t byte : out) {
        TEST_ASSERT_EQUAL_HEX8(0x00, byte);
    }
}

static void test_bad_parameters_are_refused_before_any_hmac() {
    Counter counter;
    uint8_t out[32] = {};
    const auto hmac = hmacUnder("pw", counter);
    const auto yield = yieldInto(counter);
    const uint8_t* salt = bytesOf("salt");
    TEST_ASSERT_FALSE(latchkey_util::pbkdf2HmacSha256(hmac, salt, 4, 0, 1000, yield, out, sizeof(out)));
    TEST_ASSERT_FALSE(latchkey_util::pbkdf2HmacSha256(hmac, salt, 4, 1, 0, yield, out, sizeof(out)));
    TEST_ASSERT_FALSE(latchkey_util::pbkdf2HmacSha256(hmac, salt, 4, 1, 1000, yield, out, 0));
    TEST_ASSERT_FALSE(latchkey_util::pbkdf2HmacSha256(hmac, salt, 4, 1, 1000, yield, nullptr, sizeof(out)));
    TEST_ASSERT_FALSE(latchkey_util::pbkdf2HmacSha256(hmac, nullptr, 4, 1, 1000, yield, out, sizeof(out)));
    TEST_ASSERT_FALSE(latchkey_util::pbkdf2HmacSha256(nullptr, salt, 4, 1, 1000, yield, out, sizeof(out)));
    TEST_ASSERT_FALSE(latchkey_util::pbkdf2HmacSha256(hmac, salt, 4, 1, 1000, nullptr, out, sizeof(out)));
    TEST_ASSERT_EQUAL_UINT(0, counter.hmacCalls);
    TEST_ASSERT_EQUAL_UINT(0, counter.yieldsAt.size());
}

static void test_scratch_allocation_failure_wipes_output_before_any_hmac() {
    Counter counter;
    uint8_t out[32];
    std::memset(out, 0xEE, sizeof(out));
    const auto hmac = hmacUnder("Password", counter);
    const auto yield = yieldInto(counter);
    const size_t before = allocation_failure::live();
    allocation_failure::failNext();
    const bool derived = latchkey_util::pbkdf2HmacSha256(hmac, bytesOf("salt"), 4, 2, 1000, yield, out, sizeof(out));
    allocation_failure::resume();
    TEST_ASSERT_FALSE(derived);
    TEST_ASSERT_EQUAL_UINT(1, allocation_failure::attempts);
    TEST_ASSERT_EQUAL_UINT(before, allocation_failure::live());
    TEST_ASSERT_EQUAL_UINT(0, counter.hmacCalls);
    for (uint8_t byte : out) TEST_ASSERT_EQUAL_UINT8(0, byte);
}

static void test_salt_size_overflow_is_rejected_without_allocation_or_hmac() {
    Counter counter;
    uint8_t out[32];
    std::memset(out, 0xEE, sizeof(out));
    TEST_ASSERT_FALSE(latchkey_util::pbkdf2HmacSha256(hmacUnder("Password", counter), bytesOf("salt"), SIZE_MAX,
                                                     2, 1000, yieldInto(counter), out, sizeof(out)));
    TEST_ASSERT_EQUAL_UINT(0, allocation_failure::attempts);
    TEST_ASSERT_EQUAL_UINT(0, counter.hmacCalls);
    for (uint8_t byte : out) TEST_ASSERT_EQUAL_UINT8(0, byte);
}

int main() {
    UNITY_BEGIN();
    RUN_TEST(test_reference_sha256_matches_fips_180_4);
    RUN_TEST(test_reference_hmac_matches_rfc_4231);
    RUN_TEST(test_rfc_7914_section_11_one_iteration);
    RUN_TEST(test_rfc_7914_section_11_80000_iterations_yield_160_times);
    RUN_TEST(test_yield_fires_after_every_nth_hmac_call);
    RUN_TEST(test_output_lengths_off_the_block_size_take_the_stream_prefix);
    RUN_TEST(test_a_failing_hmac_stops_and_wipes_the_output);
    RUN_TEST(test_bad_parameters_are_refused_before_any_hmac);
    RUN_TEST(test_scratch_allocation_failure_wipes_output_before_any_hmac);
    RUN_TEST(test_salt_size_overflow_is_rejected_without_allocation_or_hmac);
    return UNITY_END();
}
