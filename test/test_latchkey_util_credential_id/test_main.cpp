// SPDX-License-Identifier: GPL-3.0-or-later
#include <unity.h>

#include <cstdint>
#include <string>

#include "latchkey_util/credential_id.h"
#include "latchkey_util/passcode_type.h"
#include "ttlock/types.h"

using ttlock::PasscodeType;

void setUp() {}

void tearDown() {}

static void test_credential_ids_are_plain_decimal_text() {
    uint64_t id = 0;
    TEST_ASSERT_TRUE(latchkey_util::parseCredentialId("0", latchkey_util::kMaxFingerprintId, id));
    TEST_ASSERT_EQUAL_UINT64(0, id);
    TEST_ASSERT_TRUE(latchkey_util::parseCredentialId("3141592653", latchkey_util::kMaxCardNumber, id));
    TEST_ASSERT_EQUAL_UINT64(3141592653ULL, id);
    TEST_ASSERT_TRUE(latchkey_util::parseCredentialId("281474976710655", latchkey_util::kMaxFingerprintId, id));
    TEST_ASSERT_EQUAL_UINT64(281474976710655ULL, id);
    TEST_ASSERT_TRUE(latchkey_util::parseCredentialId("18446744073709551615", latchkey_util::kMaxCardNumber, id));
    TEST_ASSERT_EQUAL_UINT64(18446744073709551615ULL, id);
    TEST_ASSERT_EQUAL_STRING("18446744073709551615", latchkey_util::formatCredentialId(18446744073709551615ULL).c_str());
    TEST_ASSERT_EQUAL_STRING("0", latchkey_util::formatCredentialId(0).c_str());
}

static void test_other_id_text_and_ids_out_of_range_are_refused() {
    const char* refused[] = {"", "01", "-1", "+1", " 1", "1 ", "1.0", "1e3", "0x10", "abc", "18446744073709551616"};
    for (const char* text : refused) {
        uint64_t id = 42;
        TEST_ASSERT_FALSE_MESSAGE(latchkey_util::parseCredentialId(text, latchkey_util::kMaxCardNumber, id), text);
        TEST_ASSERT_EQUAL_UINT64(42, id);
    }
    uint64_t id = 42;
    TEST_ASSERT_FALSE(latchkey_util::parseCredentialId("281474976710656", latchkey_util::kMaxFingerprintId, id));
    TEST_ASSERT_EQUAL_UINT64(42, id);
}

static void test_passcode_types_have_the_names_the_api_uses() {
    TEST_ASSERT_EQUAL_STRING("permanent", latchkey_util::passcodeTypeName(PasscodeType::Permanent));
    TEST_ASSERT_EQUAL_STRING("one_time", latchkey_util::passcodeTypeName(PasscodeType::Count));
    TEST_ASSERT_EQUAL_STRING("timed", latchkey_util::passcodeTypeName(PasscodeType::Period));
    TEST_ASSERT_EQUAL_STRING("cyclic", latchkey_util::passcodeTypeName(PasscodeType::Cyclic));
    TEST_ASSERT_EQUAL_STRING("unknown", latchkey_util::passcodeTypeName(static_cast<PasscodeType>(9)));
    const struct {
        const char* name;
        PasscodeType type;
    } known[] = {{"permanent", PasscodeType::Permanent},
                 {"one_time", PasscodeType::Count},
                 {"timed", PasscodeType::Period},
                 {"cyclic", PasscodeType::Cyclic}};
    for (const auto& entry : known) {
        PasscodeType type = PasscodeType::Permanent;
        TEST_ASSERT_TRUE(latchkey_util::passcodeTypeOf(entry.name, type));
        TEST_ASSERT_EQUAL_UINT8(static_cast<uint8_t>(entry.type), static_cast<uint8_t>(type));
    }
    for (const char* name : {"", "Permanent", "one-time", "count", "period", "unknown"}) {
        PasscodeType type = PasscodeType::Cyclic;
        TEST_ASSERT_FALSE_MESSAGE(latchkey_util::passcodeTypeOf(name, type), name);
        TEST_ASSERT_EQUAL_UINT8(static_cast<uint8_t>(PasscodeType::Cyclic), static_cast<uint8_t>(type));
    }
}

int main(int, char**) {
    UNITY_BEGIN();
    RUN_TEST(test_credential_ids_are_plain_decimal_text);
    RUN_TEST(test_other_id_text_and_ids_out_of_range_are_refused);
    RUN_TEST(test_passcode_types_have_the_names_the_api_uses);
    return UNITY_END();
}
