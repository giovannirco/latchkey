// SPDX-License-Identifier: GPL-3.0-or-later
#include <unity.h>

#include <cstdint>
#include <initializer_list>
#include <optional>
#include <string>

#include "latchkey_util/access_json.h"
#include "latchkey_util/feature_gate.h"
#include "latchkey_util/weekly_window.h"
#include "ttlock/features.h"

using latchkey_util::CredentialView;
using latchkey_util::PasscodeView;
using latchkey_util::UtcWindow;
using latchkey_util::WeeklyWindow;
using ttlock::Feature;

void setUp() {}

void tearDown() {}

static std::string passcode(const PasscodeView& view) {
    std::string out;
    latchkey_util::appendPasscodeJson(out, view);
    return out;
}

static std::string credential(const CredentialView& view) {
    std::string out;
    latchkey_util::appendCredentialJson(out, view);
    return out;
}

static void test_strings_are_escaped_for_json() {
    std::string out;
    latchkey_util::appendJsonString(out, "Front \"door\" \\ caf\xc3\xa9");
    TEST_ASSERT_EQUAL_STRING("\"Front \\\"door\\\" \\\\ caf\xc3\xa9\"", out.c_str());
    out.clear();
    latchkey_util::appendJsonString(out, std::string("a\x01\x1f\nb", 5));
    TEST_ASSERT_EQUAL_STRING("\"a\\u0001\\u001f\\nb\"", out.c_str());
}

static void test_a_passcode_renders_with_its_window_or_null() {
    PasscodeView timed;
    timed.id = "01235252d4d1";
    timed.type = "timed";
    timed.name = "Cleaner";
    timed.window = UtcWindow{1794156000, 1794163200};
    timed.managed = true;
    TEST_ASSERT_EQUAL_STRING(
        "{\"id\":\"01235252d4d1\",\"type\":\"timed\",\"name\":\"Cleaner\",\"validity\":{\"start\":1794156000,\"end\":"
        "1794163200},\"managed\":true}",
        passcode(timed).c_str());
    PasscodeView permanent;
    permanent.id = "13ec081e65d7";
    permanent.type = "permanent";
    permanent.code = "482913";
    TEST_ASSERT_EQUAL_STRING(
        "{\"id\":\"13ec081e65d7\",\"type\":\"permanent\",\"name\":\"\",\"validity\":null,\"managed\":false,"
        "\"code\":\"482913\"}",
        passcode(permanent).c_str());
}

static void test_a_credential_renders_its_decimal_id_and_weekly_window() {
    CredentialView card;
    card.id = 18446744073709551615ULL;
    card.name = "Spare";
    card.cycle = WeeklyWindow{0x1F, 480, 1110};
    TEST_ASSERT_EQUAL_STRING(
        "{\"id\":\"18446744073709551615\",\"name\":\"Spare\",\"validity\":null,\"cycle\":{\"days\":[1,2,3,4,5],"
        "\"start\":\"08:00\",\"end\":\"18:30\"}}",
        credential(card).c_str());
    CredentialView finger;
    finger.id = 1;
    finger.window = UtcWindow{0, 4102444740};
    TEST_ASSERT_EQUAL_STRING("{\"id\":\"1\",\"name\":\"\",\"validity\":{\"start\":0,\"end\":4102444740}}",
                             credential(finger).c_str());
}

static void test_the_bounds_cover_the_largest_entries() {
    const std::string quotes(48, '"');
    PasscodeView worst;
    worst.id = "ffffffffffff";
    worst.type = "one_time";
    worst.name = quotes;
    worst.window = UtcWindow{4102444740, 4102444740};
    worst.managed = true;
    TEST_ASSERT_TRUE(passcode(worst).size() + 1 <= latchkey_util::passcodeJsonBound(quotes.size()));
    CredentialView card;
    card.id = 18446744073709551615ULL;
    card.name = quotes;
    card.window = UtcWindow{4102444740, 4102444740};
    card.cycle = WeeklyWindow{0x7F, 0, 1440};
    TEST_ASSERT_TRUE(credential(card).size() + 1 <= latchkey_util::credentialJsonBound(quotes.size()));
}

static void test_a_list_fits_only_with_room_for_its_copies() {
    TEST_ASSERT_TRUE(latchkey_util::listFitsInHeap(10000, 60000, 20000));
    TEST_ASSERT_FALSE(latchkey_util::listFitsInHeap(10000, 40000, 20000));
    TEST_ASSERT_FALSE(latchkey_util::listFitsInHeap(10000, 60000, 9000));
    TEST_ASSERT_TRUE(latchkey_util::listFitsInHeap(0, latchkey_util::kListHeadroomBytes, 1));
}

static void test_the_first_feature_the_lock_does_not_report_is_named() {
    const uint64_t mask = ttlock::featureBit(Feature::Passcode) | ttlock::featureBit(Feature::FingerPrint);
    TEST_ASSERT_FALSE(latchkey_util::firstMissingFeature(mask, {Feature::Passcode}).has_value());
    const std::optional<Feature> missing =
        latchkey_util::firstMissingFeature(mask, {Feature::FingerPrint, Feature::CyclicIcOrFingerPrint});
    TEST_ASSERT_TRUE(missing.has_value());
    TEST_ASSERT_EQUAL_UINT8(static_cast<uint8_t>(Feature::CyclicIcOrFingerPrint), static_cast<uint8_t>(*missing));
    TEST_ASSERT_EQUAL_STRING("the lock does not report cyclic_ic_or_finger_print",
                             latchkey_util::missingFeatureMessage(*missing).c_str());
    TEST_ASSERT_EQUAL_UINT8(static_cast<uint8_t>(Feature::Ic),
                            static_cast<uint8_t>(*latchkey_util::firstMissingFeature(0, {Feature::Ic})));
}

static void test_list_preflight_reserves_response_envelope_space() {
    TEST_ASSERT_TRUE(latchkey_util::listFitsInHeap(20000, 1000000, 1000000));
    TEST_ASSERT_TRUE(latchkey_util::listFitsInHeap(32768 - 256, 1000000, 1000000));
    TEST_ASSERT_FALSE(latchkey_util::listFitsInHeap(32768 - 255, 1000000, 1000000));
    TEST_ASSERT_FALSE(latchkey_util::listFitsInHeap(SIZE_MAX, SIZE_MAX, SIZE_MAX));
}

int main(int, char**) {
    UNITY_BEGIN();
    RUN_TEST(test_strings_are_escaped_for_json);
    RUN_TEST(test_a_passcode_renders_with_its_window_or_null);
    RUN_TEST(test_a_credential_renders_its_decimal_id_and_weekly_window);
    RUN_TEST(test_the_bounds_cover_the_largest_entries);
    RUN_TEST(test_a_list_fits_only_with_room_for_its_copies);
    RUN_TEST(test_the_first_feature_the_lock_does_not_report_is_named);
    RUN_TEST(test_list_preflight_reserves_response_envelope_space);
    return UNITY_END();
}
