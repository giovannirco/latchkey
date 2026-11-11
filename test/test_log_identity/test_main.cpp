// SPDX-License-Identifier: GPL-3.0-or-later
#include <unity.h>

#include "../reference/hmac_sha256.h"
#include "latchkey_util/lock_log.h"
#include "latchkey_util/passcode_id.h"

void setUp() {}
void tearDown() {}

static constexpr latchkey_util::LockAesKey kKey{0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15};

static ttlock::LogEntry entry(uint8_t type, std::string credential = {}) {
    ttlock::LogEntry value;
    value.recordNumber = 42;
    value.type = type;
    value.time = {2026, 1, 1, 12, 0, 0};
    value.battery = 74;
    value.credential = std::move(credential);
    return value;
}

static std::string render(const ttlock::LogEntry& value, const latchkey_util::LogLabels& labels = {}) {
    std::string out;
    TEST_ASSERT_TRUE(latchkey_util::logEntryJson(value, 0, labels, kKey, reference::hmacSha256, out));
    return out;
}

static void contains(const std::string& text, std::string_view expected) {
    TEST_ASSERT_TRUE(text.find(expected) != std::string::npos);
}

static void test_fingerprint_and_card_events_include_safe_ids_and_current_labels() {
    latchkey_util::LogLabels labels;
    labels.fingerprints.put({17, false, "Entry finger", {}});
    labels.cards.put({17, false, "Visitor card", {}});
    for (uint8_t type : {20, 21, 22, 23, 33, 40}) {
        const auto text = render(entry(type, "17"), labels);
        contains(text, R"("credential":{"kind":"fingerprint","id":"17","name":"Entry finger","nameSource":"current_label"})");
    }
    for (uint8_t type : {15, 17, 18, 25, 35, 39}) {
        const auto text = render(entry(type, "17"), labels);
        contains(text, R"("credential":{"kind":"card","id":"17","name":"Visitor card","nameSource":"current_label"})");
    }
}

static void test_passcodes_match_only_complete_exact_values_and_never_leave_raw_secrets() {
    latchkey_util::LogLabels labels;
    latchkey_util::PasscodeId id;
    TEST_ASSERT_TRUE(latchkey_util::passcodeId(kKey, "001234", reference::hmacSha256, id));
    labels.passcodes.put({latchkey_util::passcodeIdNumber(id), true, "Visitor PIN", {}});
    for (uint8_t type : {4, 5, 6, 7, 9, 10, 11, 12, 13, 34, 38, 92, 93}) {
        auto value = entry(type, "001234");
        value.newCredential = "678901";
        const auto text = render(value, labels);
        contains(text, R"("name":"Visitor PIN","nameSource":"current_label")");
        contains(text, latchkey_util::formatPasscodeId(id));
        TEST_ASSERT_TRUE(text.find("001234") == std::string::npos);
        TEST_ASSERT_TRUE(text.find("678901") == std::string::npos);
    }
    for (const char* attempted : {"1234", "9001234", "123", "0012340000", "001234x", ""}) {
        const auto text = render(entry(7, attempted), labels);
        contains(text, R"("credential":{"kind":"passcode","id":null,"name":null,"nameSource":null})");
        TEST_ASSERT_TRUE(text.find("Visitor PIN") == std::string::npos);
    }
}

static void test_unknown_numeric_credentials_keep_ids_but_reject_sentinels_and_invalid_values() {
    contains(render(entry(23, "123456")), R"("id":"123456","name":null,"nameSource":null)");
    contains(render(entry(18, "18446744073709551614")), R"("id":"18446744073709551614")");
    for (const char* value : {"", "0", "01", "-1", "281474976710655", "281474976710656", "7x"}) {
        contains(render(entry(22, value)), R"("id":null,"name":null,"nameSource":null)");
    }
}

static void test_clear_and_unrelated_types_never_infer_a_credential_from_their_tail() {
    for (uint8_t type : {8, 16, 24}) {
        const auto text = render(entry(type, "123456"));
        contains(text, R"("action":"clear","outcome":"success")");
        contains(text, R"("id":null,"name":null,"nameSource":null)");
        TEST_ASSERT_TRUE(text.find("123456") == std::string::npos);
    }
    for (uint8_t type : {1, 14, 19, 55, 67, 78, 79, 80, 91, 250}) {
        const auto text = render(entry(type, "123456"));
        TEST_ASSERT_TRUE(text.find("credential") == std::string::npos);
        TEST_ASSERT_TRUE(text.find("123456") == std::string::npos);
    }
}

static void test_failed_attempts_are_explicit_and_unknown_outcomes_are_not_successes() {
    for (uint8_t type : {7, 11, 12, 13, 22, 25, 38, 39, 40, 41}) {
        contains(render(entry(type)), R"("action":"unlock","outcome":"failure")");
    }
    contains(render(entry(250)), R"("action":"unknown","outcome":"unknown")");
    contains(render(entry(93)), R"("action":"add","outcome":"success")");
    contains(render(entry(5)), R"("action":"change","outcome":"success")");
}

static bool failedHmac(const uint8_t*, size_t, const uint8_t*, size_t, uint8_t (&)[32]) { return false; }

static void test_hash_failure_does_not_publish_a_partial_result_and_names_are_escaped() {
    std::string out = "untouched";
    TEST_ASSERT_FALSE(latchkey_util::logEntryJson(entry(4, "123456"), 0, {}, kKey, failedHmac, out));
    TEST_ASSERT_EQUAL_STRING("untouched", out.c_str());
    latchkey_util::LogLabels labels;
    labels.cards.put({17, false, "Card \"A\"\n\\", {}});
    contains(render(entry(17, "17"), labels), R"("name":"Card \"A\"\n\\")");
}

static void test_app_records_keep_safe_actor_numbers_only_for_supported_record_layouts() {
    for (uint8_t type : {1, 26, 28, 41, 52, 75, 76, 77}) {
        auto value = entry(type, "untrusted tail");
        value.uid = 123;
        value.recordId = 456;
        contains(render(value), R"("uid":123,"recordId":456)");
    }
    auto value = entry(7, "123456");
    value.uid = 123;
    value.recordId = 456;
    TEST_ASSERT_TRUE(render(value).find("uid") == std::string::npos);
}

static void test_retired_labels_survive_reload_are_bounded_and_do_not_override_current_names() {
    latchkey_util::RetiredLabels retired;
    TEST_ASSERT_TRUE(retired.remember('f', 17, "Previous finger"));
    auto bytes = retired.encode();
    latchkey_util::LogLabels labels;
    TEST_ASSERT_TRUE(latchkey_util::RetiredLabels::decode(bytes.data(), bytes.size(), labels.retired));
    contains(render(entry(23, "17"), labels), R"("name":"Previous finger","nameSource":"last_known_label")");
    labels.fingerprints.put({17, false, "Current finger", {}});
    contains(render(entry(20, "17"), labels), R"("name":"Current finger","nameSource":"current_label")");
    labels.fingerprints.put({17, true, "", {}});
    contains(render(entry(20, "17"), labels), R"("name":null,"nameSource":null)");
    for (uint64_t id = 1; id <= 17; ++id) TEST_ASSERT_TRUE(retired.remember('c', id, "Card"));
    TEST_ASSERT_NULL(retired.find('f', 17));
    TEST_ASSERT_NULL(retired.find('c', 1));
    TEST_ASSERT_NOT_NULL(retired.find('c', 17));
    TEST_ASSERT_TRUE(retired.remember('c', 2, "Renamed"));
    TEST_ASSERT_TRUE(retired.remember('p', 18, "PIN"));
    TEST_ASSERT_NOT_NULL(retired.find('c', 2));
    TEST_ASSERT_NULL(retired.find('c', 3));
    TEST_ASSERT_LESS_OR_EQUAL_UINT(latchkey_util::kRetiredLabelsBytes, retired.encode().size());
}

static void test_retired_labels_reject_damaged_or_invalid_data_without_mutating_output() {
    latchkey_util::RetiredLabels labels;
    TEST_ASSERT_FALSE(labels.remember('x', 1, "Name"));
    TEST_ASSERT_FALSE(labels.remember('f', 1, std::string(49, 'x')));
    TEST_ASSERT_TRUE(labels.remember('f', 1, "Name"));
    const auto bytes = labels.encode();
    for (size_t length = 0; length < bytes.size(); ++length) {
        TEST_ASSERT_FALSE(latchkey_util::RetiredLabels::decode(bytes.data(), length, labels));
        TEST_ASSERT_NOT_NULL(labels.find('f', 1));
    }
    auto damaged = bytes;
    damaged[2] = 'x';
    TEST_ASSERT_FALSE(latchkey_util::RetiredLabels::decode(damaged.data(), damaged.size(), labels));
    damaged = bytes;
    damaged.push_back(0);
    TEST_ASSERT_FALSE(latchkey_util::RetiredLabels::decode(damaged.data(), damaged.size(), labels));
}

static void test_truncated_replacement_pin_is_never_mistaken_for_a_complete_credential() {
    const ttlock::Bytes record{5, 0x26, 1, 1, 0x12, 0, 0, 80, 6, '4', '8', '2', '6', '1', '3',
                               9, '7', '5', '1', '9', '4', '6'};
    ttlock::Bytes wire{0, 1, 0, 1, static_cast<uint8_t>(record.size())};
    wire.insert(wire.end(), record.begin(), record.end());
    ttlock::LogPage page;
    TEST_ASSERT_TRUE(ttlock::parseLogPage(wire, page));
    TEST_ASSERT_EQUAL_UINT(1, page.entries.size());
    TEST_ASSERT_TRUE(page.entries[0].newCredential.empty());
    TEST_ASSERT_TRUE(render(page.entries[0]).find("newCredential") == std::string::npos);
}

static void test_failed_status_push_does_not_turn_an_error_code_into_battery_or_state_data() {
    for (const ttlock::Bytes data : {ttlock::Bytes{1}, ttlock::Bytes{1, 0, 0}, ttlock::Bytes(15, 1)}) {
        ttlock::Reply reply;
        reply.command = ttlock::command::kSearchStatus;
        reply.status = 0;
        reply.data = data;
        const auto event = ttlock::parseLockEvent(reply);
        TEST_ASSERT_EQUAL_INT(-1, event.battery);
        TEST_ASSERT_EQUAL_INT(ttlock::LockState::Unknown, event.state);
        TEST_ASSERT_FALSE(event.hasRecord);
    }
}

int main() {
    UNITY_BEGIN();
    RUN_TEST(test_fingerprint_and_card_events_include_safe_ids_and_current_labels);
    RUN_TEST(test_passcodes_match_only_complete_exact_values_and_never_leave_raw_secrets);
    RUN_TEST(test_unknown_numeric_credentials_keep_ids_but_reject_sentinels_and_invalid_values);
    RUN_TEST(test_clear_and_unrelated_types_never_infer_a_credential_from_their_tail);
    RUN_TEST(test_failed_attempts_are_explicit_and_unknown_outcomes_are_not_successes);
    RUN_TEST(test_hash_failure_does_not_publish_a_partial_result_and_names_are_escaped);
    RUN_TEST(test_app_records_keep_safe_actor_numbers_only_for_supported_record_layouts);
    RUN_TEST(test_retired_labels_survive_reload_are_bounded_and_do_not_override_current_names);
    RUN_TEST(test_retired_labels_reject_damaged_or_invalid_data_without_mutating_output);
    RUN_TEST(test_truncated_replacement_pin_is_never_mistaken_for_a_complete_credential);
    RUN_TEST(test_failed_status_push_does_not_turn_an_error_code_into_battery_or_state_data);
    return UNITY_END();
}
