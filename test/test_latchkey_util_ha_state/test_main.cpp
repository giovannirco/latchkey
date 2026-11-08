// SPDX-License-Identifier: GPL-3.0-or-later
#include <unity.h>

#include <cstdint>
#include <optional>
#include <string>

#include "latchkey_util/ha_discovery.h"
#include "latchkey_util/ha_state.h"

using latchkey_util::HaCommand;
using latchkey_util::HaLockTopics;
using latchkey_util::MqttMessage;

void setUp() {}

void tearDown() {}

static HaLockTopics frontDoorTopics() {
    HaLockTopics topics;
    TEST_ASSERT_TRUE(latchkey_util::haLockTopics("latchkey-0a1b2c", "00005e005321", topics));
    return topics;
}

static void assertText(const char* expected, const std::optional<std::string>& actual) {
    TEST_ASSERT_TRUE_MESSAGE(actual.has_value(), expected);
    TEST_ASSERT_EQUAL_STRING(expected, actual->c_str());
}

static void test_lock_and_unlock_are_the_only_commands() {
    TEST_ASSERT_EQUAL(HaCommand::Lock, latchkey_util::parseHaCommand("LOCK", false));
    TEST_ASSERT_EQUAL(HaCommand::Unlock, latchkey_util::parseHaCommand("UNLOCK", false));
    const char* const unknown[] = {"", "lock", "unlock", "OPEN", "LOCK ", " UNLOCK", "LOCKED", "{\"state\":\"LOCK\"}"};
    for (const char* payload : unknown) {
        TEST_ASSERT_EQUAL_MESSAGE(HaCommand::Unknown, latchkey_util::parseHaCommand(payload, false), payload);
    }
}

static void test_a_retained_command_is_a_replay_and_never_runs() {
    TEST_ASSERT_EQUAL(HaCommand::Replayed, latchkey_util::parseHaCommand("UNLOCK", true));
    TEST_ASSERT_EQUAL(HaCommand::Replayed, latchkey_util::parseHaCommand("LOCK", true));
    TEST_ASSERT_EQUAL(HaCommand::Replayed, latchkey_util::parseHaCommand("OPEN", true));
}

static void test_lock_states_map_to_the_entity_payloads() {
    assertText("LOCKED", latchkey_util::haLockState("locked"));
    assertText("UNLOCKED", latchkey_util::haLockState("unlocked"));
    TEST_ASSERT_FALSE(latchkey_util::haLockState("unknown").has_value());
    TEST_ASSERT_FALSE(latchkey_util::haLockState("").has_value());
    TEST_ASSERT_FALSE(latchkey_util::haLockState("LOCKED").has_value());
}

static void test_a_battery_level_is_a_whole_percentage() {
    assertText("0", latchkey_util::haBattery(0));
    assertText("57", latchkey_util::haBattery(57));
    assertText("100", latchkey_util::haBattery(100));
    TEST_ASSERT_FALSE(latchkey_util::haBattery(-1).has_value());
    TEST_ASSERT_FALSE(latchkey_util::haBattery(101).has_value());
}

static void test_lock_events_read_like_the_web_ui() {
    assertText("Unlocked from the app", latchkey_util::haEventText("unlock", "app"));
    assertText("Locked from the app", latchkey_util::haEventText("lock", "app"));
    assertText("Locked", latchkey_util::haEventText("lock", ""));
    assertText("Locked automatically", latchkey_util::haEventText("lock", "auto"));
    assertText("Unlocked with a passcode", latchkey_util::haEventText("unlock", "passcode"));
    assertText("Unlocked with a fingerprint", latchkey_util::haEventText("unlock", "fingerprint"));
    assertText("Unlocked with a card", latchkey_util::haEventText("unlock", "card"));
    assertText("Unlocked with the mechanical key", latchkey_util::haEventText("unlock", "key"));
    assertText("Unlocked remotely", latchkey_util::haEventText("unlock", "remote"));
    assertText("Locked with the inside button", latchkey_util::haEventText("lock", "button"));
    assertText("Unlocked by wristband", latchkey_util::haEventText("unlock", "wristband"));
    TEST_ASSERT_FALSE(latchkey_util::haEventText("push", "").has_value());
    TEST_ASSERT_FALSE(latchkey_util::haEventText("", "app").has_value());
}

static void test_an_alert_is_a_one_off_event_for_the_alert_entity() {
    MqttMessage alert;
    TEST_ASSERT_TRUE(latchkey_util::haAlert(frontDoorTopics(), "app", 1731000000, alert));
    TEST_ASSERT_EQUAL_STRING("latchkey/latchkey-0a1b2c/00005e005321/alert", alert.topic.c_str());
    TEST_ASSERT_EQUAL_STRING(R"({"event_type":"unexpected_unlock","method":"app","time":1731000000})",
                             alert.payload.c_str());
    TEST_ASSERT_FALSE(alert.retain);
    TEST_ASSERT_TRUE(latchkey_util::haAlert(frontDoorTopics(), "forced", 0, alert));
    TEST_ASSERT_EQUAL_STRING(R"({"event_type":"unexpected_unlock","method":"forced","time":0})",
                             alert.payload.c_str());
}

static void test_an_alert_method_must_be_a_plain_name() {
    const char* const bad[] = {"", "App", "a\"b", "a b", "x\\y", "abcdefghijklmnopq"};
    for (const char* method : bad) {
        MqttMessage alert{"kept", "kept"};
        TEST_ASSERT_FALSE_MESSAGE(latchkey_util::haAlert(frontDoorTopics(), method, 1, alert), method);
        TEST_ASSERT_EQUAL_STRING("kept", alert.topic.c_str());
    }
}

static void test_the_link_is_up_while_the_board_hears_the_lock() {
    const int64_t now = 1731000000;
    const int64_t window = latchkey_util::kHaLinkWindowSeconds;
    TEST_ASSERT_EQUAL_INT64(120, window);
    const int64_t longAgo = now - 3600;
    assertText("ON", latchkey_util::haLinkState(now - 5, now, longAgo));
    assertText("ON", latchkey_util::haLinkState(now - window, now, longAgo));
    assertText("OFF", latchkey_util::haLinkState(now - window - 1, now, longAgo));
    assertText("ON", latchkey_util::haLinkState(now + 30, now, longAgo));
    assertText("OFF", latchkey_util::haLinkState(0, now, now - window - 1));
}

static void test_the_link_is_unknown_without_a_clock_or_before_a_full_window() {
    const int64_t now = 1731000000;
    TEST_ASSERT_FALSE(latchkey_util::haLinkState(now - 5, 0, 0).has_value());
    TEST_ASSERT_FALSE(latchkey_util::haLinkState(0, now, now - 30).has_value());
    assertText("OFF", latchkey_util::haLinkState(now - 500, now, now - 30));
    assertText("ON", latchkey_util::haLinkState(now - 5, now, now - 30));
}

int main() {
    UNITY_BEGIN();
    RUN_TEST(test_lock_and_unlock_are_the_only_commands);
    RUN_TEST(test_a_retained_command_is_a_replay_and_never_runs);
    RUN_TEST(test_lock_states_map_to_the_entity_payloads);
    RUN_TEST(test_a_battery_level_is_a_whole_percentage);
    RUN_TEST(test_lock_events_read_like_the_web_ui);
    RUN_TEST(test_an_alert_is_a_one_off_event_for_the_alert_entity);
    RUN_TEST(test_an_alert_method_must_be_a_plain_name);
    RUN_TEST(test_the_link_is_up_while_the_board_hears_the_lock);
    RUN_TEST(test_the_link_is_unknown_without_a_clock_or_before_a_full_window);
    return UNITY_END();
}
