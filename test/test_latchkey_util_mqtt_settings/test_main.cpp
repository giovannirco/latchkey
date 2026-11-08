// SPDX-License-Identifier: GPL-3.0-or-later
#include <unity.h>

#include <string>

#include "latchkey_util/mqtt_settings.h"

void setUp() {}

void tearDown() {}

static void test_the_limits_match_the_web_form() {
    TEST_ASSERT_EQUAL_UINT(64, latchkey_util::kMaxMqttHost);
    TEST_ASSERT_EQUAL_UINT(64, latchkey_util::kMaxMqttUsername);
    TEST_ASSERT_EQUAL_UINT(64, latchkey_util::kMaxMqttPassword);
    TEST_ASSERT_EQUAL_UINT(32, latchkey_util::kMaxHaPrefix);
    TEST_ASSERT_EQUAL_UINT16(1883, latchkey_util::kDefaultMqttPort);
    TEST_ASSERT_EQUAL_STRING("homeassistant", latchkey_util::kDefaultHaPrefix);
}

static void test_a_host_is_a_name_or_an_ipv4_address() {
    const std::string longest(64, 'h');
    const char* const good[] = {"192.0.2.10", "broker", "mqtt.example.org", "broker-1.lan", "mqtt_server", "B"};
    for (const char* host : good) {
        TEST_ASSERT_TRUE_MESSAGE(latchkey_util::isMqttHost(host), host);
    }
    TEST_ASSERT_TRUE(latchkey_util::isMqttHost(longest));
}

static void test_a_host_cannot_carry_a_scheme_a_port_a_path_or_spaces() {
    const std::string tooLong(65, 'h');
    const char* const bad[] = {"",       "a b",      "broker/x",    "broker:1883",     "mqtt://broker",
                               "user@b", ".broker",  "broker.",     "a..b",            "broker\t",
                               "#",      "+",        "broker\n",    "caf\xC3\xA9",     "[2001:db8::1]"};
    for (const char* host : bad) {
        TEST_ASSERT_FALSE_MESSAGE(latchkey_util::isMqttHost(host), host);
    }
    TEST_ASSERT_FALSE(latchkey_util::isMqttHost(tooLong));
    TEST_ASSERT_FALSE(latchkey_util::isMqttHost(std::string("bro\0ker", 7)));
}

static void test_the_stored_password_stays_only_with_the_same_broker() {
    const latchkey_util::MqttBroker stored{"broker.lan", 1883, "latchkey"};
    TEST_ASSERT_TRUE(latchkey_util::keepsPassword(stored, {"broker.lan", 1883, "latchkey"}));
    TEST_ASSERT_FALSE(latchkey_util::keepsPassword(stored, {"other.lan", 1883, "latchkey"}));
    TEST_ASSERT_FALSE(latchkey_util::keepsPassword(stored, {"Broker.lan", 1883, "latchkey"}));
    TEST_ASSERT_FALSE(latchkey_util::keepsPassword(stored, {"broker.lan", 8883, "latchkey"}));
    TEST_ASSERT_FALSE(latchkey_util::keepsPassword(stored, {"broker.lan", 1883, "someone"}));
    TEST_ASSERT_FALSE(latchkey_util::keepsPassword(stored, {"broker.lan", 1883, ""}));
    TEST_ASSERT_FALSE(latchkey_util::keepsPassword(stored, {"", 1883, "latchkey"}));
}

int main() {
    UNITY_BEGIN();
    RUN_TEST(test_the_limits_match_the_web_form);
    RUN_TEST(test_the_stored_password_stays_only_with_the_same_broker);
    RUN_TEST(test_a_host_is_a_name_or_an_ipv4_address);
    RUN_TEST(test_a_host_cannot_carry_a_scheme_a_port_a_path_or_spaces);
    return UNITY_END();
}
