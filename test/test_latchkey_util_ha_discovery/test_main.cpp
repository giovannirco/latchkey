// SPDX-License-Identifier: GPL-3.0-or-later
#include <unity.h>

#include <cstdint>
#include <optional>
#include <string>
#include <vector>

#include "latchkey_util/ha_discovery.h"

using latchkey_util::HaLock;
using latchkey_util::HaLockTopics;
using latchkey_util::MqttMessage;

void setUp() {}

void tearDown() {}

static HaLock frontDoor() {
    HaLock lock;
    lock.discoveryPrefix = "homeassistant";
    lock.board = "latchkey-0a1b2c";
    lock.lock = "00005e005321";
    lock.name = "Front door";
    lock.model = "LK-MOCK-1";
    lock.manufacturer = "TTLock";
    lock.firmware = "6.0.2.240117";
    lock.latchkeyVersion = "0.1.0";
    return lock;
}

static const std::string kBase = "latchkey/latchkey-0a1b2c/00005e005321/";

static std::string common(const std::string& suffix) {
    return R"("unique_id":"latchkey_latchkey-0a1b2c_00005e005321_)" + suffix +
           R"(","device":{"identifiers":["latchkey_00005e005321"],"name":"Front door","model":"LK-MOCK-1",)"
           R"("manufacturer":"TTLock","sw_version":"6.0.2.240117"},"origin":{"name":"Latchkey","sw_version":"0.1.0"},)"
           R"("availability_topic":"latchkey/latchkey-0a1b2c/availability","payload_available":"online",)"
           R"("payload_not_available":"offline",)";
}

static std::vector<MqttMessage> discover(const HaLock& lock) {
    std::vector<MqttMessage> messages;
    TEST_ASSERT_TRUE(latchkey_util::haDiscovery(lock, messages));
    TEST_ASSERT_EQUAL_UINT(5, messages.size());
    return messages;
}

static void test_topics_live_under_latchkey_board_and_lock() {
    HaLockTopics topics;
    TEST_ASSERT_TRUE(latchkey_util::haLockTopics("latchkey-0a1b2c", "00005e005321", topics));
    TEST_ASSERT_EQUAL_STRING("latchkey/latchkey-0a1b2c/availability", topics.availability.c_str());
    TEST_ASSERT_EQUAL_STRING((kBase + "state").c_str(), topics.state.c_str());
    TEST_ASSERT_EQUAL_STRING((kBase + "set").c_str(), topics.command.c_str());
    TEST_ASSERT_EQUAL_STRING((kBase + "battery").c_str(), topics.battery.c_str());
    TEST_ASSERT_EQUAL_STRING((kBase + "last_event").c_str(), topics.lastEvent.c_str());
    TEST_ASSERT_EQUAL_STRING((kBase + "link").c_str(), topics.link.c_str());
    TEST_ASSERT_EQUAL_STRING((kBase + "alert").c_str(), topics.alert.c_str());
}

static void test_the_lock_entity_takes_lock_and_unlock_commands() {
    const MqttMessage lock = discover(frontDoor())[0];
    TEST_ASSERT_EQUAL_STRING("homeassistant/lock/latchkey-0a1b2c/00005e005321/config", lock.topic.c_str());
    const std::string expected = R"({"name":null,)" + common("lock") + R"("state_topic":")" + kBase +
                                 R"(state","command_topic":")" + kBase +
                                 R"(set","payload_lock":"LOCK","payload_unlock":"UNLOCK","state_locked":"LOCKED",)"
                                 R"("state_unlocked":"UNLOCKED"})";
    TEST_ASSERT_EQUAL_STRING(expected.c_str(), lock.payload.c_str());
}

static void test_the_battery_sensor_reports_a_percentage() {
    const MqttMessage battery = discover(frontDoor())[1];
    TEST_ASSERT_EQUAL_STRING("homeassistant/sensor/latchkey-0a1b2c/00005e005321_battery/config", battery.topic.c_str());
    const std::string expected = R"({"name":"Battery",)" + common("battery") + R"("state_topic":")" + kBase +
                                 R"(battery","device_class":"battery","state_class":"measurement",)"
                                 R"("unit_of_measurement":"%","entity_category":"diagnostic"})";
    TEST_ASSERT_EQUAL_STRING(expected.c_str(), battery.payload.c_str());
}

static void test_the_last_event_sensor_shows_the_latest_event() {
    const MqttMessage lastEvent = discover(frontDoor())[2];
    TEST_ASSERT_EQUAL_STRING("homeassistant/sensor/latchkey-0a1b2c/00005e005321_last_event/config",
                             lastEvent.topic.c_str());
    const std::string expected =
        R"({"name":"Last event",)" + common("last_event") + R"("state_topic":")" + kBase + R"(last_event"})";
    TEST_ASSERT_EQUAL_STRING(expected.c_str(), lastEvent.payload.c_str());
}

static void test_the_link_binary_sensor_is_a_connectivity_diagnostic() {
    const MqttMessage link = discover(frontDoor())[3];
    TEST_ASSERT_EQUAL_STRING("homeassistant/binary_sensor/latchkey-0a1b2c/00005e005321_link/config", link.topic.c_str());
    const std::string expected = R"({"name":"Bluetooth link",)" + common("link") + R"("state_topic":")" + kBase +
                                 R"(link","device_class":"connectivity","payload_on":"ON","payload_off":"OFF",)"
                                 R"("entity_category":"diagnostic"})";
    TEST_ASSERT_EQUAL_STRING(expected.c_str(), link.payload.c_str());
}

static void test_the_unlock_alert_is_an_event_entity() {
    const MqttMessage alert = discover(frontDoor())[4];
    TEST_ASSERT_EQUAL_STRING("homeassistant/event/latchkey-0a1b2c/00005e005321_unlock_alert/config",
                             alert.topic.c_str());
    const std::string expected = R"({"name":"Unlock alert",)" + common("unlock_alert") + R"("state_topic":")" +
                                 kBase + R"(alert","event_types":["unexpected_unlock"]})";
    TEST_ASSERT_EQUAL_STRING(expected.c_str(), alert.payload.c_str());
}

static void test_the_payload_constants_match_the_configs() {
    TEST_ASSERT_EQUAL_STRING("online", latchkey_util::kHaOnline);
    TEST_ASSERT_EQUAL_STRING("offline", latchkey_util::kHaOffline);
    TEST_ASSERT_EQUAL_STRING("LOCK", latchkey_util::kHaLockCommand);
    TEST_ASSERT_EQUAL_STRING("UNLOCK", latchkey_util::kHaUnlockCommand);
    TEST_ASSERT_EQUAL_STRING("LOCKED", latchkey_util::kHaLocked);
    TEST_ASSERT_EQUAL_STRING("UNLOCKED", latchkey_util::kHaUnlocked);
    TEST_ASSERT_EQUAL_STRING("ON", latchkey_util::kHaLinkUp);
    TEST_ASSERT_EQUAL_STRING("OFF", latchkey_util::kHaLinkDown);
    TEST_ASSERT_EQUAL_STRING("unexpected_unlock", latchkey_util::kHaUnexpectedUnlock);
}

static void test_names_are_escaped_for_json() {
    HaLock lock = frontDoor();
    lock.name = "Front \"door\" \\ \xC3\xA9 / \xF0\x9F\x94\x92\n\t\r\b\f\x01\x1F\x7F";
    lock.model = std::string_view("A\0B", 3);
    const MqttMessage battery = discover(lock)[1];
    const std::string escaped =
        R"("name":"Front \"door\" \\ )" "\xC3\xA9 / \xF0\x9F\x94\x92" R"(\n\t\r\b\f\u0001\u001f)" "\x7F" R"(",)";
    TEST_ASSERT_TRUE_MESSAGE(battery.payload.find(escaped) != std::string::npos, battery.payload.c_str());
    TEST_ASSERT_TRUE_MESSAGE(battery.payload.find(R"("model":"A\u0000B")") != std::string::npos,
                             battery.payload.c_str());
}

static void test_empty_details_are_left_out() {
    HaLock lock = frontDoor();
    lock.model = "";
    lock.manufacturer = "";
    lock.firmware = "";
    lock.latchkeyVersion = "";
    const MqttMessage battery = discover(lock)[1];
    const std::string device =
        R"("device":{"identifiers":["latchkey_00005e005321"],"name":"Front door"},"origin":{"name":"Latchkey"},)";
    TEST_ASSERT_TRUE_MESSAGE(battery.payload.find(device) != std::string::npos, battery.payload.c_str());
}

static void test_invalid_utf8_is_refused() {
    const char* const broken[] = {"\xC3\x28", "\xC0\xAF", "\xED\xA0\x80", "\xF4\x90\x80\x80", "\xE2\x82", "\xFF"};
    for (const char* text : broken) {
        HaLock lock = frontDoor();
        lock.firmware = text;
        std::vector<MqttMessage> messages{MqttMessage{"kept", "kept"}};
        TEST_ASSERT_FALSE(latchkey_util::haDiscovery(lock, messages));
        TEST_ASSERT_EQUAL_UINT(1, messages.size());
        TEST_ASSERT_EQUAL_STRING("kept", messages[0].topic.c_str());
    }
}

static void test_ids_that_cannot_be_topic_or_object_ids_are_refused() {
    const char* const badIds[] = {"", "00:00:5E:00:53:21", "lock/1", "a b", "a+b", "a#b", "caf\xC3\xA9"};
    for (const char* id : badIds) {
        HaLockTopics topics;
        TEST_ASSERT_FALSE_MESSAGE(latchkey_util::haLockTopics(id, "00005e005321", topics), id);
        TEST_ASSERT_FALSE_MESSAGE(latchkey_util::haLockTopics("latchkey-0a1b2c", id, topics), id);
        std::vector<MqttMessage> messages;
        HaLock board = frontDoor();
        board.board = id;
        TEST_ASSERT_FALSE_MESSAGE(latchkey_util::haDiscovery(board, messages), id);
        HaLock prefix = frontDoor();
        prefix.discoveryPrefix = id;
        TEST_ASSERT_FALSE_MESSAGE(latchkey_util::haDiscovery(prefix, messages), id);
        HaLock lockId = frontDoor();
        lockId.lock = id;
        TEST_ASSERT_FALSE_MESSAGE(latchkey_util::haDiscovery(lockId, messages), id);
        TEST_ASSERT_TRUE(messages.empty());
    }
    HaLock unnamed = frontDoor();
    unnamed.name = "";
    std::vector<MqttMessage> messages;
    TEST_ASSERT_FALSE(latchkey_util::haDiscovery(unnamed, messages));
    HaLockTopics topics;
    TEST_ASSERT_TRUE(latchkey_util::haLockTopics("Board_1-x", "LOCK_2-y", topics));
    TEST_ASSERT_EQUAL_STRING("latchkey/Board_1-x/LOCK_2-y/state", topics.state.c_str());
}

static void test_discovery_configs_are_retained() {
    for (const MqttMessage& message : discover(frontDoor())) {
        TEST_ASSERT_TRUE_MESSAGE(message.retain, message.topic.c_str());
    }
}

static void test_ids_take_letters_digits_dash_and_underscore() {
    TEST_ASSERT_TRUE(latchkey_util::isHaId("homeassistant"));
    TEST_ASSERT_TRUE(latchkey_util::isHaId("Latchkey_HIL-2"));
    const char* const bad[] = {"", "home/assistant", "a+b", "a#b", "a b", "a.b", "caf\xC3\xA9"};
    for (const char* id : bad) {
        TEST_ASSERT_FALSE_MESSAGE(latchkey_util::isHaId(id), id);
    }
}

static void test_the_board_id_ends_with_the_last_three_bytes_of_its_mac() {
    const uint8_t mac[6] = {0x00, 0x00, 0x5E, 0x0A, 0x1B, 0x2C};
    TEST_ASSERT_EQUAL_STRING("latchkey-0a1b2c", latchkey_util::haBoardId(mac).c_str());
    const uint8_t high[6] = {0xFF, 0xEE, 0xDD, 0xCC, 0xBB, 0xAA};
    TEST_ASSERT_EQUAL_STRING("latchkey-ccbbaa", latchkey_util::haBoardId(high).c_str());
    TEST_ASSERT_TRUE(latchkey_util::isHaId(latchkey_util::haBoardId(high)));
}

static void test_a_lock_id_is_its_mac_in_lowercase_hex_and_back() {
    std::string id;
    TEST_ASSERT_TRUE(latchkey_util::haLockId("00:00:5E:00:53:21", id));
    TEST_ASSERT_EQUAL_STRING("00005e005321", id.c_str());
    TEST_ASSERT_TRUE(latchkey_util::haLockId("aa:bb:cc:dd:ee:ff", id));
    TEST_ASSERT_EQUAL_STRING("aabbccddeeff", id.c_str());
    std::string mac;
    TEST_ASSERT_TRUE(latchkey_util::haLockMac("00005e005321", mac));
    TEST_ASSERT_EQUAL_STRING("00:00:5E:00:53:21", mac.c_str());
    TEST_ASSERT_TRUE(latchkey_util::haLockMac("aabbccddeeff", mac));
    TEST_ASSERT_EQUAL_STRING("AA:BB:CC:DD:EE:FF", mac.c_str());
    const char* const badMacs[] = {"", "00:00:5E:00:53", "00:00:5E:00:53:2G", "00-00-5E-00-53-21",
                                   "00:00:5E:00:53:21:00", "0:00:5E:00:53:21"};
    for (const char* bad : badMacs) {
        id = "kept";
        TEST_ASSERT_FALSE_MESSAGE(latchkey_util::haLockId(bad, id), bad);
        TEST_ASSERT_EQUAL_STRING("kept", id.c_str());
    }
    const char* const badIds[] = {"", "00005e00532", "00005e0053211", "00005E005321", "00005e00532g", "00:00:5e:00"};
    for (const char* bad : badIds) {
        mac = "kept";
        TEST_ASSERT_FALSE_MESSAGE(latchkey_util::haLockMac(bad, mac), bad);
        TEST_ASSERT_EQUAL_STRING("kept", mac.c_str());
    }
}

static void test_removing_a_lock_empties_its_configs_and_its_state() {
    std::vector<MqttMessage> messages;
    TEST_ASSERT_TRUE(latchkey_util::haRemoval("homeassistant", "latchkey-0a1b2c", "00005e005321", messages));
    const char* const expected[] = {
        "homeassistant/lock/latchkey-0a1b2c/00005e005321/config",
        "homeassistant/sensor/latchkey-0a1b2c/00005e005321_battery/config",
        "homeassistant/sensor/latchkey-0a1b2c/00005e005321_last_event/config",
        "homeassistant/binary_sensor/latchkey-0a1b2c/00005e005321_link/config",
        "homeassistant/event/latchkey-0a1b2c/00005e005321_unlock_alert/config",
        "latchkey/latchkey-0a1b2c/00005e005321/state",
        "latchkey/latchkey-0a1b2c/00005e005321/battery",
        "latchkey/latchkey-0a1b2c/00005e005321/last_event",
        "latchkey/latchkey-0a1b2c/00005e005321/link",
    };
    TEST_ASSERT_EQUAL_UINT(9, messages.size());
    for (size_t i = 0; i < messages.size(); ++i) {
        TEST_ASSERT_EQUAL_STRING(expected[i], messages[i].topic.c_str());
        TEST_ASSERT_TRUE(messages[i].payload.empty());
        TEST_ASSERT_TRUE(messages[i].retain);
    }
    const std::vector<MqttMessage> configs = discover(frontDoor());
    for (size_t i = 0; i < configs.size(); ++i) {
        TEST_ASSERT_EQUAL_STRING(configs[i].topic.c_str(), messages[i].topic.c_str());
    }
    std::vector<MqttMessage> kept{MqttMessage{"kept", "kept"}};
    TEST_ASSERT_FALSE(latchkey_util::haRemoval("home/assistant", "latchkey-0a1b2c", "00005e005321", kept));
    TEST_ASSERT_FALSE(latchkey_util::haRemoval("homeassistant", "latchkey 0a1b2c", "00005e005321", kept));
    TEST_ASSERT_FALSE(latchkey_util::haRemoval("homeassistant", "latchkey-0a1b2c", "00:00:5E:00:53:21", kept));
    TEST_ASSERT_EQUAL_UINT(1, kept.size());
    TEST_ASSERT_EQUAL_STRING("kept", kept[0].topic.c_str());
}

static void test_a_config_topic_names_its_lock() {
    for (const MqttMessage& config : discover(frontDoor())) {
        const std::optional<std::string> lock =
            latchkey_util::haConfigLock(config.topic, "homeassistant", "latchkey-0a1b2c");
        TEST_ASSERT_TRUE_MESSAGE(lock.has_value(), config.topic.c_str());
        TEST_ASSERT_EQUAL_STRING("00005e005321", lock->c_str());
    }
    const char* const foreign[] = {
        "homeassistant/lock/latchkey-0a1b2c/00005e005321",
        "homeassistant/lock/latchkey-0a1b2c/00005e005321/config/more",
        "other/lock/latchkey-0a1b2c/00005e005321/config",
        "homeassistant/lock/latchkey-ffffff/00005e005321/config",
        "homeassistant/switch/latchkey-0a1b2c/00005e005321/config",
        "homeassistant/lock/latchkey-0a1b2c/00005e005321_battery/config",
        "homeassistant/sensor/latchkey-0a1b2c/00005e005321/config",
        "homeassistant/sensor/latchkey-0a1b2c/00005e005321_link/config",
        "homeassistant/sensor/latchkey-0a1b2c/00005e005321_temperature/config",
        "homeassistant/lock/latchkey-0a1b2c/00005E005321/config",
        "homeassistant/lock/latchkey-0a1b2c/00005e00532/config",
        "homeassistant/lock/latchkey-0a1b2c/zz005e005321/config",
        "homeassistant/sensor/latchkey-0a1b2c/_battery/config",
        "",
    };
    for (const char* topic : foreign) {
        TEST_ASSERT_FALSE_MESSAGE(latchkey_util::haConfigLock(topic, "homeassistant", "latchkey-0a1b2c").has_value(),
                                  topic);
    }
}

static void test_a_command_topic_names_its_lock() {
    HaLockTopics topics;
    TEST_ASSERT_TRUE(latchkey_util::haLockTopics("latchkey-0a1b2c", "00005e005321", topics));
    const std::optional<std::string> lock = latchkey_util::haCommandLock(topics.command, "latchkey-0a1b2c");
    TEST_ASSERT_TRUE(lock.has_value());
    TEST_ASSERT_EQUAL_STRING("00005e005321", lock->c_str());
    const char* const foreign[] = {
        "latchkey/latchkey-ffffff/00005e005321/set",
        "latchkey/latchkey-0a1b2c/00005e005321/state",
        "latchkey/latchkey-0a1b2c/set",
        "latchkey/latchkey-0a1b2c/00005e005321/set/more",
        "latchkey/latchkey-0a1b2c/00005E005321/set",
        "latchkey/latchkey-0a1b2c/00005e00532/set",
        "other/latchkey-0a1b2c/00005e005321/set",
        "latchkey/latchkey-0a1b2c//set",
        "",
    };
    for (const char* topic : foreign) {
        TEST_ASSERT_FALSE_MESSAGE(latchkey_util::haCommandLock(topic, "latchkey-0a1b2c").has_value(), topic);
    }
}

int main() {
    UNITY_BEGIN();
    RUN_TEST(test_topics_live_under_latchkey_board_and_lock);
    RUN_TEST(test_the_lock_entity_takes_lock_and_unlock_commands);
    RUN_TEST(test_the_battery_sensor_reports_a_percentage);
    RUN_TEST(test_the_last_event_sensor_shows_the_latest_event);
    RUN_TEST(test_the_link_binary_sensor_is_a_connectivity_diagnostic);
    RUN_TEST(test_the_unlock_alert_is_an_event_entity);
    RUN_TEST(test_the_payload_constants_match_the_configs);
    RUN_TEST(test_names_are_escaped_for_json);
    RUN_TEST(test_empty_details_are_left_out);
    RUN_TEST(test_invalid_utf8_is_refused);
    RUN_TEST(test_ids_that_cannot_be_topic_or_object_ids_are_refused);
    RUN_TEST(test_discovery_configs_are_retained);
    RUN_TEST(test_ids_take_letters_digits_dash_and_underscore);
    RUN_TEST(test_the_board_id_ends_with_the_last_three_bytes_of_its_mac);
    RUN_TEST(test_a_lock_id_is_its_mac_in_lowercase_hex_and_back);
    RUN_TEST(test_removing_a_lock_empties_its_configs_and_its_state);
    RUN_TEST(test_a_config_topic_names_its_lock);
    RUN_TEST(test_a_command_topic_names_its_lock);
    return UNITY_END();
}
