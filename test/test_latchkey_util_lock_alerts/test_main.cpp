// SPDX-License-Identifier: GPL-3.0-or-later
#include <unity.h>

#include <array>
#include <cstdint>

#include "latchkey_util/lock_alerts.h"

using latchkey_util::LockAlert;
using latchkey_util::LockAlerts;
using latchkey_util::LockAlertKind;
using latchkey_util::UnlockMethod;

void setUp() {}

void tearDown() {}

static LockAlert unexpected(uint16_t seq) {
    LockAlert alert;
    alert.kind = LockAlertKind::UnexpectedUnlock;
    alert.time = 0x12345678;
    alert.seq = seq;
    alert.type = 1;
    alert.method = UnlockMethod::App;
    return alert;
}

static void test_an_alert_survives_restart_and_acknowledging_it_keeps_a_new_arrival() {
    LockAlerts alerts;
    TEST_ASSERT_TRUE(alerts.add(unexpected(41)));
    const uint32_t seen = alerts.entries().back().id;
    const auto bytes = alerts.encode();
    LockAlerts restarted;
    TEST_ASSERT_TRUE(LockAlerts::decode(bytes.data(), bytes.size(), restarted));
    TEST_ASSERT_EQUAL_UINT(1, restarted.entries().size());
    TEST_ASSERT_EQUAL_UINT32(seen, restarted.entries()[0].id);
    TEST_ASSERT_TRUE(restarted.add(unexpected(42)));
    TEST_ASSERT_TRUE(restarted.acknowledge(seen));
    TEST_ASSERT_EQUAL_UINT(1, restarted.entries().size());
    TEST_ASSERT_EQUAL_UINT16(42, restarted.entries()[0].seq);
    TEST_ASSERT_GREATER_THAN_UINT32(seen, restarted.entries()[0].id);
}

static void test_the_recent_list_is_bounded_and_ids_do_not_restart_after_acknowledgement() {
    LockAlerts alerts;
    for (uint16_t seq = 1; seq <= 12; ++seq) {
        TEST_ASSERT_TRUE(alerts.add(unexpected(seq)));
    }
    TEST_ASSERT_EQUAL_UINT(8, alerts.entries().size());
    TEST_ASSERT_EQUAL_UINT16(5, alerts.entries().front().seq);
    const uint32_t last = alerts.entries().back().id;
    TEST_ASSERT_TRUE(alerts.acknowledge(last));
    TEST_ASSERT_TRUE(alerts.entries().empty());
    const auto bytes = alerts.encode();
    LockAlerts restarted;
    TEST_ASSERT_TRUE(LockAlerts::decode(bytes.data(), bytes.size(), restarted));
    TEST_ASSERT_TRUE(restarted.add(unexpected(13)));
    TEST_ASSERT_EQUAL_UINT32(last + 1, restarted.entries()[0].id);
}

static void test_a_repeated_log_read_does_not_duplicate_an_unacknowledged_alert() {
    LockAlerts alerts;
    TEST_ASSERT_TRUE(alerts.add(unexpected(41)));
    TEST_ASSERT_TRUE(alerts.add(unexpected(41)));
    TEST_ASSERT_EQUAL_UINT(1, alerts.entries().size());
    TEST_ASSERT_TRUE(alerts.add(unexpected(42)));
    TEST_ASSERT_EQUAL_UINT32(2, alerts.entries().back().id);
}

static void test_a_watch_warning_is_stored_without_becoming_an_unlock() {
    LockAlerts alerts;
    LockAlert warning;
    warning.kind = LockAlertKind::WatchStateUnreadable;
    warning.time = 42;
    TEST_ASSERT_TRUE(alerts.add(warning));
    const auto bytes = alerts.encode();
    LockAlerts restarted;
    TEST_ASSERT_TRUE(LockAlerts::decode(bytes.data(), bytes.size(), restarted));
    TEST_ASSERT_EQUAL(LockAlertKind::WatchStateUnreadable, restarted.entries()[0].kind);
    TEST_ASSERT_EQUAL(UnlockMethod::None, restarted.entries()[0].method);
}

static void test_an_acknowledgement_cannot_hide_alerts_that_have_not_arrived() {
    LockAlerts alerts;
    TEST_ASSERT_TRUE(alerts.add(unexpected(41)));
    TEST_ASSERT_FALSE(alerts.acknowledge(2));
    TEST_ASSERT_EQUAL_UINT(1, alerts.entries().size());
    TEST_ASSERT_TRUE(alerts.acknowledge(0));
    TEST_ASSERT_EQUAL_UINT(1, alerts.entries().size());
}

static void test_a_corrupt_alert_table_is_refused_without_overwriting_the_caller() {
    LockAlerts alerts;
    TEST_ASSERT_TRUE(alerts.add(unexpected(41)));
    const auto original = alerts.encode();
    TEST_ASSERT_FALSE(LockAlerts::decode(nullptr, original.size(), alerts));
    TEST_ASSERT_FALSE(LockAlerts::decode(original.data(), original.size() - 1, alerts));
    for (const auto [offset, value] : std::array<std::array<uint8_t, 2>, 5>{
             {{0, 99}, {5, 9}, {10, 0}, {18, 99}, {19, 99}}}) {
        auto broken = original;
        broken[offset] = value;
        TEST_ASSERT_FALSE(LockAlerts::decode(broken.data(), broken.size(), alerts));
        TEST_ASSERT_TRUE(alerts.encode() == original);
    }
}

static void test_a_lost_table_starts_empty_but_for_a_warning_that_is_not_an_unlock() {
    LockAlerts alerts = LockAlerts::lost();
    TEST_ASSERT_EQUAL_UINT(1, alerts.entries().size());
    const LockAlert warning = alerts.entries()[0];
    TEST_ASSERT_EQUAL(LockAlertKind::AlertsUnreadable, warning.kind);
    TEST_ASSERT_EQUAL(UnlockMethod::None, warning.method);
    TEST_ASSERT_EQUAL_UINT32(0, warning.time);
    TEST_ASSERT_TRUE(alerts.add(unexpected(41)));
    TEST_ASSERT_GREATER_THAN_UINT32(warning.id, alerts.entries().back().id);
}

static void test_the_lost_warning_survives_a_restart_until_it_is_acknowledged() {
    const LockAlerts alerts = LockAlerts::lost();
    const auto bytes = alerts.encode();
    LockAlerts restarted;
    TEST_ASSERT_TRUE(LockAlerts::decode(bytes.data(), bytes.size(), restarted));
    TEST_ASSERT_EQUAL_UINT(1, restarted.entries().size());
    TEST_ASSERT_EQUAL(LockAlertKind::AlertsUnreadable, restarted.entries()[0].kind);
    TEST_ASSERT_TRUE(restarted.acknowledge(restarted.entries()[0].id));
    TEST_ASSERT_TRUE(restarted.entries().empty());
}

static void test_a_lost_warning_cannot_carry_an_unlock() {
    LockAlerts alerts;
    LockAlert forged = unexpected(41);
    forged.kind = LockAlertKind::AlertsUnreadable;
    TEST_ASSERT_FALSE(alerts.add(forged));
    TEST_ASSERT_TRUE(alerts.entries().empty());
}

static void test_low_battery_is_strictly_below_forty_and_ignores_invalid_levels() {
    LockAlerts alerts;
    TEST_ASSERT_FALSE(alerts.observeBattery(-1, 1));
    TEST_ASSERT_FALSE(alerts.observeBattery(101, 1));
    TEST_ASSERT_TRUE(alerts.observeBattery(40, 1));
    TEST_ASSERT_TRUE(alerts.entries().empty());
    TEST_ASSERT_TRUE(alerts.observeBattery(39, 2));
    TEST_ASSERT_EQUAL_UINT(1, alerts.entries().size());
    TEST_ASSERT_EQUAL(LockAlertKind::LowBattery, alerts.entries()[0].kind);
    TEST_ASSERT_EQUAL_INT(39, alerts.entries()[0].battery);
    TEST_ASSERT_EQUAL_UINT32(2, alerts.entries()[0].time);
    TEST_ASSERT_TRUE(alerts.observeBattery(0, 3));
    TEST_ASSERT_EQUAL_UINT(1, alerts.entries().size());
}

static void test_battery_episode_survives_acknowledgement_restart_and_rearms_after_recovery() {
    LockAlerts alerts;
    TEST_ASSERT_TRUE(alerts.observeBattery(20, 1));
    const auto id = alerts.entries()[0].id;
    TEST_ASSERT_TRUE(alerts.acknowledge(id));
    auto bytes = alerts.encode();
    LockAlerts restarted;
    TEST_ASSERT_TRUE(LockAlerts::decode(bytes.data(), bytes.size(), restarted));
    TEST_ASSERT_TRUE(restarted.observeBattery(10, 2));
    TEST_ASSERT_TRUE(restarted.entries().empty());
    TEST_ASSERT_TRUE(restarted.observeBattery(40, 3));
    bytes = restarted.encode();
    TEST_ASSERT_TRUE(LockAlerts::decode(bytes.data(), bytes.size(), alerts));
    TEST_ASSERT_TRUE(alerts.observeBattery(39, 4));
    TEST_ASSERT_EQUAL_UINT(1, alerts.entries().size());
    TEST_ASSERT_GREATER_THAN_UINT32(id, alerts.entries()[0].id);
}

static void test_battery_recovery_removes_only_battery_notices() {
    LockAlerts alerts;
    TEST_ASSERT_TRUE(alerts.add(unexpected(41)));
    TEST_ASSERT_TRUE(alerts.observeBattery(0, 1));
    TEST_ASSERT_TRUE(alerts.observeBattery(100, 2));
    TEST_ASSERT_EQUAL_UINT(1, alerts.entries().size());
    TEST_ASSERT_EQUAL(LockAlertKind::UnexpectedUnlock, alerts.entries()[0].kind);
}

static void test_v060_alerts_are_preserved_on_upgrade() {
    const std::array<uint8_t, 110> old{1, 0, 0, 0, 2, 1, 0, 0, 0, 1,
        0x12, 0x34, 0x56, 0x78, 0, 41, 1, 1, 1};
    LockAlerts alerts;
    TEST_ASSERT_TRUE(LockAlerts::decode(old.data(), old.size(), alerts));
    TEST_ASSERT_EQUAL_UINT(1, alerts.entries().size());
    TEST_ASSERT_EQUAL_UINT16(41, alerts.entries()[0].seq);
    TEST_ASSERT_EQUAL_INT(-1, alerts.entries()[0].battery);
    TEST_ASSERT_TRUE(alerts.observeBattery(39, 2));
    TEST_ASSERT_EQUAL_UINT(2, alerts.entries().size());
}

static void test_alert_overflow_keeps_unacknowledged_battery_warning_across_restart() {
    LockAlerts alerts;
    TEST_ASSERT_TRUE(alerts.observeBattery(39, 1));
    for (uint16_t seq = 1; seq <= 10; ++seq) TEST_ASSERT_TRUE(alerts.add(unexpected(seq)));
    const auto bytes = alerts.encode();
    LockAlerts restarted;
    TEST_ASSERT_TRUE(LockAlerts::decode(bytes.data(), bytes.size(), restarted));
    TEST_ASSERT_TRUE(restarted.observeBattery(20, 2));
    TEST_ASSERT_EQUAL_UINT(8, restarted.entries().size());
    TEST_ASSERT_EQUAL(LockAlertKind::LowBattery, restarted.entries()[0].kind);
}

int main(int, char**) {
    UNITY_BEGIN();
    RUN_TEST(test_an_alert_survives_restart_and_acknowledging_it_keeps_a_new_arrival);
    RUN_TEST(test_the_recent_list_is_bounded_and_ids_do_not_restart_after_acknowledgement);
    RUN_TEST(test_a_repeated_log_read_does_not_duplicate_an_unacknowledged_alert);
    RUN_TEST(test_a_watch_warning_is_stored_without_becoming_an_unlock);
    RUN_TEST(test_an_acknowledgement_cannot_hide_alerts_that_have_not_arrived);
    RUN_TEST(test_a_corrupt_alert_table_is_refused_without_overwriting_the_caller);
    RUN_TEST(test_a_lost_table_starts_empty_but_for_a_warning_that_is_not_an_unlock);
    RUN_TEST(test_the_lost_warning_survives_a_restart_until_it_is_acknowledged);
    RUN_TEST(test_a_lost_warning_cannot_carry_an_unlock);
    RUN_TEST(test_low_battery_is_strictly_below_forty_and_ignores_invalid_levels);
    RUN_TEST(test_battery_episode_survives_acknowledgement_restart_and_rearms_after_recovery);
    RUN_TEST(test_battery_recovery_removes_only_battery_notices);
    RUN_TEST(test_v060_alerts_are_preserved_on_upgrade);
    RUN_TEST(test_alert_overflow_keeps_unacknowledged_battery_warning_across_restart);
    return UNITY_END();
}
