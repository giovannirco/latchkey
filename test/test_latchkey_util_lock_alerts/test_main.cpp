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
             {{0, 2}, {5, 9}, {9, 0}, {17, 99}, {18, 99}}}) {
        auto broken = original;
        broken[offset] = value;
        TEST_ASSERT_FALSE(LockAlerts::decode(broken.data(), broken.size(), alerts));
        TEST_ASSERT_TRUE(alerts.encode() == original);
    }
}

int main(int, char**) {
    UNITY_BEGIN();
    RUN_TEST(test_an_alert_survives_restart_and_acknowledging_it_keeps_a_new_arrival);
    RUN_TEST(test_the_recent_list_is_bounded_and_ids_do_not_restart_after_acknowledgement);
    RUN_TEST(test_a_repeated_log_read_does_not_duplicate_an_unacknowledged_alert);
    RUN_TEST(test_a_watch_warning_is_stored_without_becoming_an_unlock);
    RUN_TEST(test_an_acknowledgement_cannot_hide_alerts_that_have_not_arrived);
    RUN_TEST(test_a_corrupt_alert_table_is_refused_without_overwriting_the_caller);
    return UNITY_END();
}
