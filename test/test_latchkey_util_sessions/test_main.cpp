// SPDX-License-Identifier: GPL-3.0-or-later
#include <unity.h>

#include <cstdint>
#include <optional>
#include <vector>

#include "latchkey_util/constant_time.h"
#include "latchkey_util/session_table.h"

using latchkey_util::SessionDigest;
using latchkey_util::SessionInfo;
using latchkey_util::SessionTable;

void setUp() {}

void tearDown() {}

static constexpr int64_t kIdle = 900;
static constexpr int64_t kLifetime = 12 * 3600;

static SessionDigest digest(uint8_t seed) {
    SessionDigest value{};
    for (size_t i = 0; i < value.size(); ++i) {
        value[i] = static_cast<uint8_t>(seed + i * 7);
    }
    return value;
}

static std::vector<uint32_t> ids(SessionTable& table, int64_t now) {
    std::vector<uint32_t> out;
    for (const SessionInfo& session : table.list(now)) {
        out.push_back(session.id);
    }
    return out;
}

static void test_open_numbers_sessions_in_order() {
    SessionTable table(kIdle, kLifetime, 41);
    const SessionInfo first = table.open(digest(1), 100);
    const SessionInfo second = table.open(digest(2), 105);
    TEST_ASSERT_EQUAL_UINT32(41, first.id);
    TEST_ASSERT_EQUAL_UINT32(42, second.id);
    TEST_ASSERT_EQUAL_INT64(100, first.createdAt);
    TEST_ASSERT_EQUAL_INT64(100, first.lastSeenAt);
    TEST_ASSERT_EQUAL_INT64(100 + kLifetime, table.expiresAt(first));
}

static void test_touch_finds_the_session_and_refreshes_it() {
    SessionTable table(kIdle, kLifetime, 1);
    table.open(digest(1), 100);
    const SessionInfo second = table.open(digest(2), 100);
    const std::optional<uint32_t> found = table.touch(digest(2), 400);
    TEST_ASSERT_TRUE(found.has_value());
    TEST_ASSERT_EQUAL_UINT32(second.id, *found);
    const std::vector<SessionInfo> sessions = table.list(400);
    TEST_ASSERT_EQUAL_size_t(2, sessions.size());
    TEST_ASSERT_EQUAL_INT64(100, sessions[1].createdAt);
    TEST_ASSERT_EQUAL_INT64(400, sessions[1].lastSeenAt);
    TEST_ASSERT_EQUAL_INT64(100, sessions[0].lastSeenAt);
}

static void test_an_unknown_digest_finds_nothing() {
    SessionTable table(kIdle, kLifetime, 1);
    table.open(digest(1), 100);
    SessionDigest near = digest(1);
    near[31] ^= 0x01;
    TEST_ASSERT_FALSE(table.touch(near, 100).has_value());
    TEST_ASSERT_FALSE(table.touch(digest(9), 100).has_value());
    SessionTable empty(kIdle, kLifetime, 1);
    TEST_ASSERT_FALSE(empty.touch(SessionDigest{}, 0).has_value());
}

static void test_an_idle_session_expires() {
    SessionTable table(kIdle, kLifetime, 1);
    table.open(digest(1), 0);
    TEST_ASSERT_TRUE(table.touch(digest(1), kIdle - 1).has_value());
    TEST_ASSERT_TRUE(table.touch(digest(1), 2 * kIdle - 2).has_value());
    TEST_ASSERT_FALSE(table.touch(digest(1), 3 * kIdle - 2).has_value());
    TEST_ASSERT_TRUE(table.list(3 * kIdle - 2).empty());
    TEST_ASSERT_FALSE(table.touch(digest(1), 3 * kIdle - 2).has_value());
}

static void test_a_busy_session_still_ends_after_12_hours() {
    SessionTable table(kIdle, kLifetime, 1);
    table.open(digest(1), 0);
    int64_t now = 0;
    while (now + kIdle - 1 < kLifetime) {
        now += kIdle - 1;
        TEST_ASSERT_TRUE(table.touch(digest(1), now).has_value());
    }
    TEST_ASSERT_TRUE(table.touch(digest(1), kLifetime - 1).has_value());
    TEST_ASSERT_FALSE(table.touch(digest(1), kLifetime).has_value());
}

static void test_a_fifth_session_replaces_the_least_recently_seen() {
    SessionTable table(kIdle, kLifetime, 1);
    for (uint8_t i = 1; i <= 4; ++i) {
        table.open(digest(i), i);
    }
    table.touch(digest(1), 10);
    const SessionInfo fifth = table.open(digest(5), 11);
    TEST_ASSERT_EQUAL_UINT32(5, fifth.id);
    TEST_ASSERT_TRUE(table.touch(digest(1), 12).has_value());
    TEST_ASSERT_FALSE(table.touch(digest(2), 12).has_value());
    TEST_ASSERT_EQUAL_size_t(latchkey_util::kMaxSessions, table.list(12).size());
}

static void test_expired_sessions_make_room_first() {
    SessionTable table(kIdle, kLifetime, 1);
    table.open(digest(1), 0);
    for (int64_t now = 600; now <= 42000; now += 600) {
        TEST_ASSERT_TRUE(table.touch(digest(1), now).has_value());
    }
    for (uint8_t i = 2; i <= 4; ++i) {
        table.open(digest(i), 42500);
    }
    TEST_ASSERT_TRUE(table.touch(digest(1), 42600).has_value());
    table.open(digest(5), kLifetime);
    TEST_ASSERT_FALSE(table.touch(digest(1), kLifetime).has_value());
    for (uint8_t i = 2; i <= 5; ++i) {
        TEST_ASSERT_TRUE(table.touch(digest(i), kLifetime).has_value());
    }
}

static void test_close_ends_one_session() {
    SessionTable table(kIdle, kLifetime, 1);
    const SessionInfo first = table.open(digest(1), 0);
    table.open(digest(2), 0);
    TEST_ASSERT_TRUE(table.close(first.id));
    TEST_ASSERT_FALSE(table.close(first.id));
    TEST_ASSERT_FALSE(table.close(77));
    TEST_ASSERT_FALSE(table.touch(digest(1), 1).has_value());
    TEST_ASSERT_TRUE(table.touch(digest(2), 1).has_value());
}

static void test_close_all_except_keeps_one() {
    SessionTable table(kIdle, kLifetime, 1);
    table.open(digest(1), 0);
    const SessionInfo kept = table.open(digest(2), 0);
    table.open(digest(3), 0);
    table.closeAllExcept(kept.id);
    TEST_ASSERT_EQUAL_size_t(1, table.list(0).size());
    TEST_ASSERT_EQUAL_UINT32(kept.id, table.list(0)[0].id);
    table.closeAllExcept(std::nullopt);
    TEST_ASSERT_TRUE(table.list(0).empty());
}

static void test_ids_are_never_reused() {
    SessionTable table(kIdle, kLifetime, 1);
    const SessionInfo first = table.open(digest(1), 0);
    table.close(first.id);
    const SessionInfo second = table.open(digest(1), 0);
    TEST_ASSERT_EQUAL_UINT32(first.id + 1, second.id);
}

static void test_list_drops_expired_sessions_and_keeps_creation_order() {
    SessionTable table(kIdle, kLifetime, 1);
    table.open(digest(1), 0);
    table.open(digest(2), 500);
    table.open(digest(3), 600);
    table.touch(digest(1), 700);
    const std::vector<uint32_t> listed = ids(table, 1450);
    TEST_ASSERT_EQUAL_size_t(2, listed.size());
    TEST_ASSERT_EQUAL_UINT32(1, listed[0]);
    TEST_ASSERT_EQUAL_UINT32(3, listed[1]);
}

static void test_constant_time_equal_compares_every_byte() {
    const uint8_t a[] = {1, 2, 3, 4};
    const uint8_t b[] = {1, 2, 3, 4};
    const uint8_t first[] = {9, 2, 3, 4};
    const uint8_t last[] = {1, 2, 3, 5};
    TEST_ASSERT_TRUE(latchkey_util::constantTimeEqual(a, b, sizeof(a)));
    TEST_ASSERT_FALSE(latchkey_util::constantTimeEqual(a, first, sizeof(a)));
    TEST_ASSERT_FALSE(latchkey_util::constantTimeEqual(a, last, sizeof(a)));
    TEST_ASSERT_TRUE(latchkey_util::constantTimeEqual(a, first, 0));
}

int main() {
    UNITY_BEGIN();
    RUN_TEST(test_open_numbers_sessions_in_order);
    RUN_TEST(test_touch_finds_the_session_and_refreshes_it);
    RUN_TEST(test_an_unknown_digest_finds_nothing);
    RUN_TEST(test_an_idle_session_expires);
    RUN_TEST(test_a_busy_session_still_ends_after_12_hours);
    RUN_TEST(test_a_fifth_session_replaces_the_least_recently_seen);
    RUN_TEST(test_expired_sessions_make_room_first);
    RUN_TEST(test_close_ends_one_session);
    RUN_TEST(test_close_all_except_keeps_one);
    RUN_TEST(test_ids_are_never_reused);
    RUN_TEST(test_list_drops_expired_sessions_and_keeps_creation_order);
    RUN_TEST(test_constant_time_equal_compares_every_byte);
    return UNITY_END();
}
