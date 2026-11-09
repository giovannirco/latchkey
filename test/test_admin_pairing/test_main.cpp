// SPDX-License-Identifier: GPL-3.0-or-later
#include <unity.h>
#include "../fake_lock/fake_lock.h"
#include "ttlock/session.h"
#include "ttlock/commands.h"

namespace cmd = ttlock::command;
using ttlock::Status;
struct Rig {
    fake::FakeLock lock;
    fake::FakeClock clock;
    fake::FakeRandom random;
    ttlock::Session session{lock, clock, random};
    ttlock::AesKey key{};
    ttlock::LockKeys keys;
    ttlock::PairOptions options;
    ttlock::PairResult result;
    size_t prepared = 0;
    size_t finished = 0;
    bool allowPrepare = true;
    bool allowFinish = true;
    bool accepted = false;
    std::string candidate;
    Rig() {
        key.fill(0x42);
        lock.expect(cmd::kInitialization, ttlock::kDefaultAesKey, {fake::success(ttlock::kDefaultAesKey, cmd::kInitialization)});
        lock.expect(cmd::kGetAesKey, ttlock::kDefaultAesKey, {fake::success(ttlock::kDefaultAesKey, cmd::kGetAesKey, {key.begin(), key.end()})});
        lock.expect(cmd::kAddAdmin, key, {fake::success(key, cmd::kAddAdmin, fake::text("SCIENER"))});
        lock.expect(cmd::kTimeCalibrate, key, {fake::success(key, cmd::kTimeCalibrate)});
        lock.expect(cmd::kSearchDeviceFeature, key, {fake::success(key, cmd::kSearchDeviceFeature, {0, 0, 0, 0, 0})});
        options.prepareAdminPasscode = [&](std::string_view code) {
            ++prepared;
            candidate = code;
            TEST_ASSERT_EQUAL_UINT(5, lock.requests().size());
            return allowPrepare;
        };
        options.finishAdminPasscode = [&](bool verdict) {
            ++finished;
            accepted = verdict;
            TEST_ASSERT_EQUAL_UINT(6, lock.requests().size());
            return allowFinish;
        };
    }
    void tail(bool respond = true, bool refuse = false) {
        lock.expect(cmd::kSetAdminKeyboardPassword, key, respond ? std::vector<ttlock::Bytes>{refuse ? fake::failure(key, cmd::kSetAdminKeyboardPassword, 2) : fake::success(key, cmd::kSetAdminKeyboardPassword)} : std::vector<ttlock::Bytes>{});
        lock.expect(cmd::kInitPasswords, key, {fake::success(key, cmd::kInitPasswords)});
        lock.expect(cmd::kOperateFinished, key, {fake::success(key, cmd::kOperateFinished)});
    }
    Status pair() { return session.pair(fake::kRequestVersion, options, keys, {}, result); }
};
void setUp() {}
void tearDown() {}
static void test_failed_candidate_storage_stops_before_admin_write() {
    Rig rig;
    rig.allowPrepare = false;
    TEST_ASSERT_EQUAL_INT(static_cast<int>(Status::PairIncomplete), static_cast<int>(rig.pair()));
    TEST_ASSERT_EQUAL_UINT(1, rig.prepared);
    TEST_ASSERT_EQUAL_UINT(5, rig.lock.requests().size());
    TEST_ASSERT_FALSE(rig.result.adminPasscodeConfirmed);
}
static void test_confirmed_pairing_finishes_durable_verdict_before_password_initialization() {
    for (const bool explicitCode : {false, true}) {
        Rig rig;
        if (explicitCode) rig.options.adminPasscode = "2468135";
        rig.tail();
        TEST_ASSERT_EQUAL_INT(static_cast<int>(Status::Ok), static_cast<int>(rig.pair()));
        TEST_ASSERT_EQUAL_UINT(1, rig.prepared);
        TEST_ASSERT_EQUAL_UINT(1, rig.finished);
        TEST_ASSERT_TRUE(rig.accepted);
        TEST_ASSERT_TRUE(rig.result.adminPasscodeConfirmed);
        TEST_ASSERT_TRUE(ttlock::isPasscode(rig.candidate));
        TEST_ASSERT_TRUE(!explicitCode || rig.options.adminPasscode == rig.candidate);
    }
}
static void test_timeout_leaves_candidate_unresolved_and_pairing_unconfirmed() {
    Rig rig;
    rig.tail(false);
    TEST_ASSERT_EQUAL_INT(static_cast<int>(Status::Ok), static_cast<int>(rig.pair()));
    TEST_ASSERT_EQUAL_UINT(1, rig.prepared);
    TEST_ASSERT_EQUAL_UINT(0, rig.finished);
    TEST_ASSERT_FALSE(rig.result.adminPasscodeConfirmed);
}
static void test_confirmed_verdict_storage_failure_stops_later_mutations() {
    Rig rig;
    rig.tail();
    rig.allowFinish = false;
    TEST_ASSERT_EQUAL_INT(static_cast<int>(Status::PairIncomplete), static_cast<int>(rig.pair()));
    TEST_ASSERT_EQUAL_UINT(6, rig.lock.requests().size());
    TEST_ASSERT_FALSE(rig.result.adminPasscodeConfirmed);
}
static void test_lock_refusal_finishes_rejected_candidate() {
    Rig rig;
    rig.tail(true, true);
    TEST_ASSERT_EQUAL_INT(static_cast<int>(Status::PairIncomplete), static_cast<int>(rig.pair()));
    TEST_ASSERT_EQUAL_UINT(1, rig.finished);
    TEST_ASSERT_FALSE(rig.accepted);
    TEST_ASSERT_EQUAL_UINT(6, rig.lock.requests().size());
}
int main() {
    UNITY_BEGIN();
    RUN_TEST(test_failed_candidate_storage_stops_before_admin_write);
    RUN_TEST(test_confirmed_pairing_finishes_durable_verdict_before_password_initialization);
    RUN_TEST(test_timeout_leaves_candidate_unresolved_and_pairing_unconfirmed);
    RUN_TEST(test_confirmed_verdict_storage_failure_stops_later_mutations);
    RUN_TEST(test_lock_refusal_finishes_rejected_candidate);
    return UNITY_END();
}
