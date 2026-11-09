// SPDX-License-Identifier: GPL-3.0-or-later
#include <unity.h>

#include <cstdint>
#include <vector>

#include "../fake_lock/fake_lock.h"
#include "ttlock/commands.h"
#include "ttlock/features.h"
#include "ttlock/session.h"

namespace {

class DelayedLock : public fake::FakeLock {
public:
    uint8_t delayedCommand = ttlock::command::kConfigurePassageMode;
    uint32_t delayMs = 6100;
    uint32_t lastTimeoutMs = 0;

    ttlock::Status receive(ttlock::Bytes& frame, uint32_t timeoutMs) override {
        lastTimeoutMs = timeoutMs;
        if (!requests().empty() && requests().back().command == delayedCommand && timeoutMs < delayMs) {
            return ttlock::Status::Timeout;
        }
        return FakeLock::receive(frame, timeoutMs);
    }
};

struct PassageRig {
    DelayedLock lock;
    fake::FakeClock clock;
    fake::FakeRandom random;
    ttlock::Session session{lock, clock, random};
    ttlock::LockKeys keys;
    ttlock::PassageMode mode{ttlock::PassageType::Weekly, 4, 0, 3, 17, 3, 41};

    PassageRig() {
        keys.version = fake::kRequestVersion;
        keys.aesKey.fill(0x42);
        keys.features = ttlock::featureBit(ttlock::Feature::PassageMode);
        TEST_ASSERT_EQUAL_INT(static_cast<int>(ttlock::Status::Ok), static_cast<int>(session.attach(keys)));
        lock.expect(ttlock::command::kCheckAdmin, keys.aesKey,
                    {fake::success(keys.aesKey, ttlock::command::kCheckAdmin, fake::be32(0x11223344))});
        lock.expect(ttlock::command::kCheckRandom, keys.aesKey,
                    {fake::success(keys.aesKey, ttlock::command::kCheckRandom)});
        lock.expect(ttlock::command::kConfigurePassageMode, keys.aesKey,
                    {fake::success(keys.aesKey, ttlock::command::kConfigurePassageMode)});
    }
};

void test_passage_add_waits_for_a_slow_ack_without_resending() {
    PassageRig rig;
    TEST_ASSERT_EQUAL_INT(static_cast<int>(ttlock::Status::Ok), static_cast<int>(rig.session.passageAdd(rig.mode)));
    TEST_ASSERT_EQUAL_UINT32(3, rig.lock.requests().size());
    TEST_ASSERT_TRUE(rig.lock.scriptDone());
    TEST_ASSERT_EQUAL_UINT32(10000, rig.lock.lastTimeoutMs);
}

void test_passage_add_still_times_out_when_no_ack_arrives_in_ten_seconds() {
    PassageRig rig;
    rig.lock.delayMs = 10001;
    TEST_ASSERT_EQUAL_INT(static_cast<int>(ttlock::Status::Timeout),
                          static_cast<int>(rig.session.passageAdd(rig.mode)));
    TEST_ASSERT_EQUAL_UINT32(3, rig.lock.requests().size());
}

void test_passage_authentication_keeps_its_five_second_deadline() {
    PassageRig rig;
    rig.lock.delayedCommand = ttlock::command::kCheckAdmin;
    TEST_ASSERT_EQUAL_INT(static_cast<int>(ttlock::Status::Timeout),
                          static_cast<int>(rig.session.passageAdd(rig.mode)));
    TEST_ASSERT_EQUAL_UINT32(1, rig.lock.requests().size());
    TEST_ASSERT_EQUAL_UINT32(5000, rig.lock.lastTimeoutMs);
}

void test_passage_reads_keep_their_five_second_deadline() {
    PassageRig rig;
    std::vector<ttlock::PassageMode> modes;
    TEST_ASSERT_EQUAL_INT(static_cast<int>(ttlock::Status::Timeout), static_cast<int>(rig.session.passageList(modes)));
    TEST_ASSERT_EQUAL_UINT32(5000, rig.lock.lastTimeoutMs);
}

void test_passage_deletion_keeps_its_five_second_deadline() {
    PassageRig rig;
    TEST_ASSERT_EQUAL_INT(static_cast<int>(ttlock::Status::Timeout),
                          static_cast<int>(rig.session.passageDelete(rig.mode)));
    TEST_ASSERT_EQUAL_UINT32(5000, rig.lock.lastTimeoutMs);
}

void test_passage_clear_keeps_its_five_second_deadline() {
    PassageRig rig;
    TEST_ASSERT_EQUAL_INT(static_cast<int>(ttlock::Status::Timeout), static_cast<int>(rig.session.passageClear()));
    TEST_ASSERT_EQUAL_UINT32(5000, rig.lock.lastTimeoutMs);
}

}

void setUp() {}
void tearDown() {}

int main() {
    UNITY_BEGIN();
    RUN_TEST(test_passage_add_waits_for_a_slow_ack_without_resending);
    RUN_TEST(test_passage_add_still_times_out_when_no_ack_arrives_in_ten_seconds);
    RUN_TEST(test_passage_authentication_keeps_its_five_second_deadline);
    RUN_TEST(test_passage_reads_keep_their_five_second_deadline);
    RUN_TEST(test_passage_deletion_keeps_its_five_second_deadline);
    RUN_TEST(test_passage_clear_keeps_its_five_second_deadline);
    return UNITY_END();
}
