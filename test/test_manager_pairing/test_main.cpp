// SPDX-License-Identifier: GPL-3.0-or-later
#include "latchkey_util/key_restore.h"
#include "lock_manager_test_runtime.h"
#include "../fake_lock/fake_lock.h"
#include "ttlock/commands.h"

namespace cmd = ttlock::command;
using latchkey_util::AdminProvenance;
struct Rig {
    fake::FakeLock lock;
    ttlock::AesKey key{};
    Rig(bool ack) {
        fixtureClockSynced = true;
        bluetoothReady = true;
        fixtureTransport = &lock;
        receiveAdvert = [&](ble::Message& message) {
            message.kind = ble::Message::Kind::Advert;
            message.advert = {};
            const uint8_t bytes[]{18, 0xFF, 5, 3, 2, 4, 80, 0, 0, 0, 0, 0, 0, 1, 0x53, 0, 0x5E, 0, 0};
            std::copy(std::begin(bytes), std::end(bytes), message.advert.data);
            message.advert.length = sizeof(bytes);
            return true;
        };
        key.fill(0x42);
        lock.expect(cmd::kInitialization, ttlock::kDefaultAesKey, {fake::success(ttlock::kDefaultAesKey, cmd::kInitialization)});
        lock.expect(cmd::kGetAesKey, ttlock::kDefaultAesKey, {fake::success(ttlock::kDefaultAesKey, cmd::kGetAesKey, {key.begin(), key.end()})});
        lock.expect(cmd::kAddAdmin, key, {fake::success(key, cmd::kAddAdmin, fake::text("SCIENER"))});
        lock.expect(cmd::kTimeCalibrate, key, {fake::success(key, cmd::kTimeCalibrate)});
        lock.expect(cmd::kSearchDeviceFeature, key, {fake::success(key, cmd::kSearchDeviceFeature, {0, 0, 0, 0, 0})});
        lock.expect(cmd::kSetAdminKeyboardPassword, key, ack ? std::vector<ttlock::Bytes>{fake::success(key, cmd::kSetAdminKeyboardPassword)} : std::vector<ttlock::Bytes>{});
        lock.expect(cmd::kInitPasswords, key, {fake::success(key, cmd::kInitPasswords)});
        lock.expect(cmd::kOperateFinished, key, {fake::success(key, cmd::kOperateFinished)});
    }
};
void setUp() { resetManagerFixture(); }
void tearDown() { clearManagerFixture(); }
static void test_confirmed_pairing_classifies_explicit_and_generated_codes() {
    for (const bool generated : {false, true}) {
        resetManagerFixture();
        Rig rig(true);
        const auto reply = lock_manager::pair(std::string(kMac), "Entry", 1, generated ? "" : "2468135");
        TEST_ASSERT_TRUE(reply.error.empty());
        lock_manager::AdminState state;
        TEST_ASSERT_EQUAL_INT(ESP_OK, lock_manager::readAdminState(std::string(kMac), state));
        TEST_ASSERT_EQUAL_INT(static_cast<int>(generated ? AdminProvenance::PairingGenerated : AdminProvenance::Owner), static_cast<int>(state.metadata.provenance));
        TEST_ASSERT_TRUE(ttlock::isPasscode(state.record.adminPasscode));
        TEST_ASSERT_TRUE((state.record.flags & store::locks::kFlagAdminPasscodeConfirmed) != 0);
        TEST_ASSERT_TRUE(state.metadata.pendingAdminPasscode[0] == 0);
        TEST_ASSERT_EQUAL_UINT(0, state.metadata.lifecycle);
    }
}
static void test_unconfirmed_pairing_retains_candidate_separately_after_restart() {
    Rig rig(false);
    const auto reply = lock_manager::pair(std::string(kMac), "Entry", 1, {});
    TEST_ASSERT_TRUE(reply.error.empty());
    lock_manager::s_locks = {};
    lock_manager::s_lockCount = 0;
    lock_manager::start();
    lock_manager::AdminState state;
    TEST_ASSERT_EQUAL_INT(ESP_OK, lock_manager::readAdminState(std::string(kMac), state));
    TEST_ASSERT_TRUE(state.record.adminPasscode[0] == 0);
    TEST_ASSERT_FALSE((state.record.flags & store::locks::kFlagAdminPasscodeConfirmed) != 0);
    TEST_ASSERT_EQUAL_INT(static_cast<int>(AdminProvenance::LegacyUnknown), static_cast<int>(state.metadata.provenance));
    TEST_ASSERT_TRUE(ttlock::isPasscode(state.metadata.pendingAdminPasscode.data()));
    TEST_ASSERT_EQUAL_INT(static_cast<int>(AdminProvenance::PairingGenerated), static_cast<int>(state.metadata.pendingProvenance));
}
int main() {
    rpc::init();
    UNITY_BEGIN();
    RUN_TEST(test_confirmed_pairing_classifies_explicit_and_generated_codes);
    RUN_TEST(test_unconfirmed_pairing_retains_candidate_separately_after_restart);
    return UNITY_END();
}
