// SPDX-License-Identifier: GPL-3.0-or-later
#include "lock_manager_test_runtime.h"
#include "../reference/backup_fixture.h"
#include "../fake_lock/fake_lock.h"

#include <future>

using ttlock::Status;
static constexpr int64_t kUtc = 1762524000;

void setUp() {
    resetManagerFixture();
    const auto decoded = backup_fixture::make();
    store::locks::Record record;
    TEST_ASSERT_TRUE(key_store::makeRecord(decoded.locks()[0], record));
    TEST_ASSERT_EQUAL_INT(ESP_OK, lock_manager::persist(record));
    auto& state = lock_manager::findLocked(kMac)->live.watch.state();
    state.baselined = true;
    state.cursor = 10;
    TEST_ASSERT_EQUAL_INT(ESP_OK, store::watch::save(kMac.data(), state));
    monitoringWrites.clear();
}

void tearDown() { clearManagerFixture(); }

static ttlock::Bytes page(bool own = false, bool undated = false) {
    ttlock::Bytes body{0, static_cast<uint8_t>(own ? 12 : 11)};
    if (own) {
        const auto record = fake::concat({ttlock::Bytes{1, 25, 11, 7, 14, 0, 0, 90}, fake::be32(0), fake::be32(123)});
        body.push_back(record.size());
        body.insert(body.end(), record.begin(), record.end());
    }
    const ttlock::Bytes record{29, 25, static_cast<uint8_t>(undated ? 0 : 11), 7, 14, 0, 0, 90};
    body.push_back(record.size());
    body.insert(body.end(), record.begin(), record.end());
    return fake::concat({ttlock::Bytes{0, static_cast<uint8_t>(body.size())}, body});
}

struct Rig {
    fake::FakeLock radio;
    fake::FakeClock clock;
    fake::FakeRandom random;
    ttlock::Session session{radio, clock, random};
    ttlock::LockKeys keys = lock_manager::keysOf(lock_manager::findLocked(kMac)->record);

    Rig() { TEST_ASSERT_EQUAL_INT(Status::Ok, session.attach(keys)); }

    void expect(const ttlock::Bytes& bytes, bool end) {
        radio.expect(ttlock::command::kGetOperateLog, keys.aesKey,
                     {fake::success(keys.aesKey, ttlock::command::kGetOperateLog, bytes)});
        if (end) radio.expect(ttlock::command::kGetOperateLog, keys.aesKey,
                             {fake::success(keys.aesKey, ttlock::command::kGetOperateLog, {0, 0})});
    }

    Status read(bool own = false, bool undated = false, bool succeeds = true, int64_t now = kUtc) {
        lock_manager::WatchView view;
        TEST_ASSERT_TRUE(lock_manager::watchView(std::string(kMac), view));
        expect(page(own, undated), succeeds);
        lock_log::Entries entries;
        bool more = false;
        const auto status = lock_log::catchUp(session, std::string(kMac), 0, view.watch, entries, more, now);
        lock_manager::keepWatch(std::string(kMac), view, status == Status::Ok, more);
        TEST_ASSERT_TRUE(radio.scriptDone());
        return status;
    }
};

static void reboot() {
    lock_manager::s_locks = {};
    lock_manager::s_lockCount = 0;
    lock_manager::start();
}

static void test_failed_alert_save_keeps_cursor_and_unlock_ledger_until_retry() {
    Rig rig;
    auto& live = lock_manager::findLocked(kMac)->live;
    live.watch.noteUnlock(kUtc, kUtc, 123);
    s_failWrite = s_writes + 1;
    TEST_ASSERT_EQUAL_INT(Status::Busy, rig.read(true, false, false));
    TEST_ASSERT_EQUAL_UINT(10, live.watch.state().cursor);
    TEST_ASSERT_EQUAL_UINT(1, live.watch.unlocks());
    TEST_ASSERT_TRUE(live.alertWriteFailed);
    TEST_ASSERT_EQUAL_UINT(1, monitoringWrites.size());
    TEST_ASSERT_TRUE(monitoringWrites[0] == "alerts");
    s_failWrite = 0;
    TEST_ASSERT_EQUAL_INT(Status::Ok, rig.read(true));
    TEST_ASSERT_EQUAL_UINT(12, live.watch.state().cursor);
    TEST_ASSERT_EQUAL_UINT(0, live.watch.unlocks());
    TEST_ASSERT_FALSE(live.alertWriteFailed);
    TEST_ASSERT_EQUAL_UINT(1, live.alerts.entries().size());
    TEST_ASSERT_TRUE(monitoringWrites == (std::vector<std::string>{"alerts", "alerts", "watch"}));
}

static void test_acknowledgement_refuses_an_alert_that_is_not_durable() {
    Rig rig;
    s_failWrite = s_writes + 1;
    TEST_ASSERT_EQUAL_INT(Status::Busy, rig.read(false, false, false));
    s_failWrite = 0;
    const auto writes = s_writes;
    const auto reply = lock_manager::acknowledgeAlerts(std::string(kMac), 1);
    TEST_ASSERT_EQUAL_STRING("storage_error", reply.error.c_str());
    TEST_ASSERT_EQUAL_UINT(writes, s_writes);
    TEST_ASSERT_EQUAL_UINT(1, lock_manager::findLocked(kMac)->live.alerts.entries().size());
}

static void test_failed_cursor_save_cannot_be_acknowledged_and_replayed_after_reboot() {
    Rig rig;
    s_failWrite = s_writes + 2;
    TEST_ASSERT_EQUAL_INT(Status::Ok, rig.read());
    TEST_ASSERT_TRUE(lock_manager::findLocked(kMac)->live.watchWriteFailed);
    s_failWrite = 0;
    const auto reply = lock_manager::acknowledgeAlerts(std::string(kMac), 1);
    TEST_ASSERT_EQUAL_STRING("storage_error", reply.error.c_str());
    reboot();
    TEST_ASSERT_EQUAL_UINT(10, lock_manager::findLocked(kMac)->live.watch.state().cursor);
    TEST_ASSERT_EQUAL_UINT(1, lock_manager::findLocked(kMac)->live.alerts.entries().size());
    const auto beforeRetry = lock_manager::acknowledgeAlerts(std::string(kMac), 1);
    TEST_ASSERT_EQUAL_STRING("storage_error", beforeRetry.error.c_str());
    Rig retry;
    TEST_ASSERT_EQUAL_INT(Status::Ok, retry.read());
    TEST_ASSERT_EQUAL_UINT(1, lock_manager::findLocked(kMac)->live.alerts.entries().size());
    TEST_ASSERT_TRUE(lock_manager::acknowledgeAlerts(std::string(kMac), 1).error.empty());
    reboot();
    TEST_ASSERT_EQUAL_UINT(11, lock_manager::findLocked(kMac)->live.watch.state().cursor);
    TEST_ASSERT_TRUE(lock_manager::findLocked(kMac)->live.alerts.entries().empty());
}

static void test_undated_alert_identity_is_stable_across_cursor_failure_and_reboot() {
    Rig rig;
    s_failWrite = s_writes + 2;
    TEST_ASSERT_EQUAL_INT(Status::Ok, rig.read(false, true));
    s_failWrite = 0;
    reboot();
    Rig retry;
    TEST_ASSERT_EQUAL_INT(Status::Ok, retry.read(false, true, true, kUtc + 60));
    const auto entries = lock_manager::findLocked(kMac)->live.alerts.entries();
    TEST_ASSERT_EQUAL_UINT(1, entries.size());
    TEST_ASSERT_EQUAL_UINT(0, entries[0].time);
}

static void test_acknowledgement_waits_for_active_catchup_to_persist_its_cursor() {
    Rig rig;
    managerBusy = true;
    lock_manager::WatchView view;
    TEST_ASSERT_TRUE(lock_manager::watchView(std::string(kMac), view));
    rig.expect(page(), true);
    lock_log::Entries entries;
    bool more = false;
    TEST_ASSERT_EQUAL_INT(Status::Ok, lock_log::catchUp(rig.session, std::string(kMac), 0,
                                                      view.watch, entries, more, kUtc));
    auto reply = std::async(std::launch::async, [] { return lock_manager::acknowledgeAlerts(std::string(kMac), 1); });
    bool queued = false;
    const auto deadline = std::chrono::steady_clock::now() + std::chrono::seconds(2);
    while (std::chrono::steady_clock::now() < deadline) {
        {
            std::lock_guard<std::mutex> guard(lock_manager::s_mutex);
            queued = !lock_manager::s_queue.empty();
        }
        if (queued || reply.wait_for(std::chrono::milliseconds(0)) == std::future_status::ready) break;
        std::this_thread::yield();
    }
    lock_manager::keepWatch(std::string(kMac), view, true, false);
    managerBusy = false;
    ble::wake();
    const auto result = reply.get();
    TEST_ASSERT_TRUE(queued);
    TEST_ASSERT_TRUE(result.error.empty());
    TEST_ASSERT_TRUE(monitoringWrites == (std::vector<std::string>{"alerts", "watch", "alerts"}));
    reboot();
    TEST_ASSERT_EQUAL_UINT(11, lock_manager::findLocked(kMac)->live.watch.state().cursor);
    TEST_ASSERT_TRUE(lock_manager::findLocked(kMac)->live.alerts.entries().empty());
}

static void test_failed_acknowledgement_can_be_retried_without_new_log_entries() {
    Rig rig;
    TEST_ASSERT_EQUAL_INT(Status::Ok, rig.read());
    for (bool mutated : {false, true}) {
        s_failAfter = mutated;
        s_failWrite = s_writes + 1;
        const auto failed = lock_manager::acknowledgeAlerts(std::string(kMac), 1);
        TEST_ASSERT_EQUAL_STRING("internal", failed.error.c_str());
        TEST_ASSERT_EQUAL_UINT(1, lock_manager::findLocked(kMac)->live.alerts.entries().size());
    }
    s_failWrite = 0;
    TEST_ASSERT_TRUE(lock_manager::acknowledgeAlerts(std::string(kMac), 1).error.empty());
    reboot();
    TEST_ASSERT_TRUE(lock_manager::findLocked(kMac)->live.alerts.entries().empty());
    TEST_ASSERT_EQUAL_UINT(11, lock_manager::findLocked(kMac)->live.watch.state().cursor);
}

static void test_strict_catchup_does_not_publish_failed_alert_or_watch_progress() {
    Rig rig;
    lock_manager::WatchView view;
    TEST_ASSERT_TRUE(lock_manager::watchView(std::string(kMac), view));
    rig.expect(page(), false);
    s_failWrite = s_writes + 1;
    lock_log::Entries entries;
    bool more = false;
    const auto status = lock_log::catchUp(rig.session, std::string(kMac), 0,
                                         view.watch, entries, more, kUtc, true);
    TEST_ASSERT_EQUAL_INT(Status::Busy, status);
    TEST_ASSERT_EQUAL_UINT(10, view.watch.state().cursor);
    TEST_ASSERT_TRUE(entries.items().empty());
    TEST_ASSERT_TRUE(lock_manager::findLocked(kMac)->live.alerts.entries().empty());
    TEST_ASSERT_TRUE(monitoringWrites == (std::vector<std::string>{"alerts"}));
}

static void test_reboot_rechecks_wrapped_and_restarted_alerts_before_allowing_acknowledgement() {
    for (bool wrapped : {true, false}) {
        auto& live = lock_manager::findLocked(kMac)->live;
        live.alerts = {};
        latchkey_util::LockAlert alert;
        alert.seq = wrapped ? 65535 : 0;
        alert.time = wrapped ? 0 : kUtc + 1;
        alert.type = 29;
        alert.method = latchkey_util::UnlockMethod::Forced;
        TEST_ASSERT_TRUE(live.alerts.add(alert));
        live.watch.state().cursor = wrapped ? 1 : 100;
        live.watch.state().lastUtc = kUtc;
        TEST_ASSERT_EQUAL_INT(ESP_OK, store::alerts::save(kMac.data(), live.alerts));
        TEST_ASSERT_EQUAL_INT(ESP_OK, store::watch::save(kMac.data(), live.watch.state()));
        reboot();
        TEST_ASSERT_EQUAL_STRING("storage_error", lock_manager::acknowledgeAlerts(std::string(kMac), 1).error.c_str());
        Rig rig;
        rig.expect({0, 0}, false);
        TEST_ASSERT_EQUAL_INT(Status::Ok, lock_manager::readBeforeClock(rig.session, std::string(kMac)));
        TEST_ASSERT_TRUE(lock_manager::acknowledgeAlerts(std::string(kMac), 1).error.empty());
        reboot();
        TEST_ASSERT_TRUE(lock_manager::findLocked(kMac)->live.alerts.entries().empty());
    }
}

static void test_genuine_log_restart_releases_old_high_sequence_alerts_after_catchup() {
    auto& live = lock_manager::findLocked(kMac)->live;
    latchkey_util::LockAlert old;
    old.seq = 65535;
    old.time = kUtc;
    old.type = 29;
    old.method = latchkey_util::UnlockMethod::Forced;
    TEST_ASSERT_TRUE(live.alerts.add(old));
    live.watch.state().cursor = 65535;
    live.watch.state().lastUtc = kUtc;
    TEST_ASSERT_EQUAL_INT(ESP_OK, store::alerts::save(kMac.data(), live.alerts));
    TEST_ASSERT_EQUAL_INT(ESP_OK, store::watch::save(kMac.data(), live.watch.state()));
    reboot();
    TEST_ASSERT_EQUAL_STRING("storage_error", lock_manager::acknowledgeAlerts(std::string(kMac), 1).error.c_str());
    Rig rig;
    auto restarted = page();
    restarted[3] = 1;
    restarted[11] = 1;
    rig.expect(restarted, true);
    TEST_ASSERT_EQUAL_INT(Status::Ok, lock_manager::readBeforeClock(rig.session, std::string(kMac)));
    TEST_ASSERT_EQUAL_UINT(1, lock_manager::findLocked(kMac)->live.watch.state().cursor);
    TEST_ASSERT_EQUAL_UINT(kUtc + 1, lock_manager::findLocked(kMac)->live.watch.state().lastUtc);
    TEST_ASSERT_TRUE(lock_manager::acknowledgeAlerts(std::string(kMac), 1).error.empty());
    reboot();
    const auto entries = lock_manager::findLocked(kMac)->live.alerts.entries();
    TEST_ASSERT_EQUAL_UINT(1, entries.size());
    TEST_ASSERT_EQUAL_UINT(0, entries[0].seq);
    TEST_ASSERT_EQUAL_UINT(2, entries[0].id);
}

static void test_undated_alert_after_epoch_reset_waits_for_catchup_after_reboot() {
    auto& state = lock_manager::findLocked(kMac)->live.watch.state();
    state.cursor = 100;
    state.lastUtc = kUtc;
    TEST_ASSERT_EQUAL_INT(ESP_OK, store::watch::save(kMac.data(), state));
    Rig rig;
    auto reset = page();
    reset[3] = 1;
    reset[5] = 36;
    reset[11] = 1;
    auto undated = page(false, true);
    undated[3] = 2;
    rig.expect(reset, false);
    rig.expect(undated, true);
    s_failWrite = s_writes + 2;
    TEST_ASSERT_EQUAL_INT(Status::Ok, lock_manager::readBeforeClock(rig.session, std::string(kMac)));
    TEST_ASSERT_EQUAL_UINT(2, lock_manager::findLocked(kMac)->live.watch.state().cursor);
    TEST_ASSERT_TRUE(lock_manager::findLocked(kMac)->live.watchWriteFailed);
    s_failWrite = 0;
    reboot();
    TEST_ASSERT_EQUAL_UINT(100, lock_manager::findLocked(kMac)->live.watch.state().cursor);
    TEST_ASSERT_EQUAL_UINT(1, lock_manager::findLocked(kMac)->live.alerts.entries().size());
    TEST_ASSERT_EQUAL_UINT(0, lock_manager::findLocked(kMac)->live.alerts.entries()[0].time);
    TEST_ASSERT_EQUAL_STRING("storage_error", lock_manager::acknowledgeAlerts(std::string(kMac), 1).error.c_str());
    Rig retry;
    retry.expect(reset, false);
    retry.expect(undated, true);
    TEST_ASSERT_EQUAL_INT(Status::Ok, lock_manager::readBeforeClock(retry.session, std::string(kMac)));
    TEST_ASSERT_EQUAL_UINT(1, lock_manager::findLocked(kMac)->live.alerts.entries().size());
    TEST_ASSERT_TRUE(lock_manager::acknowledgeAlerts(std::string(kMac), 1).error.empty());
}

int main() {
    rpc::init();
    UNITY_BEGIN();
    RUN_TEST(test_failed_alert_save_keeps_cursor_and_unlock_ledger_until_retry);
    RUN_TEST(test_acknowledgement_refuses_an_alert_that_is_not_durable);
    RUN_TEST(test_failed_cursor_save_cannot_be_acknowledged_and_replayed_after_reboot);
    RUN_TEST(test_undated_alert_identity_is_stable_across_cursor_failure_and_reboot);
    RUN_TEST(test_acknowledgement_waits_for_active_catchup_to_persist_its_cursor);
    RUN_TEST(test_failed_acknowledgement_can_be_retried_without_new_log_entries);
    RUN_TEST(test_strict_catchup_does_not_publish_failed_alert_or_watch_progress);
    RUN_TEST(test_reboot_rechecks_wrapped_and_restarted_alerts_before_allowing_acknowledgement);
    RUN_TEST(test_genuine_log_restart_releases_old_high_sequence_alerts_after_catchup);
    RUN_TEST(test_undated_alert_after_epoch_reset_waits_for_catchup_after_reboot);
    return UNITY_END();
}
