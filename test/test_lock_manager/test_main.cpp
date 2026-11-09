// SPDX-License-Identifier: GPL-3.0-or-later
#include "latchkey_util/key_restore.h"
#include "lock_manager_test_runtime.h"
#include "../reference/backup_fixture.h"

void setUp() { resetManagerFixture(); }
void tearDown() { clearManagerFixture(); }

static latchkey_util::RestoreStatus restore(const latchkey_util::DecodedBackup& decoded) {
    auto status = latchkey_util::RestoreStatus::Invalid;
    auto reply = lock_manager::runStorage("fixture.restore", [&](auto& storage, auto& publication) {
        status = latchkey_util::restoreKeys(decoded, storage, publication);
        return rpc::ok();
    });
    TEST_ASSERT_TRUE(reply.error.empty());
    return status;
}

static size_t visibleLocks() {
    const auto reply = lock_manager::list();
    return cJSON_GetArraySize(cJSON_GetObjectItemCaseSensitive(reply.result.get(), "locks"));
}

static void test_restored_locks_are_published_together_with_metadata_and_pending_state() {
    const auto decoded = backup_fixture::make(2);
    TEST_ASSERT_EQUAL_INT(static_cast<int>(latchkey_util::RestoreStatus::Ok), static_cast<int>(restore(decoded)));
    TEST_ASSERT_EQUAL_UINT(2, visibleLocks());
    for (const auto& lock : decoded.locks()) {
        store::locks::Record record;
        TEST_ASSERT_TRUE(lock_manager::record(std::string(lock.mac), record));
        TEST_ASSERT_TRUE(std::equal(lock.aesKey.begin(), lock.aesKey.end(), record.aesKey));
        TEST_ASSERT_TRUE(std::equal(lock.address.begin(), lock.address.end(), record.address));
        latchkey_util::LockMetadata metadata;
        TEST_ASSERT_EQUAL_INT(ESP_OK, key_store::loadMetadata(lock.mac, metadata));
        TEST_ASSERT_TRUE(std::string_view(metadata.pendingAdminPasscode.data()) == lock.pendingAdminPasscode);
    }
    const auto reply = lock_manager::list();
    const auto* locks = cJSON_GetObjectItemCaseSensitive(reply.result.get(), "locks");
    for (size_t i = 0; i < 2; ++i) {
        const auto* lock = cJSON_GetArrayItem(locks, i);
        TEST_ASSERT_TRUE(cJSON_IsTrue(cJSON_GetObjectItemCaseSensitive(lock, "backedUp")));
        TEST_ASSERT_TRUE(cJSON_IsTrue(cJSON_GetObjectItemCaseSensitive(lock, "hardened")));
    }
    TEST_ASSERT_EQUAL_UINT(0, bluetoothCalls);
}

static void test_failed_restore_publishes_nothing_and_existing_objects_survive() {
    const auto one = backup_fixture::make();
    TEST_ASSERT_EQUAL_INT(static_cast<int>(latchkey_util::RestoreStatus::Ok), static_cast<int>(restore(one)));
    const auto* existing = lock_manager::findLocked(kMac);
    auto source = backup_fixture::make(2);
    latchkey_util::SensitiveBuffer plaintext;
    TEST_ASSERT_EQUAL_INT(static_cast<int>(latchkey_util::BackupStatus::Ok),
                          static_cast<int>(latchkey_util::encodeBackup(source.locks().subspan(1), plaintext)));
    latchkey_util::DecodedBackup second;
    TEST_ASSERT_EQUAL_INT(static_cast<int>(latchkey_util::BackupStatus::Ok),
                          static_cast<int>(latchkey_util::decodeBackup(std::move(plaintext), second)));
    s_failWrite = s_writes + 4;
    TEST_ASSERT_EQUAL_INT(static_cast<int>(latchkey_util::RestoreStatus::WriteFailed), static_cast<int>(restore(second)));
    TEST_ASSERT_EQUAL_UINT(1, visibleLocks());
    TEST_ASSERT_EQUAL_PTR(existing, lock_manager::findLocked(kMac));
    s_failWrite = 0;
    TEST_ASSERT_EQUAL_INT(static_cast<int>(latchkey_util::RestoreStatus::Ok), static_cast<int>(restore(second)));
    TEST_ASSERT_EQUAL_UINT(2, visibleLocks());
    TEST_ASSERT_EQUAL_PTR(existing, lock_manager::findLocked(kMac));
}

static void test_storage_job_runs_without_bluetooth_and_holds_the_manager_mutex() {
    bool called = false;
    bool mutexHeld = false;
    auto reply = lock_manager::runStorage("fixture.storage", [&](auto&, auto&) {
        called = true;
        std::thread observer([&] {
            mutexHeld = !lock_manager::s_mutex.try_lock();
            if (!mutexHeld) lock_manager::s_mutex.unlock();
        });
        observer.join();
        return rpc::ok();
    });
    TEST_ASSERT_TRUE(reply.error.empty());
    TEST_ASSERT_TRUE(called);
    TEST_ASSERT_TRUE(mutexHeld);
    TEST_ASSERT_EQUAL_UINT(0, bluetoothCalls);
}

static void test_storage_job_waits_until_the_active_pairing_job_finishes() {
    bluetoothReady = true;
    std::mutex gate;
    std::condition_variable changed;
    bool pairing = false;
    bool release = false;
    bool stored = false;
    receiveAdvert = [&](ble::Message&) {
        std::unique_lock<std::mutex> lock(gate);
        pairing = true;
        changed.notify_all();
        changed.wait(lock, [&] { return release; });
        return false;
    };
    rpc::Reply paired;
    std::thread pairingThread([&] { paired = lock_manager::pair(std::string(kMac), "Entry", 1, {}); });
    {
        std::unique_lock<std::mutex> lock(gate);
        TEST_ASSERT_TRUE(changed.wait_for(lock, std::chrono::seconds(2), [&] { return pairing; }));
    }
    rpc::Reply backedUp;
    std::thread storageThread([&] {
        backedUp = lock_manager::runStorage("fixture.storage", [&](auto&, auto&) {
            std::lock_guard<std::mutex> lock(gate);
            stored = true;
            return rpc::ok();
        });
    });
    while (lock_manager::queueIdle()) std::this_thread::yield();
    {
        std::lock_guard<std::mutex> lock(gate);
        TEST_ASSERT_FALSE(stored);
        release = true;
        changed.notify_all();
    }
    pairingThread.join();
    storageThread.join();
    TEST_ASSERT_EQUAL_STRING("timeout", paired.error.c_str());
    TEST_ASSERT_TRUE(backedUp.error.empty());
    TEST_ASSERT_TRUE(stored);
}

static void test_every_import_publication_allocation_failure_precedes_all_writes() {
    const auto decoded = backup_fixture::make(2);
    for (size_t at = 1; at <= 2; ++at) {
        allocation_failure::attempts = 0;
        allocation_failure::failAt = at;
        const auto status = restore(decoded);
        allocation_failure::resume();
        TEST_ASSERT_EQUAL_INT(static_cast<int>(latchkey_util::RestoreStatus::NoMemory), static_cast<int>(status));
        TEST_ASSERT_EQUAL_UINT(0, s_writes);
        TEST_ASSERT_EQUAL_UINT(0, visibleLocks());
        TEST_ASSERT_TRUE(std::all_of(lock_manager::s_locks.begin(), lock_manager::s_locks.end(),
                                     [](const auto& lock) { return !lock; }));
    }
    TEST_ASSERT_EQUAL_INT(static_cast<int>(latchkey_util::RestoreStatus::Ok), static_cast<int>(restore(decoded)));
    TEST_ASSERT_EQUAL_UINT(2, visibleLocks());
}

static void test_recovery_required_remains_latched_across_requests_and_blocks_every_storage_mutation() {
    const auto decoded = backup_fixture::make();
    TEST_ASSERT_EQUAL_INT(static_cast<int>(latchkey_util::RestoreStatus::Ok), static_cast<int>(restore(decoded)));
    latchkey_util::RestoreJournal journal;
    journal.count = 1;
    std::memcpy(journal.identities[0].data(), "00:00:5E:00:53:09", 18);
    key_store::Restore storage;
    TEST_ASSERT_TRUE(storage.writeJournal(journal));
    TEST_ASSERT_EQUAL_INT(static_cast<int>(latchkey_util::RestoreStatus::RecoveryRequired),
                          static_cast<int>(restore(decoded)));
    TEST_ASSERT_TRUE(storage.clearJournal());
    const auto before = s_namespaces;
    s_writes = 0;
    const std::string mac(kMac);
    TEST_ASSERT_FALSE(lock_manager::rename(mac, "Changed").error.empty());
    TEST_ASSERT_FALSE(lock_manager::forget(mac).error.empty());
    lock_manager::AdminPasscodeCopy previous;
    TEST_ASSERT_FALSE(lock_manager::stageAdminPasscode(mac, "246813579", previous));
    TEST_ASSERT_FALSE(lock_manager::confirmAdminPasscode(mac));
    TEST_ASSERT_FALSE(lock_manager::restoreAdminPasscode(mac, previous));
    latchkey_util::LabelTable labels;
    TEST_ASSERT_NOT_EQUAL(ESP_OK, lock_manager::saveLabels(mac, store::labels::Kind::Passcodes, labels));
    TEST_ASSERT_NOT_EQUAL(ESP_OK, lock_manager::eraseAll());
    lock_manager::cancelErase();
    bool called = false;
    const auto reply = lock_manager::runStorage("fixture.storage", [&](auto&, auto&) {
        called = true;
        return rpc::ok();
    });
    TEST_ASSERT_EQUAL_STRING("recovery_required", reply.error.c_str());
    TEST_ASSERT_FALSE(called);
    bluetoothReady = true;
    TEST_ASSERT_FALSE(lock_manager::pair(mac, "Changed", 1, {}).error.empty());
    TEST_ASSERT_EQUAL_UINT(0, bluetoothCalls);
    TEST_ASSERT_EQUAL_UINT(0, s_writes);
    TEST_ASSERT_TRUE(s_namespaces == before);
}

static void test_forget_and_board_erase_remove_metadata_including_orphan_entries() {
    const auto decoded = backup_fixture::make(2);
    TEST_ASSERT_EQUAL_INT(static_cast<int>(latchkey_util::RestoreStatus::Ok), static_cast<int>(restore(decoded)));
    TEST_ASSERT_TRUE(lock_manager::forget(std::string(kMac)).error.empty());
    TEST_ASSERT_FALSE(s_namespaces["lockmeta"].contains(kKey));
    TEST_ASSERT_EQUAL_UINT(1, visibleLocks());
    s_namespaces["lockmeta"][kOtherKey] = {NVS_TYPE_BLOB, {0xFF}};
    TEST_ASSERT_EQUAL_INT(ESP_OK, lock_manager::eraseAll());
    TEST_ASSERT_TRUE(s_namespaces["lockmeta"].empty());
    TEST_ASSERT_EQUAL_UINT(0, visibleLocks());
}

static void test_startup_loads_metadata_and_never_trusts_unreadable_lifecycle_flags() {
    const auto decoded = backup_fixture::make();
    TEST_ASSERT_EQUAL_INT(static_cast<int>(latchkey_util::RestoreStatus::Ok), static_cast<int>(restore(decoded)));
    for (bool damaged : {false, true}) {
        lock_manager::s_locks = {};
        lock_manager::s_lockCount = 0;
        if (damaged) s_namespaces["lockmeta"][kKey] = {NVS_TYPE_BLOB, {0xFF}};
        lock_manager::start();
        const auto reply = lock_manager::list();
        const auto* lock = cJSON_GetArrayItem(cJSON_GetObjectItemCaseSensitive(reply.result.get(), "locks"), 0);
        TEST_ASSERT_EQUAL_INT(!damaged, cJSON_IsTrue(cJSON_GetObjectItemCaseSensitive(lock, "backedUp")));
        TEST_ASSERT_EQUAL_INT(!damaged, cJSON_IsTrue(cJSON_GetObjectItemCaseSensitive(lock, "hardened")));
        const auto* warnings = cJSON_GetObjectItemCaseSensitive(lock, "warnings");
        TEST_ASSERT_EQUAL_INT(damaged, cJSON_GetArraySize(warnings) > 0);
    }
}

static void test_pairing_cleanup_resets_previous_lifecycle_before_new_pairing() {
    const auto decoded = backup_fixture::make();
    TEST_ASSERT_EQUAL_INT(static_cast<int>(latchkey_util::RestoreStatus::Ok), static_cast<int>(restore(decoded)));
    bluetoothReady = true;
    receiveAdvert = [&](ble::Message& message) {
        message.kind = ble::Message::Kind::Advert;
        message.advert = {};
        const uint8_t bytes[]{18, 0xFF, 5, 3, 2, 4, 80, 0, 0, 0, 0, 0, 0, 1, 0x53, 0, 0x5E, 0, 0};
        std::copy(std::begin(bytes), std::end(bytes), message.advert.data);
        message.advert.length = sizeof(bytes);
        return true;
    };
    const auto paired = lock_manager::pair(std::string(kMac), "Entry", 1, {});
    TEST_ASSERT_EQUAL_STRING("timeout", paired.error.c_str());
    TEST_ASSERT_FALSE(s_namespaces["lockmeta"].contains(kKey));
    const auto reply = lock_manager::list();
    const auto* lock = cJSON_GetArrayItem(cJSON_GetObjectItemCaseSensitive(reply.result.get(), "locks"), 0);
    TEST_ASSERT_FALSE(cJSON_IsTrue(cJSON_GetObjectItemCaseSensitive(lock, "backedUp")));
    TEST_ASSERT_FALSE(cJSON_IsTrue(cJSON_GetObjectItemCaseSensitive(lock, "hardened")));
}

static void test_direct_rename_waits_for_the_storage_snapshot_to_finish() {
    const auto decoded = backup_fixture::make();
    TEST_ASSERT_EQUAL_INT(static_cast<int>(latchkey_util::RestoreStatus::Ok), static_cast<int>(restore(decoded)));
    std::mutex gate;
    std::condition_variable changed;
    bool entered = false;
    bool release = false;
    std::atomic<bool> renameStarted = false;
    std::atomic<bool> renamed = false;
    s_writes = 0;
    std::thread storageThread([&] {
        lock_manager::runStorage("fixture.storage", [&](auto&, auto&) {
            std::unique_lock<std::mutex> lock(gate);
            entered = true;
            changed.notify_all();
            changed.wait(lock, [&] { return release; });
            return rpc::ok();
        });
    });
    {
        std::unique_lock<std::mutex> lock(gate);
        TEST_ASSERT_TRUE(changed.wait_for(lock, std::chrono::seconds(2), [&] { return entered; }));
    }
    std::thread renameThread([&] {
        renameStarted = true;
        const auto reply = lock_manager::rename(std::string(kMac), "Changed");
        renamed = reply.error.empty();
    });
    while (!renameStarted) std::this_thread::yield();
    TEST_ASSERT_FALSE(renamed);
    TEST_ASSERT_EQUAL_UINT(0, s_writes);
    {
        std::lock_guard<std::mutex> lock(gate);
        release = true;
        changed.notify_all();
    }
    storageThread.join();
    renameThread.join();
    TEST_ASSERT_TRUE(renamed);
    store::locks::Record record;
    TEST_ASSERT_TRUE(lock_manager::record(std::string(kMac), record));
    TEST_ASSERT_EQUAL_STRING("Changed", record.name);
}

static void test_publication_stays_hidden_through_journal_clear_without_post_commit_allocations() {
    const auto decoded = backup_fixture::make(2);
    bool journalSeen = false;
    bool exposedEarly = false;
    s_afterMutation = [&] {
        const auto found = s_namespaces.find("restore");
        const bool pending = found != s_namespaces.end() && found->second.contains("pending");
        journalSeen = journalSeen || pending;
        exposedEarly = exposedEarly || lock_manager::s_lockCount != 0;
        if (journalSeen && !pending) allocation_failure::failNext();
    };
    const auto status = restore(decoded);
    allocation_failure::resume();
    s_afterMutation = {};
    TEST_ASSERT_EQUAL_INT(static_cast<int>(latchkey_util::RestoreStatus::Ok), static_cast<int>(status));
    TEST_ASSERT_TRUE(journalSeen);
    TEST_ASSERT_FALSE(exposedEarly);
    TEST_ASSERT_EQUAL_UINT(0, allocation_failure::attempts);
    TEST_ASSERT_EQUAL_UINT(2, visibleLocks());
}

static void test_ambiguous_commit_latches_recovery_and_restart_loads_the_complete_import() {
    const auto decoded = backup_fixture::make();
    TEST_ASSERT_EQUAL_INT(static_cast<int>(latchkey_util::RestoreStatus::Ok), static_cast<int>(restore(decoded)));
    const size_t lastWrite = s_writes;
    resetManagerFixture();
    s_failWrite = lastWrite;
    TEST_ASSERT_EQUAL_INT(static_cast<int>(latchkey_util::RestoreStatus::RecoveryRequired),
                          static_cast<int>(restore(decoded)));
    TEST_ASSERT_EQUAL_UINT(0, visibleLocks());
    TEST_ASSERT_TRUE(s_namespaces["locks"].contains(kKey));
    s_failWrite = 0;
    bool called = false;
    const auto reply = lock_manager::runStorage("fixture.storage", [&](auto&, auto&) {
        called = true;
        return rpc::ok();
    });
    TEST_ASSERT_EQUAL_STRING("recovery_required", reply.error.c_str());
    TEST_ASSERT_FALSE(called);
    TEST_ASSERT_EQUAL_INT(ESP_OK, key_store::recover());
    lock_manager::s_restore = key_store::Restore{};
    lock_manager::start();
    TEST_ASSERT_EQUAL_UINT(1, visibleLocks());
}

static void test_pair_record_allocation_failure_precedes_persistence() {
    const auto decoded = backup_fixture::make();
    store::locks::Record record;
    TEST_ASSERT_TRUE(key_store::makeRecord(decoded.locks()[0], record));
    allocation_failure::failNext();
    const auto error = lock_manager::persist(record);
    allocation_failure::resume();
    TEST_ASSERT_EQUAL_INT(ESP_ERR_NO_MEM, error);
    TEST_ASSERT_EQUAL_UINT(0, s_writes);
    TEST_ASSERT_EQUAL_UINT(0, visibleLocks());
    TEST_ASSERT_EQUAL_INT(ESP_OK, lock_manager::persist(record));
    TEST_ASSERT_EQUAL_UINT(1, visibleLocks());
}

int main() {
    rpc::init();
    UNITY_BEGIN();
    RUN_TEST(test_storage_job_runs_without_bluetooth_and_holds_the_manager_mutex);
    RUN_TEST(test_storage_job_waits_until_the_active_pairing_job_finishes);
    RUN_TEST(test_restored_locks_are_published_together_with_metadata_and_pending_state);
    RUN_TEST(test_failed_restore_publishes_nothing_and_existing_objects_survive);
    RUN_TEST(test_every_import_publication_allocation_failure_precedes_all_writes);
    RUN_TEST(test_recovery_required_remains_latched_across_requests_and_blocks_every_storage_mutation);
    RUN_TEST(test_forget_and_board_erase_remove_metadata_including_orphan_entries);
    RUN_TEST(test_startup_loads_metadata_and_never_trusts_unreadable_lifecycle_flags);
    RUN_TEST(test_pairing_cleanup_resets_previous_lifecycle_before_new_pairing);
    RUN_TEST(test_direct_rename_waits_for_the_storage_snapshot_to_finish);
    RUN_TEST(test_publication_stays_hidden_through_journal_clear_without_post_commit_allocations);
    RUN_TEST(test_ambiguous_commit_latches_recovery_and_restart_loads_the_complete_import);
    RUN_TEST(test_pair_record_allocation_failure_precedes_persistence);
    return UNITY_END();
}
