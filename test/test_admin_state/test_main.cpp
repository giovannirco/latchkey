// SPDX-License-Identifier: GPL-3.0-or-later
#include "lock_manager_test_runtime.h"
#include "../reference/backup_fixture.h"

using latchkey_util::AdminProvenance;
using lock_manager::AdminState;

static const std::string mac(kMac);
static constexpr std::string_view previous = "135792468";
static constexpr std::string_view candidate = "246813579";

static void seed() {
    const auto decoded = backup_fixture::make();
    store::locks::Record record;
    TEST_ASSERT_TRUE(key_store::makeRecord(decoded.locks()[0], record));
    std::memcpy(record.adminPasscode, previous.data(), previous.size());
    record.adminPasscode[previous.size()] = 0;
    TEST_ASSERT_EQUAL_INT(ESP_OK, lock_manager::persist(record));
    latchkey_util::LockMetadata metadata;
    metadata.provenance = AdminProvenance::Owner;
    metadata.lifecycle = latchkey_util::kBackupBackedUp;
    TEST_ASSERT_EQUAL_INT(ESP_OK, key_store::saveMetadata(mac, metadata));
    s_reads = s_writes = 0;
}

void setUp() { resetManagerFixture(); seed(); }
void tearDown() { clearManagerFixture(); }

static AdminState state() {
    AdminState value;
    TEST_ASSERT_EQUAL_INT(ESP_OK, lock_manager::readAdminState(mac, value));
    return value;
}

static void test_staging_preserves_confirmed_code_and_persists_target_provenance() {
    TEST_ASSERT_EQUAL_INT(ESP_OK, lock_manager::stageAdminPasscode(mac, candidate, AdminProvenance::Owner));
    const auto stored = state();
    TEST_ASSERT_TRUE(previous == stored.record.adminPasscode);
    TEST_ASSERT_TRUE((stored.record.flags & store::locks::kFlagAdminPasscodeConfirmed) != 0);
    TEST_ASSERT_TRUE(candidate == stored.metadata.pendingAdminPasscode.data());
    TEST_ASSERT_EQUAL_INT(static_cast<int>(AdminProvenance::Owner), static_cast<int>(stored.metadata.pendingProvenance));
    const auto before = s_namespaces;
    TEST_ASSERT_NOT_EQUAL(ESP_OK, lock_manager::stageAdminPasscode(mac, "975312468", AdminProvenance::Owner));
    TEST_ASSERT_TRUE(before == s_namespaces);
}

static void test_reconciliation_confirms_candidate_or_old_without_a_lock_write() {
    for (const bool accepted : {false, true}) {
        resetManagerFixture();
        seed();
        TEST_ASSERT_EQUAL_INT(ESP_OK, lock_manager::stageAdminPasscode(mac, candidate, AdminProvenance::HardeningGenerated));
        TEST_ASSERT_EQUAL_INT(ESP_OK, lock_manager::reconcileAdminPasscode(mac, accepted ? candidate : previous));
        const auto stored = state();
        TEST_ASSERT_TRUE((accepted ? candidate : previous) == stored.record.adminPasscode);
        TEST_ASSERT_TRUE(stored.metadata.pendingAdminPasscode[0] == 0);
        TEST_ASSERT_EQUAL_INT(static_cast<int>(accepted ? AdminProvenance::HardeningGenerated : AdminProvenance::Owner),
                              static_cast<int>(stored.metadata.provenance));
        TEST_ASSERT_EQUAL_UINT(0, bluetoothCalls);
    }
}

static void test_third_code_never_clears_pending_or_changes_confirmed_state() {
    TEST_ASSERT_EQUAL_INT(ESP_OK, lock_manager::stageAdminPasscode(mac, candidate, AdminProvenance::Owner));
    const auto before = s_namespaces;
    TEST_ASSERT_NOT_EQUAL(ESP_OK, lock_manager::reconcileAdminPasscode(mac, "975312468"));
    TEST_ASSERT_TRUE(before == s_namespaces);
}

static void test_failed_candidate_persistence_never_overwrites_confirmed_copy() {
    for (size_t at = 1; at <= 2; ++at) for (const bool after : {false, true}) {
        resetManagerFixture();
        seed();
        s_failWrite = at;
        s_failAfter = after;
        TEST_ASSERT_NOT_EQUAL(ESP_OK, lock_manager::stageAdminPasscode(mac, candidate, AdminProvenance::Owner));
        s_failWrite = 0;
        TEST_ASSERT_TRUE(previous == state().record.adminPasscode);
        TEST_ASSERT_EQUAL_UINT(0, bluetoothCalls);
    }
}

static void test_each_verdict_write_failure_remains_recoverable_after_restart() {
    for (size_t at = 1; at <= 3; ++at) for (const bool after : {false, true}) {
        resetManagerFixture();
        seed();
        TEST_ASSERT_EQUAL_INT(ESP_OK, lock_manager::stageAdminPasscode(mac, candidate, AdminProvenance::HardeningGenerated));
        s_failWrite = s_writes + at;
        s_failAfter = after;
        TEST_ASSERT_NOT_EQUAL(ESP_OK, lock_manager::confirmAdminPasscode(mac));
        s_failWrite = 0;
        lock_manager::s_locks = {};
        lock_manager::s_lockCount = 0;
        lock_manager::start();
        auto stored = state();
        if (stored.metadata.pendingAdminPasscode[0] != 0) {
            TEST_ASSERT_EQUAL_INT(ESP_OK, lock_manager::reconcileAdminPasscode(mac, candidate));
        }
        stored = state();
        TEST_ASSERT_TRUE(candidate == stored.record.adminPasscode);
        TEST_ASSERT_TRUE(stored.metadata.pendingAdminPasscode[0] == 0);
        TEST_ASSERT_EQUAL_INT(static_cast<int>(AdminProvenance::HardeningGenerated), static_cast<int>(stored.metadata.provenance));
    }
}

static void test_interrupted_verdict_can_be_backed_up_with_matching_pending_and_confirmed_copies() {
    TEST_ASSERT_EQUAL_INT(ESP_OK, lock_manager::stageAdminPasscode(mac, candidate, AdminProvenance::HardeningGenerated));
    s_failWrite = s_writes + 2;
    TEST_ASSERT_NOT_EQUAL(ESP_OK, lock_manager::confirmAdminPasscode(mac));
    s_failWrite = 0;
    latchkey_util::SensitiveBuffer bytes;
    latchkey_util::RestoreJournal ids;
    TEST_ASSERT_EQUAL_INT(ESP_OK, key_store::snapshot(mac, bytes, ids));
    latchkey_util::DecodedBackup decoded;
    TEST_ASSERT_EQUAL_INT(static_cast<int>(latchkey_util::BackupStatus::Ok),
                          static_cast<int>(latchkey_util::decodeBackup(std::move(bytes), decoded)));
    TEST_ASSERT_TRUE(decoded.locks()[0].adminPasscode == candidate);
    TEST_ASSERT_TRUE(decoded.locks()[0].pendingAdminPasscode == candidate);
    TEST_ASSERT_EQUAL_INT(static_cast<int>(AdminProvenance::HardeningGenerated),
                          static_cast<int>(decoded.locks()[0].pendingProvenance));
    resetManagerFixture();
    const auto restored = lock_manager::runStorage("fixture.restore", [&](auto& storage, auto& publication) {
        TEST_ASSERT_EQUAL_INT(static_cast<int>(latchkey_util::RestoreStatus::Ok),
                              static_cast<int>(latchkey_util::restoreKeys(decoded, storage, publication)));
        return rpc::ok();
    });
    TEST_ASSERT_TRUE(restored.error.empty());
    lock_manager::s_locks = {};
    lock_manager::s_lockCount = 0;
    lock_manager::start();
    TEST_ASSERT_EQUAL_INT(ESP_OK, lock_manager::reconcileAdminPasscode(mac, candidate));
    const auto recovered = state();
    TEST_ASSERT_TRUE(candidate == recovered.record.adminPasscode);
    TEST_ASSERT_TRUE(recovered.metadata.pendingAdminPasscode[0] == 0);
    TEST_ASSERT_EQUAL_INT(static_cast<int>(AdminProvenance::HardeningGenerated), static_cast<int>(recovered.metadata.provenance));
}

static void test_confirmed_refusal_removes_only_pending_candidate() {
    TEST_ASSERT_EQUAL_INT(ESP_OK, lock_manager::stageAdminPasscode(mac, candidate, AdminProvenance::Owner));
    TEST_ASSERT_EQUAL_INT(ESP_OK, lock_manager::rejectAdminPasscode(mac));
    const auto stored = state();
    TEST_ASSERT_TRUE(previous == stored.record.adminPasscode);
    TEST_ASSERT_TRUE(stored.metadata.pendingAdminPasscode[0] == 0);
    TEST_ASSERT_EQUAL_INT(static_cast<int>(AdminProvenance::Owner), static_cast<int>(stored.metadata.provenance));
}

static void test_local_erasure_refuses_disabled_reset_or_unreadable_persisted_state() {
    for (int damage = 0; damage < 3; ++damage) {
        resetManagerFixture();
        seed();
        auto metadata = state().metadata;
        metadata.lifecycle |= latchkey_util::kBackupResetButtonOff;
        TEST_ASSERT_EQUAL_INT(ESP_OK, key_store::saveMetadata(mac, metadata));
        if (damage == 1) s_namespaces["lockmeta"][kKey] = {NVS_TYPE_BLOB, {0xFF}};
        if (damage == 2) s_namespaces["locks"][kKey] = {NVS_TYPE_BLOB, {0xFF}};
        const auto before = s_namespaces;
        TEST_ASSERT_FALSE(lock_manager::forget(mac).error.empty());
        TEST_ASSERT_NOT_EQUAL(ESP_OK, lock_manager::checkEraseAll());
        TEST_ASSERT_NOT_EQUAL(ESP_OK, lock_manager::eraseAll());
        TEST_ASSERT_TRUE(before == s_namespaces);
        lock_manager::s_locks = {};
        lock_manager::s_lockCount = 0;
        TEST_ASSERT_NOT_EQUAL(ESP_OK, lock_manager::checkEraseAll());
        TEST_ASSERT_NOT_EQUAL(ESP_OK, lock_manager::eraseAll());
        TEST_ASSERT_TRUE(before == s_namespaces);
    }
}

static void test_erasure_guard_checks_all_stored_entries_and_fails_on_read_errors() {
    s_namespaces["locks"]["invalid"] = {NVS_TYPE_BLOB, {0xFF}};
    const auto before = s_namespaces;
    TEST_ASSERT_NOT_EQUAL(ESP_OK, lock_manager::checkEraseAll());
    TEST_ASSERT_NOT_EQUAL(ESP_OK, lock_manager::eraseAll());
    TEST_ASSERT_TRUE(before == s_namespaces);
    s_namespaces["locks"].erase("invalid");
    s_failRead = s_reads + 1;
    TEST_ASSERT_NOT_EQUAL(ESP_OK, lock_manager::checkEraseAll());
}

int main() {
    rpc::init();
    UNITY_BEGIN();
    RUN_TEST(test_staging_preserves_confirmed_code_and_persists_target_provenance);
    RUN_TEST(test_reconciliation_confirms_candidate_or_old_without_a_lock_write);
    RUN_TEST(test_third_code_never_clears_pending_or_changes_confirmed_state);
    RUN_TEST(test_failed_candidate_persistence_never_overwrites_confirmed_copy);
    RUN_TEST(test_each_verdict_write_failure_remains_recoverable_after_restart);
    RUN_TEST(test_interrupted_verdict_can_be_backed_up_with_matching_pending_and_confirmed_copies);
    RUN_TEST(test_confirmed_refusal_removes_only_pending_candidate);
    RUN_TEST(test_local_erasure_refuses_disabled_reset_or_unreadable_persisted_state);
    RUN_TEST(test_erasure_guard_checks_all_stored_entries_and_fails_on_read_errors);
    return UNITY_END();
}
