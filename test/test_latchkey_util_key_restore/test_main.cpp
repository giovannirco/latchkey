// SPDX-License-Identifier: GPL-3.0-or-later
#include <unity.h>

#include <array>
#include <cstring>
#include <map>
#include <new>
#include <string>
#include <vector>

#include "latchkey_util/key_restore.h"

using namespace latchkey_util;

void setUp() {}
void tearDown() {}

static constexpr std::array<uint8_t, 16> kKey{};
static constexpr std::array<uint8_t, 2> kLabels{1, 0};
static constexpr std::array<std::string_view, 2> kMacs{"00:00:5E:00:53:01", "00:00:5E:00:53:02"};

static DecodedBackup backup() {
    std::array<BackupLock, 2> locks;
    for (size_t i = 0; i < locks.size(); ++i) {
        locks[i].mac = kMacs[i];
        locks[i].protocol = {5, 3, 1, 1, 1};
        locks[i].aesKey = kKey;
        locks[i].labels.fill(kLabels);
    }
    SensitiveBuffer bytes;
    TEST_ASSERT_EQUAL_INT(static_cast<int>(BackupStatus::Ok), static_cast<int>(encodeBackup(locks, bytes)));
    DecodedBackup out;
    TEST_ASSERT_EQUAL_INT(static_cast<int>(BackupStatus::Ok), static_cast<int>(decodeBackup(std::move(bytes), out)));
    return out;
}

struct Storage final : RestoreStorage {
    std::map<std::pair<std::string, RestorePart>, std::vector<uint8_t>> entries;
    RestoreJournal journal;
    bool pending = false;
    size_t writes = 0;
    size_t available = 4096;
    size_t reserve = 100;
    size_t failWrite = 0;
    bool failAfter = false;
    bool failReads = false;
    bool failCleanup = false;
    bool failJournalReadAfterClear = false;
    bool cleared = false;

    bool readJournal(RestoreJournal& out, bool& present) override {
        if (failReads || (cleared && failJournalReadAfterClear)) return false;
        out = journal;
        present = pending;
        return true;
    }

    bool countRecords(size_t& out) override {
        if (failReads) return false;
        out = 0;
        for (const auto& [key, bytes] : entries) if (key.second == RestorePart::Record) ++out;
        return true;
    }

    bool containsIdentity(std::string_view mac, bool& out) override {
        if (failReads) return false;
        out = false;
        for (const auto& [key, bytes] : entries) if (key.first == mac) out = true;
        return true;
    }

    bool capacity(size_t& free, size_t& reserved) override {
        if (failReads) return false;
        free = available;
        reserved = reserve;
        return true;
    }

    size_t recordBytes() const override { return 344; }

    template <typename Mutation>
    bool write(Mutation mutation) {
        ++writes;
        if (writes == failWrite && !failAfter) return false;
        mutation();
        return writes != failWrite;
    }

    bool writeJournal(const RestoreJournal& value) override {
        return write([&] { journal = value; pending = true; });
    }

    bool writePart(const BackupLock& lock, RestorePart part) override {
        TEST_ASSERT_TRUE(pending);
        return write([&] { entries[{std::string(lock.mac), part}] = {1, 2, 3}; });
    }

    bool erasePart(std::string_view mac, RestorePart part) override {
        TEST_ASSERT_TRUE(pending);
        if (failCleanup) return false;
        return write([&] { entries.erase({std::string(mac), part}); });
    }

    bool clearJournal() override {
        cleared = true;
        return write([&] { pending = false; });
    }
};

struct Publication final : RestorePublication {
    explicit Publication(Storage& storage) : storage(storage) {}
    Storage& storage;
    bool fail = false;
    bool prepared = false;
    bool published = false;
    bool discarded = false;

    bool prepare(std::span<const BackupLock> locks) override {
        TEST_ASSERT_EQUAL_UINT(0, storage.writes);
        TEST_ASSERT_EQUAL_UINT(2, locks.size());
        prepared = !fail;
        return prepared;
    }

    void publish() noexcept override {
        TEST_ASSERT_TRUE(prepared);
        TEST_ASSERT_FALSE(storage.pending);
        TEST_ASSERT_EQUAL_UINT(12, storage.entries.size());
        published = true;
    }

    void discard() noexcept override { discarded = true; }
};

static void expect(RestoreStatus wanted, RestoreStatus actual) {
    TEST_ASSERT_EQUAL_INT(static_cast<int>(wanted), static_cast<int>(actual));
}

static void test_complete_restore_publishes_only_after_journal_commit() {
    const auto decoded = backup();
    Storage storage;
    Publication publication(storage);
    expect(RestoreStatus::Ok, restoreKeys(decoded, storage, publication));
    TEST_ASSERT_EQUAL_UINT(14, storage.writes);
    TEST_ASSERT_FALSE(storage.pending);
    TEST_ASSERT_TRUE(publication.published);
    TEST_ASSERT_FALSE(publication.discarded);
}

static void test_whole_import_conflict_refuses_unreadable_record_without_writes() {
    const auto decoded = backup();
    Storage storage;
    storage.entries[{std::string(kMacs[1]), RestorePart::Record}] = {0xFF};
    const auto before = storage.entries;
    Publication publication(storage);
    expect(RestoreStatus::Conflict, restoreKeys(decoded, storage, publication));
    TEST_ASSERT_TRUE(storage.entries == before);
    TEST_ASSERT_EQUAL_UINT(0, storage.writes);
    TEST_ASSERT_FALSE(publication.published);
}

static void test_orphan_metadata_conflicts_before_writes() {
    const auto decoded = backup();
    for (const auto part : kRestoreParts) {
        Storage storage;
        storage.entries[{std::string(kMacs[1]), part}] = {0xFF};
        Publication publication(storage);
        expect(RestoreStatus::Conflict, restoreKeys(decoded, storage, publication));
        TEST_ASSERT_EQUAL_UINT(0, storage.writes);
    }
}

static void test_record_capacity_and_reserve_refuse_without_writes() {
    const auto decoded = backup();
    Storage storage;
    for (size_t i = 0; i < 7; ++i) storage.entries[{std::to_string(i), RestorePart::Record}] = {0xFF};
    Publication publication(storage);
    expect(RestoreStatus::Capacity, restoreKeys(decoded, storage, publication));
    TEST_ASSERT_EQUAL_UINT(0, storage.writes);
    storage.entries.clear();
    storage.available = storage.reserve + 1;
    expect(RestoreStatus::Capacity, restoreKeys(decoded, storage, publication));
    TEST_ASSERT_EQUAL_UINT(0, storage.writes);
}

static void test_preparation_failure_and_pending_journal_refuse_without_writes() {
    const auto decoded = backup();
    Storage storage;
    Publication publication(storage);
    publication.fail = true;
    expect(RestoreStatus::NoMemory, restoreKeys(decoded, storage, publication));
    TEST_ASSERT_EQUAL_UINT(0, storage.writes);
    storage.pending = true;
    expect(RestoreStatus::RecoveryRequired, restoreKeys(decoded, storage, publication));
    TEST_ASSERT_EQUAL_UINT(0, storage.writes);
    Storage unreadable;
    unreadable.failReads = true;
    expect(RestoreStatus::ReadFailed, restoreKeys(decoded, unreadable, publication));
    TEST_ASSERT_EQUAL_UINT(0, unreadable.writes);
}

static void test_failures_before_and_after_every_durable_write_roll_back_only_new_ids() {
    const auto decoded = backup();
    for (size_t boundary = 1; boundary < 14; ++boundary) {
        for (const bool after : {false, true}) {
            Storage storage;
            storage.entries[{"00:00:5E:00:53:09", RestorePart::Record}] = {9};
            const auto before = storage.entries;
            storage.failWrite = boundary;
            storage.failAfter = after;
            Publication publication(storage);
            expect(RestoreStatus::WriteFailed, restoreKeys(decoded, storage, publication));
            TEST_ASSERT_TRUE(storage.entries == before);
            TEST_ASSERT_FALSE(storage.pending);
            TEST_ASSERT_FALSE(publication.published);
            TEST_ASSERT_TRUE(publication.discarded);
        }
    }
}

static void test_journal_clear_failure_checks_durable_marker_before_any_rollback() {
    const auto decoded = backup();
    for (const bool after : {false, true}) {
        Storage storage;
        storage.failWrite = 14;
        storage.failAfter = after;
        Publication publication(storage);
        expect(after ? RestoreStatus::RecoveryRequired : RestoreStatus::WriteFailed,
               restoreKeys(decoded, storage, publication));
        TEST_ASSERT_FALSE(publication.published);
        TEST_ASSERT_TRUE(publication.discarded);
        TEST_ASSERT_FALSE(storage.pending);
        TEST_ASSERT_EQUAL_UINT(after ? 12 : 0, storage.entries.size());
        if (after) TEST_ASSERT_EQUAL_UINT(14, storage.writes);
        expect(RestoreStatus::Ok, recoverKeys(storage));
        TEST_ASSERT_EQUAL_UINT(after ? 12 : 0, storage.entries.size());
    }
}

static void test_unknown_commit_outcome_and_failed_cleanup_retain_recovery_evidence() {
    const auto decoded = backup();
    Storage storage;
    storage.failWrite = 14;
    storage.failJournalReadAfterClear = true;
    Publication publication(storage);
    expect(RestoreStatus::RecoveryRequired, restoreKeys(decoded, storage, publication));
    TEST_ASSERT_TRUE(storage.pending);
    TEST_ASSERT_EQUAL_UINT(12, storage.entries.size());
    TEST_ASSERT_EQUAL_UINT(14, storage.writes);
    storage.failJournalReadAfterClear = false;
    storage.failCleanup = true;
    expect(RestoreStatus::RecoveryRequired, recoverKeys(storage));
    TEST_ASSERT_TRUE(storage.pending);
    TEST_ASSERT_EQUAL_UINT(12, storage.entries.size());
    storage.failCleanup = false;
    expect(RestoreStatus::Ok, recoverKeys(storage));
    TEST_ASSERT_FALSE(storage.pending);
    TEST_ASSERT_TRUE(storage.entries.empty());
}

static void test_reboot_recovery_removes_only_journaled_identities() {
    Storage storage;
    storage.pending = true;
    storage.journal.count = 2;
    for (size_t i = 0; i < kMacs.size(); ++i) {
        std::memcpy(storage.journal.identities[i].data(), kMacs[i].data(), 17);
        for (const auto part : kRestoreParts) storage.entries[{std::string(kMacs[i]), part}] = {1};
    }
    storage.entries[{"00:00:5E:00:53:09", RestorePart::Record}] = {9};
    expect(RestoreStatus::Ok, recoverKeys(storage));
    TEST_ASSERT_EQUAL_UINT(1, storage.entries.size());
    TEST_ASSERT_FALSE(storage.pending);
    TEST_ASSERT_EQUAL_STRING("00:00:5E:00:53:09", storage.entries.begin()->first.first.c_str());
}

static void test_recovery_failure_at_every_cleanup_boundary_never_clears_a_live_journal() {
    for (size_t boundary = 1; boundary <= 13; ++boundary) {
        for (const bool after : {false, true}) {
            Storage storage;
            storage.pending = true;
            storage.journal.count = 2;
            for (size_t i = 0; i < kMacs.size(); ++i) {
                std::memcpy(storage.journal.identities[i].data(), kMacs[i].data(), 17);
                for (const auto part : kRestoreParts) storage.entries[{std::string(kMacs[i]), part}] = {1};
            }
            storage.failWrite = boundary;
            storage.failAfter = after;
            expect(RestoreStatus::RecoveryRequired, recoverKeys(storage));
            TEST_ASSERT_EQUAL_INT(!(boundary == 13 && after), storage.pending);
            storage.failWrite = 0;
            expect(RestoreStatus::Ok, recoverKeys(storage));
            TEST_ASSERT_TRUE(storage.entries.empty());
            TEST_ASSERT_FALSE(storage.pending);
        }
    }
}

static void test_journal_codec_rejects_bad_identities_counts_duplicates_and_trailing_bytes() {
    RestoreJournal journal;
    journal.count = 2;
    for (size_t i = 0; i < kMacs.size(); ++i) std::memcpy(journal.identities[i].data(), kMacs[i].data(), 17);
    std::array<uint8_t, kRestoreJournalBytes> bytes{};
    size_t size = 0;
    TEST_ASSERT_TRUE(encodeRestoreJournal(journal, bytes, size));
    TEST_ASSERT_EQUAL_UINT(36, size);
    TEST_ASSERT_EQUAL_UINT8(1, bytes[0]);
    TEST_ASSERT_EQUAL_UINT8(2, bytes[1]);
    TEST_ASSERT_EQUAL_MEMORY(kMacs[0].data(), bytes.data() + 2, 17);
    RestoreJournal out;
    TEST_ASSERT_TRUE(decodeRestoreJournal({bytes.data(), size}, out));
    TEST_ASSERT_EQUAL_UINT(2, out.count);
    TEST_ASSERT_TRUE(out.identities == journal.identities);
    for (size_t length = 0; length < size; ++length) {
        TEST_ASSERT_FALSE(decodeRestoreJournal({bytes.data(), length}, out));
        TEST_ASSERT_TRUE(out.identities == journal.identities);
    }
    TEST_ASSERT_FALSE(decodeRestoreJournal(bytes, out));
    for (const size_t index : {size_t{0}, size_t{1}, size_t{2}, size_t{4}}) {
        auto damaged = bytes;
        damaged[index] = 0xFF;
        TEST_ASSERT_FALSE(decodeRestoreJournal({damaged.data(), size}, out));
    }
    auto duplicate = bytes;
    std::memcpy(duplicate.data() + 19, duplicate.data() + 2, 17);
    TEST_ASSERT_FALSE(decodeRestoreJournal({duplicate.data(), size}, out));
    TEST_ASSERT_FALSE(encodeRestoreJournal(journal, {bytes.data(), size - 1}, size));
    journal.count = 9;
    TEST_ASSERT_FALSE(encodeRestoreJournal(journal, bytes, size));
    journal.count = 0;
    TEST_ASSERT_FALSE(encodeRestoreJournal(journal, bytes, size));
}

static void test_invalid_journal_never_deletes_any_identity() {
    Storage storage;
    storage.pending = true;
    storage.journal.count = 1;
    storage.journal.identities[0].fill('x');
    expect(RestoreStatus::RecoveryRequired, recoverKeys(storage));
    TEST_ASSERT_EQUAL_UINT(0, storage.writes);
    TEST_ASSERT_TRUE(storage.pending);
}

static void test_metadata_codec_preserves_flags_provenance_and_pending_code() {
    LockMetadata metadata;
    metadata.lifecycle = 7;
    metadata.provenance = AdminProvenance::Owner;
    metadata.pendingProvenance = AdminProvenance::PairingGenerated;
    std::memcpy(metadata.pendingAdminPasscode.data(), "123456789", 9);
    std::array<uint8_t, kLockMetadataBytes> bytes{};
    TEST_ASSERT_TRUE(encodeLockMetadata(metadata, bytes));
    TEST_ASSERT_EQUAL_UINT8(1, bytes[0]);
    TEST_ASSERT_EQUAL_UINT8(7, bytes[1]);
    TEST_ASSERT_EQUAL_UINT8(1, bytes[2]);
    TEST_ASSERT_EQUAL_UINT8(2, bytes[3]);
    TEST_ASSERT_EQUAL_UINT8(9, bytes[4]);
    LockMetadata out;
    TEST_ASSERT_TRUE(decodeLockMetadata(bytes, out));
    TEST_ASSERT_EQUAL_UINT8(7, out.lifecycle);
    TEST_ASSERT_EQUAL_INT(static_cast<int>(metadata.provenance), static_cast<int>(out.provenance));
    TEST_ASSERT_EQUAL_INT(static_cast<int>(metadata.pendingProvenance), static_cast<int>(out.pendingProvenance));
    TEST_ASSERT_TRUE(metadata.pendingAdminPasscode == out.pendingAdminPasscode);
    for (size_t length = 0; length < bytes.size(); ++length) {
        TEST_ASSERT_FALSE(decodeLockMetadata({bytes.data(), length}, out));
        TEST_ASSERT_TRUE(metadata.pendingAdminPasscode == out.pendingAdminPasscode);
    }
    for (const size_t index : {size_t{0}, size_t{1}, size_t{2}, size_t{3}, size_t{4}, size_t{5}}) {
        auto damaged = bytes;
        damaged[index] = 0xFF;
        TEST_ASSERT_FALSE(decodeLockMetadata(damaged, out));
    }
    auto damaged = bytes;
    damaged[4] = 0;
    TEST_ASSERT_FALSE(decodeLockMetadata(damaged, out));
    metadata = LockMetadata{};
    TEST_ASSERT_TRUE(encodeLockMetadata(metadata, bytes));
    TEST_ASSERT_TRUE(decodeLockMetadata(bytes, out));
    TEST_ASSERT_EQUAL_INT(static_cast<int>(AdminProvenance::LegacyUnknown), static_cast<int>(out.provenance));
    TEST_ASSERT_EQUAL_UINT8(0, out.lifecycle);
    TEST_ASSERT_EQUAL_UINT8(0, out.pendingAdminPasscode[0]);
    bytes[13] = '1';
    TEST_ASSERT_FALSE(decodeLockMetadata(bytes, out));
    metadata.pendingProvenance = AdminProvenance::Owner;
    TEST_ASSERT_FALSE(encodeLockMetadata(metadata, bytes));
}

static void test_metadata_destruction_wipes_pending_code() {
    alignas(LockMetadata) std::array<uint8_t, sizeof(LockMetadata)> bytes{};
    auto* metadata = new (bytes.data()) LockMetadata;
    metadata->pendingAdminPasscode.fill('8');
    const auto* code = reinterpret_cast<const volatile char*>(metadata->pendingAdminPasscode.data());
    metadata->~LockMetadata();
    for (size_t i = 0; i < 10; ++i) TEST_ASSERT_EQUAL_UINT8(0, code[i]);
}

static void test_uncertain_commit_refuses_further_imports_even_after_journal_is_gone() {
    const auto decoded = backup();
    Storage storage;
    storage.failWrite = 14;
    storage.failAfter = true;
    Publication publication(storage);
    expect(RestoreStatus::RecoveryRequired, restoreKeys(decoded, storage, publication));
    TEST_ASSERT_FALSE(storage.pending);
    TEST_ASSERT_TRUE(storage.recoveryRequired());
    expect(RestoreStatus::Ok, recoverKeys(storage));
    expect(RestoreStatus::RecoveryRequired, restoreKeys(decoded, storage, publication));
    TEST_ASSERT_EQUAL_UINT(14, storage.writes);
    TEST_ASSERT_FALSE(publication.published);
}

int main() {
    UNITY_BEGIN();
    RUN_TEST(test_complete_restore_publishes_only_after_journal_commit);
    RUN_TEST(test_whole_import_conflict_refuses_unreadable_record_without_writes);
    RUN_TEST(test_orphan_metadata_conflicts_before_writes);
    RUN_TEST(test_record_capacity_and_reserve_refuse_without_writes);
    RUN_TEST(test_preparation_failure_and_pending_journal_refuse_without_writes);
    RUN_TEST(test_failures_before_and_after_every_durable_write_roll_back_only_new_ids);
    RUN_TEST(test_journal_clear_failure_checks_durable_marker_before_any_rollback);
    RUN_TEST(test_unknown_commit_outcome_and_failed_cleanup_retain_recovery_evidence);
    RUN_TEST(test_reboot_recovery_removes_only_journaled_identities);
    RUN_TEST(test_recovery_failure_at_every_cleanup_boundary_never_clears_a_live_journal);
    RUN_TEST(test_journal_codec_rejects_bad_identities_counts_duplicates_and_trailing_bytes);
    RUN_TEST(test_invalid_journal_never_deletes_any_identity);
    RUN_TEST(test_metadata_codec_preserves_flags_provenance_and_pending_code);
    RUN_TEST(test_metadata_destruction_wipes_pending_code);
    RUN_TEST(test_uncertain_commit_refuses_further_imports_even_after_journal_is_gone);
    return UNITY_END();
}
