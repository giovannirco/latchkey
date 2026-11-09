// SPDX-License-Identifier: GPL-3.0-or-later
#include <unity.h>

#include <cstring>
#include <map>
#include <string>
#include <vector>

#include "nvs.h"
#include "../../src/key_store.cpp"

using namespace latchkey_util;

struct StoredValue {
    nvs_type_t type = NVS_TYPE_BLOB;
    std::vector<uint8_t> bytes;
    bool operator==(const StoredValue&) const = default;
};

using Entries = std::map<std::string, StoredValue>;
static std::map<std::string, Entries> s_namespaces;
static std::map<nvs_handle_t, std::string> s_handles;
static size_t s_reads;
static size_t s_writes;
static size_t s_failRead;
static size_t s_failWrite;
static size_t s_preflightReads;
static bool s_failAfter;
static size_t s_available;
static uint32_t s_reserveSequence;
static constexpr std::string_view kMac = "00:00:5E:00:53:01";
static constexpr const char* kKey = "00005E005301";
static constexpr const char* kOtherKey = "00005E005309";

void setUp() {
    s_namespaces.clear();
    s_handles.clear();
    s_reads = s_writes = s_failRead = s_failWrite = s_preflightReads = 0;
    s_failAfter = false;
    s_available = 4096;
    s_reserveSequence = 0;
}

void tearDown() { TEST_ASSERT_TRUE(s_handles.empty()); }

static bool canRead() { return ++s_reads != s_failRead; }

template <typename Mutation>
static esp_err_t mutate(Mutation mutation) {
    if (s_writes == 0) s_preflightReads = s_reads;
    ++s_writes;
    if (s_writes == s_failWrite && !s_failAfter) return ESP_FAIL;
    mutation();
    return s_writes == s_failWrite ? ESP_FAIL : ESP_OK;
}

esp_err_t nvs_open(const char* name, nvs_open_mode_t mode, nvs_handle_t* out) {
    if (!canRead()) return ESP_FAIL;
    if (!s_namespaces.contains(name)) {
        if (mode == NVS_READONLY) return ESP_ERR_NVS_NOT_FOUND;
        const auto error = mutate([&] { s_namespaces.emplace(name, Entries{}); });
        if (error != ESP_OK) return error;
    }
    *out = s_handles.empty() ? 1 : s_handles.rbegin()->first + 1;
    s_handles[*out] = name;
    return ESP_OK;
}

void nvs_close(nvs_handle_t handle) { s_handles.erase(handle); }

esp_err_t nvs_find_key(nvs_handle_t handle, const char* key, nvs_type_t* type) {
    if (!canRead()) return ESP_FAIL;
    const auto& entries = s_namespaces.at(s_handles.at(handle));
    if (!entries.contains(key)) return ESP_ERR_NVS_NOT_FOUND;
    *type = entries.at(key).type;
    return ESP_OK;
}

esp_err_t nvs_get_blob(nvs_handle_t handle, const char* key, void* out, size_t* length) {
    if (!canRead()) return ESP_FAIL;
    const auto& entries = s_namespaces.at(s_handles.at(handle));
    if (!entries.contains(key)) return ESP_ERR_NVS_NOT_FOUND;
    const auto& value = entries.at(key);
    if (value.type != NVS_TYPE_BLOB) return ESP_ERR_NVS_TYPE_MISMATCH;
    if (out != nullptr && *length < value.bytes.size()) return ESP_ERR_NVS_INVALID_LENGTH;
    if (out != nullptr) std::memcpy(out, value.bytes.data(), value.bytes.size());
    *length = value.bytes.size();
    return ESP_OK;
}

esp_err_t nvs_get_u32(nvs_handle_t handle, const char* key, uint32_t* out) {
    if (!canRead()) return ESP_FAIL;
    const auto& entries = s_namespaces.at(s_handles.at(handle));
    if (!entries.contains(key)) return ESP_ERR_NVS_NOT_FOUND;
    const auto& value = entries.at(key);
    if (value.type != NVS_TYPE_U32 || value.bytes.size() != 4) return ESP_ERR_NVS_TYPE_MISMATCH;
    std::memcpy(out, value.bytes.data(), 4);
    return ESP_OK;
}

esp_err_t nvs_set_blob(nvs_handle_t handle, const char* key, const void* value, size_t length) {
    return mutate([&] {
        const auto* bytes = static_cast<const uint8_t*>(value);
        s_namespaces.at(s_handles.at(handle))[key] = {NVS_TYPE_BLOB, {bytes, bytes + length}};
    });
}

esp_err_t nvs_erase_key(nvs_handle_t handle, const char* key) {
    auto& entries = s_namespaces.at(s_handles.at(handle));
    if (!entries.contains(key)) return ESP_ERR_NVS_NOT_FOUND;
    return mutate([&] { entries.erase(key); });
}

esp_err_t nvs_commit(nvs_handle_t) { return mutate([] {}); }

struct nvs_iterator { size_t remaining; };

esp_err_t nvs_entry_find_in_handle(nvs_handle_t handle, nvs_type_t type, nvs_iterator_t* out) {
    if (!canRead()) return ESP_FAIL;
    TEST_ASSERT_EQUAL_INT(NVS_TYPE_ANY, type);
    const size_t size = s_namespaces.at(s_handles.at(handle)).size();
    if (size == 0) return ESP_ERR_NVS_NOT_FOUND;
    *out = new nvs_iterator{size};
    return ESP_OK;
}

esp_err_t nvs_entry_next(nvs_iterator_t* entry) {
    if (!canRead()) return ESP_FAIL;
    if (--(*entry)->remaining > 0) return ESP_OK;
    delete *entry;
    *entry = nullptr;
    return ESP_ERR_NVS_NOT_FOUND;
}

void nvs_release_iterator(nvs_iterator_t entry) { delete entry; }

namespace store {

esp_err_t usage(Usage& out) {
    if (!canRead()) return ESP_FAIL;
    out.availableEntries = s_available;
    return ESP_OK;
}

size_t reservedEntries(uint32_t nextSequence) {
    s_reserveSequence = nextSequence;
    return 100;
}

}

static DecodedBackup backup() {
    const std::array<uint8_t, 16> aesKey{1, 2, 3};
    const std::array<uint8_t, 2> emptyLabels{1, 0};
    LabelTable labels;
    TEST_ASSERT_TRUE(labels.put({7, true, "Entry", WeeklyWindow{0x1F, 480, 1080}}));
    const auto labelBytes = labels.encode();
    SeedTable seeds;
    seeds.year = 2026;
    seeds.confirmed = true;
    seeds.seeds[0] = {4, 0x123456789ULL};
    const auto seedBytes = encodeSeedTable(seeds);
    BackupLock lock;
    lock.mac = kMac;
    lock.address = {1, 0x53, 0, 0x5E, 0, 0};
    lock.addressType = 1;
    lock.protocol = {5, 3, 1, 1, 1};
    lock.aesKey = aesKey;
    lock.adminPs = 0x12345678;
    lock.unlockKey = 0x87654321;
    lock.lockFlagPos = 0x01020304;
    lock.features = 0x0102030405060708ULL;
    lock.adminPasscode = "123456789";
    lock.flags = 7;
    lock.lifecycle = 7;
    lock.provenance = AdminProvenance::Owner;
    lock.pendingAdminPasscode = "987654321";
    lock.pendingProvenance = AdminProvenance::PairingGenerated;
    lock.name = "Entry";
    lock.model = "Model";
    lock.hardware = "Hardware";
    lock.firmware = "Firmware";
    lock.manufactureDate = "2026-01-01";
    lock.labels = {labelBytes, emptyLabels, emptyLabels};
    lock.seeds = seedBytes;
    SensitiveBuffer bytes;
    TEST_ASSERT_EQUAL_INT(static_cast<int>(BackupStatus::Ok), static_cast<int>(encodeBackup({&lock, 1}, bytes)));
    DecodedBackup decoded;
    TEST_ASSERT_EQUAL_INT(static_cast<int>(BackupStatus::Ok), static_cast<int>(decodeBackup(std::move(bytes), decoded)));
    return decoded;
}

static bool pending() {
    const auto found = s_namespaces.find("restore");
    return found != s_namespaces.end() && found->second.contains("pending");
}

struct Publication final : RestorePublication {
    bool published = false;
    bool discarded = false;
    bool prepare(std::span<const BackupLock>) override { return true; }
    void publish() noexcept override { TEST_ASSERT_FALSE(pending()); published = true; }
    void discard() noexcept override { discarded = true; }
};

static void test_complete_restore_preserves_record_layout_and_exact_nested_bytes() {
    const auto decoded = backup();
    const auto& lock = decoded.locks()[0];
    key_store::Restore storage;
    Publication publication;
    TEST_ASSERT_EQUAL_INT(static_cast<int>(RestoreStatus::Ok),
                          static_cast<int>(restoreKeys(decoded, storage, publication)));
    TEST_ASSERT_TRUE(publication.published);
    TEST_ASSERT_EQUAL_UINT(sizeof(store::locks::Record), s_namespaces.at("locks").at(kKey).bytes.size());
    store::locks::Record record;
    TEST_ASSERT_EQUAL_INT(ESP_OK, key_store::loadRecord(kMac, record));
    TEST_ASSERT_EQUAL_UINT8(store::locks::kRecordVersion, record.version);
    TEST_ASSERT_EQUAL_UINT8(lock.flags, record.flags);
    TEST_ASSERT_EQUAL_STRING("Entry", record.name);
    TEST_ASSERT_EQUAL_MEMORY(lock.address.data(), record.address, 6);
    TEST_ASSERT_EQUAL_MEMORY(lock.aesKey.data(), record.aesKey, 16);
    TEST_ASSERT_EQUAL_UINT32(lock.adminPs, record.adminPs);
    TEST_ASSERT_EQUAL_UINT32(lock.unlockKey, record.unlockKey);
    TEST_ASSERT_EQUAL_UINT32(lock.lockFlagPos, record.lockFlagPos);
    TEST_ASSERT_EQUAL_UINT64(lock.features, record.features);
    TEST_ASSERT_EQUAL_STRING_LEN(lock.adminPasscode.data(), record.adminPasscode, lock.adminPasscode.size());
    TEST_ASSERT_EQUAL_STRING("Model", record.model);
    TEST_ASSERT_EQUAL_STRING("Hardware", record.hardware);
    TEST_ASSERT_EQUAL_STRING("Firmware", record.firmware);
    TEST_ASSERT_EQUAL_STRING("2026-01-01", record.manufactureDate);
    LockMetadata metadata;
    TEST_ASSERT_EQUAL_INT(ESP_OK, key_store::loadMetadata(kMac, metadata));
    TEST_ASSERT_EQUAL_UINT8(7, metadata.lifecycle);
    TEST_ASSERT_EQUAL_INT(static_cast<int>(AdminProvenance::Owner), static_cast<int>(metadata.provenance));
    TEST_ASSERT_TRUE(std::string_view(metadata.pendingAdminPasscode.data()) == lock.pendingAdminPasscode);
    for (size_t i = 0; i < 3; ++i) {
        const std::string labelKey = std::string(kKey) + "pfc"[i];
        const auto& bytes = s_namespaces.at("labels").at(labelKey).bytes;
        TEST_ASSERT_EQUAL_UINT(lock.labels[i].size(), bytes.size());
        TEST_ASSERT_EQUAL_MEMORY(lock.labels[i].data(), bytes.data(), bytes.size());
    }
    const auto& seeds = s_namespaces.at("seeds").at(kKey).bytes;
    TEST_ASSERT_EQUAL_MEMORY(lock.seeds.data(), seeds.data(), seeds.size());
    SeedTable table;
    bool present = false;
    TEST_ASSERT_EQUAL_INT(ESP_OK, key_store::loadSeeds(kMac, table, present));
    TEST_ASSERT_TRUE(present);
    TEST_ASSERT_EQUAL_UINT16(2026, table.year);
    TEST_ASSERT_EQUAL_UINT64(0x123456789ULL, table.seeds[0].secret);
    TEST_ASSERT_EQUAL_UINT32(1, s_reserveSequence);
}

static void test_unreadable_and_wrong_type_records_count_and_conflict_without_writes() {
    const auto decoded = backup();
    for (const auto type : {NVS_TYPE_BLOB, NVS_TYPE_U32}) {
        setUp();
        s_namespaces["locks"][kKey] = {type, {0xFF}};
        key_store::Restore storage;
        size_t count = 0;
        TEST_ASSERT_TRUE(storage.countRecords(count));
        TEST_ASSERT_EQUAL_UINT(1, count);
        Publication publication;
        TEST_ASSERT_EQUAL_INT(static_cast<int>(RestoreStatus::Conflict),
                              static_cast<int>(restoreKeys(decoded, storage, publication)));
        TEST_ASSERT_EQUAL_UINT(0, s_writes);
    }
}

static void test_every_orphan_namespace_conflicts_without_writes() {
    const auto decoded = backup();
    for (const auto* name : {"labels", "seeds", "lockmeta", "watch", "alerts"}) {
        setUp();
        const std::string key = std::string(kKey) + (std::string_view(name) == "labels" ? "p" : "");
        s_namespaces[name][key] = {NVS_TYPE_U32, {0xFF}};
        key_store::Restore storage;
        Publication publication;
        TEST_ASSERT_EQUAL_INT(static_cast<int>(RestoreStatus::Conflict),
                              static_cast<int>(restoreKeys(decoded, storage, publication)));
        TEST_ASSERT_EQUAL_UINT(0, s_writes);
    }
}

static void test_all_preflight_read_errors_stop_without_writes() {
    const auto decoded = backup();
    s_namespaces["locks"][kOtherKey] = {NVS_TYPE_BLOB, {9}};
    s_namespaces["audit"]["next"] = {NVS_TYPE_U32, {2, 0, 0, 0}};
    const auto before = s_namespaces;
    key_store::Restore storage;
    Publication publication;
    TEST_ASSERT_EQUAL_INT(static_cast<int>(RestoreStatus::Ok),
                          static_cast<int>(restoreKeys(decoded, storage, publication)));
    const size_t reads = s_preflightReads - 1;
    for (size_t i = 1; i <= reads; ++i) {
        setUp();
        s_namespaces = before;
        s_failRead = i;
        Publication attempt;
        TEST_ASSERT_EQUAL_INT(static_cast<int>(RestoreStatus::ReadFailed),
                              static_cast<int>(restoreKeys(decoded, storage, attempt)));
        TEST_ASSERT_EQUAL_UINT(0, s_writes);
        TEST_ASSERT_TRUE(s_namespaces == before);
    }
}

static void test_nvs_failures_before_and_after_every_mutation_keep_existing_records() {
    const auto decoded = backup();
    s_namespaces["locks"][kOtherKey] = {NVS_TYPE_BLOB, {9}};
    key_store::Restore storage;
    Publication publication;
    TEST_ASSERT_EQUAL_INT(static_cast<int>(RestoreStatus::Ok),
                          static_cast<int>(restoreKeys(decoded, storage, publication)));
    const size_t boundaries = s_writes;
    TEST_ASSERT_GREATER_THAN_UINT(16, boundaries);
    for (size_t boundary = 1; boundary <= boundaries; ++boundary) {
        for (const bool after : {false, true}) {
            setUp();
            s_namespaces["locks"][kOtherKey] = {NVS_TYPE_BLOB, {9}};
            s_failWrite = boundary;
            s_failAfter = after;
            key_store::Restore attemptStorage;
            Publication attempt;
            const auto status = restoreKeys(decoded, attemptStorage, attempt);
            TEST_ASSERT_NOT_EQUAL(static_cast<int>(RestoreStatus::Ok), static_cast<int>(status));
            TEST_ASSERT_FALSE(attempt.published);
            TEST_ASSERT_EQUAL_UINT8(9, s_namespaces.at("locks").at(kOtherKey).bytes[0]);
            if (status == RestoreStatus::RecoveryRequired && !pending()) {
                TEST_ASSERT_TRUE(s_namespaces.at("locks").contains(kKey));
                TEST_ASSERT_EQUAL_UINT(boundary, s_writes);
            } else {
                TEST_ASSERT_EQUAL_INT(static_cast<int>(RestoreStatus::WriteFailed), static_cast<int>(status));
                TEST_ASSERT_FALSE(s_namespaces.at("locks").contains(kKey));
            }
            s_failWrite = 0;
            TEST_ASSERT_EQUAL_INT(ESP_OK, key_store::recover());
            TEST_ASSERT_FALSE(pending());
        }
    }
}

static void test_metadata_absence_is_legacy_but_corruption_and_read_failures_are_errors() {
    LockMetadata metadata;
    metadata.provenance = AdminProvenance::Owner;
    TEST_ASSERT_EQUAL_INT(ESP_OK, key_store::loadMetadata(kMac, metadata));
    TEST_ASSERT_EQUAL_INT(static_cast<int>(AdminProvenance::LegacyUnknown), static_cast<int>(metadata.provenance));
    for (const auto bytes : {std::vector<uint8_t>{1}, std::vector<uint8_t>(kLockMetadataBytes, 0xFF)}) {
        s_namespaces["lockmeta"][kKey] = {NVS_TYPE_BLOB, bytes};
        TEST_ASSERT_NOT_EQUAL(ESP_OK, key_store::loadMetadata(kMac, metadata));
    }
    s_namespaces["lockmeta"][kKey] = {NVS_TYPE_U32, {1}};
    TEST_ASSERT_NOT_EQUAL(ESP_OK, key_store::loadMetadata(kMac, metadata));
    s_failRead = s_reads + 1;
    TEST_ASSERT_EQUAL_INT(ESP_FAIL, key_store::loadMetadata(kMac, metadata));
}

static void test_metadata_save_and_erase_propagate_persistence_failures() {
    LockMetadata metadata;
    metadata.lifecycle = kBackupBackedUp;
    TEST_ASSERT_EQUAL_INT(ESP_OK, key_store::saveMetadata(kMac, metadata));
    LockMetadata loaded;
    TEST_ASSERT_EQUAL_INT(ESP_OK, key_store::loadMetadata(kMac, loaded));
    TEST_ASSERT_EQUAL_UINT8(kBackupBackedUp, loaded.lifecycle);
    s_failWrite = s_writes + 1;
    TEST_ASSERT_EQUAL_INT(ESP_FAIL, key_store::saveMetadata(kMac, metadata));
    s_failWrite = s_writes + 1;
    TEST_ASSERT_EQUAL_INT(ESP_FAIL, key_store::eraseMetadata(kMac));
    s_failWrite = 0;
    TEST_ASSERT_EQUAL_INT(ESP_OK, key_store::eraseMetadata(kMac));
    TEST_ASSERT_FALSE(s_namespaces.at("lockmeta").contains(kKey));
}

static void test_strict_record_reads_reject_truncation_identity_version_and_unterminated_text() {
    store::locks::Record record;
    TEST_ASSERT_NOT_EQUAL(ESP_OK, key_store::loadRecord(kMac, record));
    for (const size_t length : {size_t{1}, sizeof(record) - 1, sizeof(record) + 1}) {
        s_namespaces["locks"][kKey] = {NVS_TYPE_BLOB, std::vector<uint8_t>(length)};
        TEST_ASSERT_NOT_EQUAL(ESP_OK, key_store::loadRecord(kMac, record));
    }
    const auto decoded = backup();
    s_namespaces.clear();
    key_store::Restore storage;
    Publication publication;
    TEST_ASSERT_EQUAL_INT(static_cast<int>(RestoreStatus::Ok),
                          static_cast<int>(restoreKeys(decoded, storage, publication)));
    const auto valid = s_namespaces.at("locks").at(kKey).bytes;
    for (const size_t index : {offsetof(store::locks::Record, version), offsetof(store::locks::Record, mac)}) {
        auto& bytes = s_namespaces["locks"][kKey].bytes;
        bytes = valid;
        bytes[index] = 0xFF;
        TEST_ASSERT_NOT_EQUAL(ESP_OK, key_store::loadRecord(kMac, record));
    }
    auto& bytes = s_namespaces["locks"][kKey].bytes;
    bytes = valid;
    std::memset(bytes.data() + offsetof(store::locks::Record, name), 'X', sizeof(record.name));
    TEST_ASSERT_NOT_EQUAL(ESP_OK, key_store::loadRecord(kMac, record));
}

static void test_seed_absence_differs_from_corrupt_or_unreadable_seed_records() {
    SeedTable table;
    bool present = true;
    TEST_ASSERT_EQUAL_INT(ESP_OK, key_store::loadSeeds(kMac, table, present));
    TEST_ASSERT_FALSE(present);
    s_namespaces["seeds"][kKey] = {NVS_TYPE_BLOB, {0xFF}};
    TEST_ASSERT_NOT_EQUAL(ESP_OK, key_store::loadSeeds(kMac, table, present));
    s_failRead = s_reads + 1;
    TEST_ASSERT_EQUAL_INT(ESP_FAIL, key_store::loadSeeds(kMac, table, present));
}

static void test_unreadable_journal_blocks_boot_recovery_without_deletion() {
    s_namespaces["restore"]["pending"] = {NVS_TYPE_BLOB, {0xFF}};
    s_namespaces["locks"][kKey] = {NVS_TYPE_BLOB, {9}};
    const auto before = s_namespaces;
    TEST_ASSERT_NOT_EQUAL(ESP_OK, key_store::recover());
    TEST_ASSERT_TRUE(s_namespaces == before);
    TEST_ASSERT_EQUAL_UINT(0, s_writes);
}

static void test_boot_recovery_retries_failed_cleanup_and_retains_only_existing_records() {
    const auto decoded = backup();
    key_store::Restore storage;
    RestoreJournal journal;
    journal.count = 1;
    std::memcpy(journal.identities[0].data(), kMac.data(), kMac.size());
    TEST_ASSERT_TRUE(storage.writeJournal(journal));
    for (const auto part : kRestoreParts) TEST_ASSERT_TRUE(storage.writePart(decoded.locks()[0], part));
    s_namespaces["locks"][kOtherKey] = {NVS_TYPE_BLOB, {9}};
    const auto interrupted = s_namespaces;
    s_writes = 0;
    TEST_ASSERT_EQUAL_INT(ESP_OK, key_store::recover());
    const size_t boundaries = s_writes;
    TEST_ASSERT_EQUAL_UINT(14, boundaries);
    for (size_t boundary = 1; boundary <= boundaries; ++boundary) {
        for (const bool after : {false, true}) {
            setUp();
            s_namespaces = interrupted;
            s_failWrite = boundary;
            s_failAfter = after;
            TEST_ASSERT_NOT_EQUAL(ESP_OK, key_store::recover());
            TEST_ASSERT_EQUAL_UINT(boundary, s_writes);
            TEST_ASSERT_EQUAL_INT(!(boundary == 14 || (boundary == 13 && after)), pending());
            s_failWrite = 0;
            TEST_ASSERT_EQUAL_INT(ESP_OK, key_store::recover());
            TEST_ASSERT_FALSE(pending());
            TEST_ASSERT_EQUAL_UINT(1, s_namespaces.at("locks").size());
            TEST_ASSERT_EQUAL_UINT8(9, s_namespaces.at("locks").at(kOtherKey).bytes[0]);
            for (const auto* name : {"labels", "seeds", "lockmeta"}) TEST_ASSERT_TRUE(s_namespaces.at(name).empty());
        }
    }
}

int main() {
    UNITY_BEGIN();
    RUN_TEST(test_complete_restore_preserves_record_layout_and_exact_nested_bytes);
    RUN_TEST(test_unreadable_and_wrong_type_records_count_and_conflict_without_writes);
    RUN_TEST(test_every_orphan_namespace_conflicts_without_writes);
    RUN_TEST(test_all_preflight_read_errors_stop_without_writes);
    RUN_TEST(test_nvs_failures_before_and_after_every_mutation_keep_existing_records);
    RUN_TEST(test_metadata_absence_is_legacy_but_corruption_and_read_failures_are_errors);
    RUN_TEST(test_metadata_save_and_erase_propagate_persistence_failures);
    RUN_TEST(test_strict_record_reads_reject_truncation_identity_version_and_unterminated_text);
    RUN_TEST(test_seed_absence_differs_from_corrupt_or_unreadable_seed_records);
    RUN_TEST(test_unreadable_journal_blocks_boot_recovery_without_deletion);
    RUN_TEST(test_boot_recovery_retries_failed_cleanup_and_retains_only_existing_records);
    return UNITY_END();
}
