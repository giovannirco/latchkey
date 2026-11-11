// SPDX-License-Identifier: GPL-3.0-or-later
#include "lock_manager_test_runtime.h"
#include "../reference/backup_fixture.h"

void setUp() { resetManagerFixture(); }
void tearDown() { clearManagerFixture(); }

static store::locks::Record seed() {
    const auto decoded = backup_fixture::make();
    store::locks::Record record;
    TEST_ASSERT_TRUE(key_store::makeRecord(decoded.locks()[0], record));
    TEST_ASSERT_EQUAL_INT(ESP_OK, lock_manager::persist(record));
    return record;
}

static ttlock::LogEntry fingerprint(uint16_t sequence) {
    ttlock::LogEntry entry;
    entry.type = 23;
    entry.recordNumber = sequence;
    entry.time = {2026, 1, 1, 12, 0, 0};
    entry.battery = 70;
    entry.credential = "17";
    return entry;
}

static void test_fetch_resolves_the_saved_label_and_respects_pagination_without_raw_credentials() {
    const auto record = seed();
    latchkey_util::LabelTable names;
    names.put({17, false, "Entry finger", {}});
    s_namespaces["labels"][std::string(kKey) + 'f'] = {NVS_TYPE_BLOB, names.encode()};
    lock_log::Entries entries;
    for (uint16_t sequence : {3, 4, 5}) {
        auto entry = fingerprint(sequence);
        entries.add(entry);
    }
    auto reply = lock_log::fetchResult(entries, 3, 5, true, {}, 0, record);
    TEST_ASSERT_TRUE(reply.error.empty());
    const auto rendered = rpc::render(std::move(reply.result));
    rpc::Json result(cJSON_Parse(rendered.c_str()));
    const auto* listed = cJSON_GetObjectItemCaseSensitive(result.get(), "entries");
    TEST_ASSERT_EQUAL_INT(1, cJSON_GetArraySize(listed));
    const auto* item = cJSON_GetArrayItem(listed, 0);
    const auto* identity = cJSON_GetObjectItemCaseSensitive(item, "credential");
    TEST_ASSERT_EQUAL_STRING("Entry finger", cJSON_GetStringValue(cJSON_GetObjectItemCaseSensitive(identity, "name")));
    TEST_ASSERT_EQUAL_INT(4, cJSON_GetObjectItemCaseSensitive(result.get(), "last")->valueint);
    TEST_ASSERT_TRUE(cJSON_IsTrue(cJSON_GetObjectItemCaseSensitive(result.get(), "more")));
}

static void test_names_are_retained_before_removal_and_remain_after_reboot() {
    seed();
    latchkey_util::LabelTable names;
    names.put({17, false, "Entry finger", {}});
    s_namespaces["labels"][std::string(kKey) + 'f'] = {NVS_TYPE_BLOB, names.encode()};
    TEST_ASSERT_EQUAL_INT(ESP_OK, lock_manager::retainLabels(std::string(kMac), store::labels::Kind::Fingerprints, {}));
    latchkey_util::LabelTable current;
    TEST_ASSERT_EQUAL_INT(ESP_OK, lock_manager::loadLabels(std::string(kMac), store::labels::Kind::Fingerprints, current));
    TEST_ASSERT_NOT_NULL(current.find(17));
    TEST_ASSERT_EQUAL_INT(ESP_OK, lock_manager::saveLabels(std::string(kMac), store::labels::Kind::Fingerprints, {}));
    lock_manager::s_locks = {};
    lock_manager::s_lockCount = 0;
    lock_manager::start();
    latchkey_util::LogLabels loaded;
    TEST_ASSERT_EQUAL_INT(ESP_OK, lock_manager::loadLogLabels(std::string(kMac), loaded));
    TEST_ASSERT_NULL(loaded.fingerprints.find(17));
    TEST_ASSERT_NOT_NULL(loaded.retired.find('f', 17));
    TEST_ASSERT_EQUAL_STRING("Entry finger", loaded.retired.find('f', 17)->name.c_str());
}

static void test_retention_failure_prevents_active_name_removal_and_log_loading_fails_explicitly() {
    const auto record = seed();
    latchkey_util::LabelTable names;
    names.put({17, false, "Entry finger", {}});
    const std::string key = std::string(kKey) + 'f';
    s_namespaces["labels"][key] = {NVS_TYPE_BLOB, names.encode()};
    s_failWrite = s_writes + 1;
    TEST_ASSERT_NOT_EQUAL(ESP_OK, lock_manager::saveLabels(std::string(kMac), store::labels::Kind::Fingerprints, {}));
    TEST_ASSERT_TRUE(s_namespaces["labels"][key].bytes == names.encode());
    s_failWrite = 0;
    s_namespaces["labels"][kKey] = {NVS_TYPE_BLOB, {255}};
    lock_log::Entries entries;
    auto entry = fingerprint(4);
    entries.add(entry);
    auto reply = lock_log::fetchResult(entries, {}, 5, false, {}, 0, record);
    TEST_ASSERT_FALSE(reply.error.empty());
    TEST_ASSERT_NULL(reply.result.get());
}

static void test_initial_fetch_returns_only_the_last_sixteen_slots_even_after_a_long_catchup() {
    const auto record = seed();
    lock_log::Entries entries;
    for (uint16_t sequence = 0; sequence < 20; ++sequence) {
        auto entry = fingerprint(sequence);
        entries.add(entry);
    }
    auto reply = lock_log::fetchResult(entries, {}, 20, false, {}, 0, record);
    TEST_ASSERT_TRUE(reply.error.empty());
    const auto rendered = rpc::render(std::move(reply.result));
    rpc::Json result(cJSON_Parse(rendered.c_str()));
    const auto* listed = cJSON_GetObjectItemCaseSensitive(result.get(), "entries");
    TEST_ASSERT_EQUAL_INT(16, cJSON_GetArraySize(listed));
    TEST_ASSERT_EQUAL_INT(4, cJSON_GetObjectItemCaseSensitive(cJSON_GetArrayItem(listed, 0), "seq")->valueint);
}

static void test_every_result_allocation_failure_returns_an_explicit_error() {
    const auto record = seed();
    lock_log::Entries entries;
    auto entry = fingerprint(4);
    entries.add(entry);
    allocationAttempts = 0;
    auto success = lock_log::fetchResult(entries, {}, 5, false, {}, 0, record);
    TEST_ASSERT_TRUE(success.error.empty());
    const size_t allocations = allocationAttempts;
    for (size_t at = 1; at <= allocations; ++at) {
        allocationAttempts = 0;
        failAllocation = at;
        auto reply = lock_log::fetchResult(entries, {}, 5, false, {}, 0, record);
        failAllocation = 0;
        TEST_ASSERT_FALSE(reply.error.empty());
        TEST_ASSERT_NULL(reply.result.get());
    }
}

static void test_reusing_an_id_invalidates_only_its_retired_name_and_reports_storage_failure() {
    seed();
    latchkey_util::RetiredLabels retired;
    retired.remember('f', 17, "Old finger");
    retired.remember('c', 17, "Old card");
    retired.remember('f', 18, "Other finger");
    TEST_ASSERT_EQUAL_INT(ESP_OK, store::labels::saveRetired(kMac.data(), retired));
    s_failWrite = s_writes + 1;
    TEST_ASSERT_NOT_EQUAL(ESP_OK, lock_manager::forgetRetiredLabel(std::string(kMac), store::labels::Kind::Fingerprints, 17));
    s_failWrite = 0;
    TEST_ASSERT_EQUAL_INT(ESP_OK, lock_manager::forgetRetiredLabel(std::string(kMac), store::labels::Kind::Fingerprints, 17));
    TEST_ASSERT_EQUAL_INT(ESP_OK, store::labels::loadRetired(kMac.data(), retired));
    TEST_ASSERT_NULL(retired.find('f', 17));
    TEST_ASSERT_NOT_NULL(retired.find('c', 17));
    TEST_ASSERT_NOT_NULL(retired.find('f', 18));
    const auto writes = s_writes;
    TEST_ASSERT_EQUAL_INT(ESP_OK, lock_manager::forgetRetiredLabel(std::string(kMac), store::labels::Kind::Fingerprints, 17));
    TEST_ASSERT_EQUAL_UINT(writes, s_writes);
}

int main() {
    rpc::init();
    UNITY_BEGIN();
    RUN_TEST(test_fetch_resolves_the_saved_label_and_respects_pagination_without_raw_credentials);
    RUN_TEST(test_names_are_retained_before_removal_and_remain_after_reboot);
    RUN_TEST(test_retention_failure_prevents_active_name_removal_and_log_loading_fails_explicitly);
    RUN_TEST(test_initial_fetch_returns_only_the_last_sixteen_slots_even_after_a_long_catchup);
    RUN_TEST(test_every_result_allocation_failure_returns_an_explicit_error);
    RUN_TEST(test_reusing_an_id_invalidates_only_its_retired_name_and_reports_storage_failure);
    return UNITY_END();
}
