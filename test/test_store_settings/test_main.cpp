// SPDX-License-Identifier: GPL-3.0-or-later
#include "latchkey_util/key_restore.h"
#include "store_test_runtime.h"

static size_t passwordWipes;
static size_t recordWipes;

void setUp() { resetNvsFixture(); passwordWipes = 0; }
void tearDown() { zeroize_fixture::observe = nullptr; clearNvsFixture(); }

static void test_loading_mqtt_wipes_the_replaced_password_and_preserves_fields() {
    store::cfg::Mqtt saved;
    saved.enabled = true;
    saved.host = "broker.example";
    saved.password = "fixture-pass";
    TEST_ASSERT_EQUAL_INT(ESP_OK, store::cfg::saveMqtt(saved));
    store::cfg::Mqtt loaded;
    loaded.password = "previous-pass";
    zeroize_fixture::observe = [](void* data, size_t length) {
        if (length == 13 && std::memcmp(data, "previous-pass", length) == 0) ++passwordWipes;
    };
    TEST_ASSERT_EQUAL_INT(ESP_OK, store::cfg::loadMqtt(loaded));
    TEST_ASSERT_EQUAL_UINT(1, passwordWipes);
    TEST_ASSERT_TRUE(loaded.password == saved.password);
    TEST_ASSERT_TRUE(loaded.host == saved.host);
    TEST_ASSERT_TRUE(loaded.enabled);
}

static void test_seed_table_uses_the_capacity_already_reserved_for_pairing() {
    s_available = store::reservedEntries();
    latchkey_util::SeedTable table;
    table.year = 2026;
    TEST_ASSERT_EQUAL_INT(ESP_OK, store::seeds::save(kMac.data(), table));
    latchkey_util::SeedTable loaded;
    bool present = false;
    TEST_ASSERT_EQUAL_INT(ESP_OK, key_store::loadSeeds(kMac, loaded, present));
    TEST_ASSERT_TRUE(present);
    TEST_ASSERT_EQUAL_UINT(2026, loaded.year);
}

static void test_seed_table_storage_failure_is_reported_without_success() {
    latchkey_util::SeedTable table;
    table.year = 2026;
    s_failWrite = 1;
    TEST_ASSERT_EQUAL_INT(ESP_FAIL, store::seeds::save(kMac.data(), table));
}

static void test_loading_wifi_wipes_password_temporaries_on_success_and_incomplete_records() {
    store::cfg::Wifi saved;
    saved.ssid = "fixture";
    saved.password = "fixture-pass";
    TEST_ASSERT_EQUAL_INT(ESP_OK, store::cfg::saveWifi(saved));
    zeroize_fixture::observe = [](void* data, size_t length) {
        if (length == 12 && std::memcmp(data, "fixture-pass", length) == 0) ++passwordWipes;
    };
    for (bool complete : {true, false}) {
        if (!complete) s_namespaces["cfg"].erase("gateway");
        store::cfg::Wifi loaded;
        passwordWipes = 0;
        TEST_ASSERT_EQUAL_INT(complete, store::cfg::loadWifi(loaded));
        TEST_ASSERT_EQUAL_UINT(2, passwordWipes);
        if (complete) TEST_ASSERT_TRUE(loaded.password == saved.password);
    }
}

static void test_listing_records_wipes_stack_and_partial_failure_copies() {
    store::locks::Record record;
    record.version = store::locks::kRecordVersion;
    record.aesKey[0] = 0xA5;
    const auto* bytes = reinterpret_cast<const uint8_t*>(&record);
    s_namespaces["locks"][kKey] = {NVS_TYPE_BLOB, {bytes, bytes + sizeof(record)}};
    zeroize_fixture::observe = [](void* data, size_t length) {
        if (length == sizeof(store::locks::Record) &&
            static_cast<store::locks::Record*>(data)->aesKey[0] == 0xA5) ++recordWipes;
    };
    for (bool fails : {false, true}) {
        recordWipes = 0;
        s_failRead = fails ? s_reads + 4 : 0;
        std::vector<store::locks::Record> loaded;
        TEST_ASSERT_EQUAL_INT(fails ? ESP_FAIL : ESP_OK, store::locks::list(loaded));
        TEST_ASSERT_EQUAL_UINT(fails ? 2 : 1, recordWipes);
        TEST_ASSERT_EQUAL_UINT(fails ? 0 : 1, loaded.size());
    }
}

static void test_listing_excess_records_fails_without_partial_publication() {
    store::locks::Record record;
    record.version = store::locks::kRecordVersion;
    const auto* bytes = reinterpret_cast<const uint8_t*>(&record);
    for (size_t i = 0; i <= store::locks::kMaxLocks; ++i) {
        s_namespaces["locks"][std::to_string(i)] = {NVS_TYPE_BLOB, {bytes, bytes + sizeof(record)}};
    }
    std::vector<store::locks::Record> loaded;
    TEST_ASSERT_EQUAL_INT(ESP_ERR_INVALID_SIZE, store::locks::list(loaded));
    TEST_ASSERT_TRUE(loaded.empty());
}

int main() {
    UNITY_BEGIN();
    RUN_TEST(test_loading_mqtt_wipes_the_replaced_password_and_preserves_fields);
    RUN_TEST(test_seed_table_uses_the_capacity_already_reserved_for_pairing);
    RUN_TEST(test_seed_table_storage_failure_is_reported_without_success);
    RUN_TEST(test_loading_wifi_wipes_password_temporaries_on_success_and_incomplete_records);
    RUN_TEST(test_listing_records_wipes_stack_and_partial_failure_copies);
    RUN_TEST(test_listing_excess_records_fails_without_partial_publication);
    return UNITY_END();
}
