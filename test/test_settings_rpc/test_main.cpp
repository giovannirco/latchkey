// SPDX-License-Identifier: GPL-3.0-or-later
#include "lock_manager_test_runtime.h"
#include "../reference/backup_fixture.h"
#include "../reference/hmac_sha256.h"
#include "../../src/methods_settings.cpp"


void setUp() { resetManagerFixture(); }
void tearDown() { clearManagerFixture(); }

static void seed(bool backedUp) {
    const auto decoded = backup_fixture::make();
    store::locks::Record record;
    TEST_ASSERT_TRUE(key_store::makeRecord(decoded.locks()[0], record));
    record.features = ttlock::featureBit(ttlock::Feature::ResetButton);
    TEST_ASSERT_EQUAL_INT(ESP_OK, lock_manager::persist(record));
    latchkey_util::LockMetadata metadata;
    metadata.lifecycle = backedUp ? latchkey_util::kBackupBackedUp : 0;
    TEST_ASSERT_EQUAL_INT(ESP_OK, key_store::saveMetadata(kMac, metadata));
    bluetoothCalls = 0;
}

static void refuses(const char* code, bool enabled = false) {
    const std::string input = std::string(R"({"method":"lock.resetButton.set","params":{"lock":"00:00:5E:00:53:01","enabled":)") +
                              (enabled ? "true}}" : "false}}");
    const auto response = dispatchRequest(request(input), rpc::Transport::Serial, {});
    TEST_ASSERT_TRUE(hasError(response, code));
    TEST_ASSERT_EQUAL_UINT(0, bluetoothCalls);
    TEST_ASSERT_EQUAL_UINT(0, confirmations);
}

static void test_reset_disable_requires_backup() {
    seed(false);
    refuses("backup_required");
}

static void test_backed_up_reset_disable_remains_unverified_without_bluetooth() {
    seed(true);
    refuses("unverified");
}

static void test_unreadable_backup_state_fails_closed_without_bluetooth() {
    seed(true);
    s_namespaces["lockmeta"][kKey] = {NVS_TYPE_BLOB, {255}};
    refuses("internal");
}

static void test_reset_enable_remains_unverified_without_backup() {
    seed(false);
    refuses("unverified", true);
}

int main() {
    rpc::init();
    methods::registerSettings();
    UNITY_BEGIN();
    RUN_TEST(test_reset_disable_requires_backup);
    RUN_TEST(test_backed_up_reset_disable_remains_unverified_without_bluetooth);
    RUN_TEST(test_unreadable_backup_state_fails_closed_without_bluetooth);
    RUN_TEST(test_reset_enable_remains_unverified_without_backup);
    return UNITY_END();
}
