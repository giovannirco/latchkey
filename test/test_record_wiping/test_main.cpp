// SPDX-License-Identifier: GPL-3.0-or-later
#include "lock_manager_test_runtime.h"
#include "../reference/backup_fixture.h"
#include "../fake_lock/fake_lock.h"
#include "ttlock/commands.h"

static size_t recordWipes;

void setUp() {
    resetManagerFixture();
    const auto decoded = backup_fixture::make();
    store::locks::Record record;
    TEST_ASSERT_TRUE(key_store::makeRecord(decoded.locks()[0], record));
    std::memset(record.aesKey, 0xA5, sizeof(record.aesKey));
    TEST_ASSERT_EQUAL_INT(ESP_OK, lock_manager::persist(record));
    recordWipes = 0;
    zeroize_fixture::observe = [](void* data, size_t length) {
        if (length != sizeof(store::locks::Record)) return;
        const auto* record = static_cast<const store::locks::Record*>(data);
        if (record->aesKey[0] == 0xA5 && std::string_view(record->mac) == kMac) ++recordWipes;
    };
}

void tearDown() {
    zeroize_fixture::observe = nullptr;
    clearManagerFixture();
}

static void test_update_record_wipes_its_copy_on_success_and_storage_failure() {
    for (bool fails : {false, true}) {
        s_failWrite = fails ? s_writes + 1 : 0;
        recordWipes = 0;
        const bool saved = lock_manager::updateRecord(kMac, [](auto& record) { record.features = 123; });
        TEST_ASSERT_EQUAL_INT(!fails, saved);
        TEST_ASSERT_EQUAL_UINT(1, recordWipes);
    }
}

static void test_rename_wipes_its_copy_on_success_and_storage_failure() {
    for (bool fails : {false, true}) {
        s_failWrite = fails ? s_writes + 1 : 0;
        recordWipes = 0;
        const auto reply = lock_manager::rename(std::string(kMac), "Entry");
        TEST_ASSERT_EQUAL_INT(!fails, reply.error.empty());
        TEST_ASSERT_EQUAL_UINT(1, recordWipes);
    }
}

static void test_device_info_wipes_both_record_copies_after_readback() {
    fake::FakeLock radio;
    fake::FakeClock clock;
    fake::FakeRandom random;
    ttlock::Session session(radio, clock, random);
    const auto* lock = lock_manager::findLocked(kMac);
    auto keys = lock_manager::keysOf(lock->record);
    TEST_ASSERT_EQUAL_INT(static_cast<int>(ttlock::Status::Ok), static_cast<int>(session.attach(keys)));
    radio.expect(ttlock::command::kCheckAdmin, keys.aesKey,
                 {fake::success(keys.aesKey, ttlock::command::kCheckAdmin, fake::be32(0x11223344))});
    radio.expect(ttlock::command::kCheckRandom, keys.aesKey,
                 {fake::success(keys.aesKey, ttlock::command::kCheckRandom)});
    for (const char* value : {"LK100", "1.3", "6.4.43", "20250101"}) {
        auto payload = fake::text(value);
        payload.push_back(0);
        radio.expect(ttlock::command::kReadDeviceInfo, keys.aesKey,
                     {fake::success(keys.aesKey, ttlock::command::kReadDeviceInfo, payload)});
    }
    rpc::Reply reply;
    TEST_ASSERT_EQUAL_INT(static_cast<int>(ttlock::Status::Ok),
                          static_cast<int>(lock_manager::readInfo(session, *lock, reply)));
    TEST_ASSERT_TRUE(radio.scriptDone());
    TEST_ASSERT_EQUAL_UINT(2, recordWipes);
}

static void test_startup_wipes_loaded_record_copies_after_publication() {
    lock_manager::s_locks = {};
    lock_manager::s_lockCount = 0;
    recordWipes = 0;
    lock_manager::start();
    TEST_ASSERT_NOT_NULL(lock_manager::findLocked(kMac));
    TEST_ASSERT_EQUAL_UINT(1, recordWipes);
}

int main() {
    rpc::init();
    UNITY_BEGIN();
    RUN_TEST(test_update_record_wipes_its_copy_on_success_and_storage_failure);
    RUN_TEST(test_rename_wipes_its_copy_on_success_and_storage_failure);
    RUN_TEST(test_device_info_wipes_both_record_copies_after_readback);
    RUN_TEST(test_startup_wipes_loaded_record_copies_after_publication);
    return UNITY_END();
}
