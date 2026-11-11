// SPDX-License-Identifier: GPL-3.0-or-later
#include "lock_manager_test_runtime.h"
#include "../reference/backup_fixture.h"
#include "../fake_lock/fake_lock.h"
#include "../../src/methods_passcodes.cpp"

void setUp() { resetManagerFixture(); }
void tearDown() { clearManagerFixture(); }

struct Rig {
    fake::FakeLock lock;
    ttlock::AesKey key{};
    std::string id;
    Rig() {
        bluetoothReady = true;
        fixtureTransport = &lock;
        const auto decoded = backup_fixture::make();
        store::locks::Record record;
        TEST_ASSERT_TRUE(key_store::makeRecord(decoded.locks()[0], record));
        std::copy(std::begin(record.aesKey), std::end(record.aesKey), key.begin());
        record.features = ttlock::featureBit(ttlock::Feature::Passcode) | ttlock::featureBit(ttlock::Feature::ModifyPasscodeFunction);
        record.flags |= store::locks::kFlagTimeCalibrated;
        TEST_ASSERT_EQUAL_INT(ESP_OK, lock_manager::persist(record));
        latchkey_util::PasscodeId number;
        TEST_ASSERT_TRUE(latchkey_util::passcodeId(key, "482613", hmac::sha256, number));
        id = latchkey_util::formatPasscodeId(number);
        latchkey_util::LabelTable labels;
        labels.put({latchkey_util::passcodeIdNumber(number), true, "Entry PIN", {}});
        s_namespaces["labels"][std::string(kKey) + 'p'] = {NVS_TYPE_BLOB, labels.encode()};
    }
    void list(bool empty = false) {
        const auto command = ttlock::command::kPasscodeList;
        lock.expect(ttlock::command::kCheckAdmin, key, {fake::success(key, ttlock::command::kCheckAdmin, fake::be32(1))});
        lock.expect(ttlock::command::kCheckRandom, key, {fake::success(key, ttlock::command::kCheckRandom)});
        ttlock::Bytes page{0, 1, 0, 0};
        if (!empty) {
            ttlock::Bytes item{static_cast<uint8_t>(ttlock::PasscodeType::Permanent), 6, '4', '8', '2', '6', '1', '3', 0, 26, 1, 1, 0, 0};
            page.push_back(item.size());
            page.insert(page.end(), item.begin(), item.end());
        }
        lock.expect(command, key, {fake::success(key, command, page)});
    }
    rpc::Json params() const {
        rpc::Json out(cJSON_CreateObject());
        cJSON_AddStringToObject(out.get(), "lock", kMac.data());
        cJSON_AddStringToObject(out.get(), "id", id.c_str());
        return out;
    }
};

static void test_failed_retention_prevents_pin_delete_clear_and_replacement() {
    for (unsigned operation = 0; operation < 3; ++operation) {
        resetManagerFixture();
        Rig rig;
        if (operation != 1) rig.list();
        s_failWrite = s_writes + 1;
        auto input = rig.params();
        rpc::Reply reply;
        const rpc::Context context{rpc::Transport::Serial, {}};
        if (operation == 0) reply = methods::passcodesDelete(input.get(), context);
        else if (operation == 1) reply = methods::passcodesClear(input.get(), context);
        else {
            cJSON_AddStringToObject(input.get(), "code", "751946");
            reply = methods::passcodesUpdate(input.get(), context);
        }
        TEST_ASSERT_FALSE(reply.error.empty());
        TEST_ASSERT_EQUAL_UINT(0, rig.lock.unexpected());
        TEST_ASSERT_TRUE(rig.lock.scriptDone());
    }
}

static void test_failed_pin_pruning_is_reported() {
    Rig rig;
    rig.list(true);
    s_failWrite = s_writes + 1;
    const auto input = rig.params();
    const auto reply = methods::passcodesList(input.get(), {rpc::Transport::Serial, {}});
    TEST_ASSERT_TRUE(rig.lock.scriptDone());
    TEST_ASSERT_EQUAL_UINT(0, rig.lock.unexpected());
    TEST_ASSERT_FALSE(reply.error.empty());
}

static void test_successful_pin_delete_retains_only_the_opaque_id_and_label() {
    Rig rig;
    rig.list();
    rig.lock.expect(ttlock::command::kCheckAdmin, rig.key, {fake::success(rig.key, ttlock::command::kCheckAdmin, fake::be32(1))});
    rig.lock.expect(ttlock::command::kCheckRandom, rig.key, {fake::success(rig.key, ttlock::command::kCheckRandom)});
    rig.lock.expect(ttlock::command::kManageKeyboardPassword, rig.key, {fake::success(rig.key, ttlock::command::kManageKeyboardPassword)});
    const auto input = rig.params();
    const auto reply = methods::passcodesDelete(input.get(), {rpc::Transport::Serial, {}});
    TEST_ASSERT_TRUE(reply.error.empty());
    TEST_ASSERT_EQUAL_UINT(0, rig.lock.unexpected());
    TEST_ASSERT_TRUE(rig.lock.scriptDone());
    latchkey_util::LogLabels labels;
    TEST_ASSERT_EQUAL_INT(ESP_OK, lock_manager::loadLogLabels(std::string(kMac), labels));
    latchkey_util::PasscodeId id;
    TEST_ASSERT_TRUE(latchkey_util::parsePasscodeId(rig.id, id));
    TEST_ASSERT_NULL(labels.passcodes.find(latchkey_util::passcodeIdNumber(id)));
    const auto* retired = labels.retired.find('p', latchkey_util::passcodeIdNumber(id));
    TEST_ASSERT_NOT_NULL(retired);
    TEST_ASSERT_EQUAL_STRING("Entry PIN", retired->name.c_str());
    const auto bytes = labels.retired.encode();
    const std::string raw(bytes.begin(), bytes.end());
    TEST_ASSERT_TRUE(raw.find("482613") == std::string::npos);
}

int main() {
    rpc::init();
    UNITY_BEGIN();
    RUN_TEST(test_failed_retention_prevents_pin_delete_clear_and_replacement);
    RUN_TEST(test_failed_pin_pruning_is_reported);
    RUN_TEST(test_successful_pin_delete_retains_only_the_opaque_id_and_label);
    return UNITY_END();
}
