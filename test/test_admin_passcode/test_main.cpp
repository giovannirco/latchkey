// SPDX-License-Identifier: GPL-3.0-or-later
#include "lock_manager_test_runtime.h"
#include "../reference/backup_fixture.h"
#include "../fake_lock/fake_lock.h"
#include "../../src/methods_admin_passcode.cpp"
#include "ttlock/commands.h"

using latchkey_util::AdminProvenance;
using ttlock::Status;
namespace cmd = ttlock::command;
static const std::string mac(kMac);
static constexpr std::string_view previous = "135792468";
static constexpr std::string_view candidate = "246813579";

struct AdminLock : fake::FakeLock {
    bool durableBeforeSend = false;
    Status send(const ttlock::Bytes& bytes) override {
        const auto result = FakeLock::send(bytes);
        if (!requests().empty() && requests().back().command == cmd::kSetAdminKeyboardPassword) {
            lock_manager::AdminState state;
            durableBeforeSend = lock_manager::readAdminState(mac, state) == ESP_OK &&
                previous == state.record.adminPasscode && candidate == state.metadata.pendingAdminPasscode.data();
        }
        return result;
    }
};

struct Rig {
    AdminLock lock;
    fake::FakeClock clock;
    fake::FakeRandom random;
    ttlock::Session session{lock, clock, random};
    ttlock::AesKey key{};
    Rig() {
        key.fill(0x42);
        ttlock::LockKeys keys;
        keys.version = fake::kRequestVersion;
        keys.aesKey = key;
        keys.features = ttlock::featureBit(ttlock::Feature::Passcode) | ttlock::featureBit(ttlock::Feature::GetAdminCode);
        TEST_ASSERT_EQUAL_INT(static_cast<int>(Status::Ok), static_cast<int>(session.attach(keys)));
    }
    void expect(uint8_t command, const ttlock::Bytes& data = {}, bool respond = true, bool refuse = false) {
        lock.expect(cmd::kCheckAdmin, key, {fake::success(key, cmd::kCheckAdmin, fake::be32(1))});
        lock.expect(cmd::kCheckRandom, key, {fake::success(key, cmd::kCheckRandom)});
        lock.expect(command, key, respond ? std::vector<ttlock::Bytes>{refuse ? fake::failure(key, command, 2) : fake::success(key, command, data)} : std::vector<ttlock::Bytes>{});
    }
    Status change(rpc::Reply& reply, bool generated = false) {
        return methods::setAdminPasscode(mac, lock_access::Secret(candidate), generated, session, reply);
    }
    void readback(std::string_view code) {
        ttlock::Bytes data{0, static_cast<uint8_t>(code.size())};
        data.insert(data.end(), code.begin(), code.end());
        expect(cmd::kGetAdminCode, data);
    }
};

void setUp() {
    resetManagerFixture();
    const auto decoded = backup_fixture::make();
    store::locks::Record record;
    TEST_ASSERT_TRUE(key_store::makeRecord(decoded.locks()[0], record));
    std::memcpy(record.adminPasscode, previous.data(), previous.size());
    record.adminPasscode[previous.size()] = 0;
    TEST_ASSERT_EQUAL_INT(ESP_OK, lock_manager::persist(record));
    latchkey_util::LockMetadata metadata;
    metadata.provenance = AdminProvenance::PairingGenerated;
    TEST_ASSERT_EQUAL_INT(ESP_OK, key_store::saveMetadata(mac, metadata));
    s_reads = s_writes = 0;
}
void tearDown() { clearManagerFixture(); }

static void test_owner_change_stages_before_write_and_confirms_owner_provenance() {
    Rig rig;
    rig.expect(cmd::kPasscodeList, {0, 0});
    rig.expect(cmd::kSetAdminKeyboardPassword);
    rpc::Reply reply;
    TEST_ASSERT_EQUAL_INT(static_cast<int>(Status::Ok), static_cast<int>(rig.change(reply, true)));
    TEST_ASSERT_TRUE(reply.error.empty());
    TEST_ASSERT_TRUE(rig.lock.durableBeforeSend);
    lock_manager::AdminState state;
    TEST_ASSERT_EQUAL_INT(ESP_OK, lock_manager::readAdminState(mac, state));
    TEST_ASSERT_TRUE(candidate == state.record.adminPasscode);
    TEST_ASSERT_EQUAL_INT(static_cast<int>(AdminProvenance::Owner), static_cast<int>(state.metadata.provenance));
    TEST_ASSERT_TRUE(state.metadata.pendingAdminPasscode[0] == 0);
    TEST_ASSERT_EQUAL_UINT(0, rig.lock.unexpected());
}

static void test_timeout_keeps_both_copies_and_retry_only_reconciles() {
    Rig rig;
    rig.expect(cmd::kPasscodeList, {0, 0});
    rig.expect(cmd::kSetAdminKeyboardPassword, {}, false);
    rpc::Reply reply;
    TEST_ASSERT_EQUAL_INT(static_cast<int>(Status::Timeout), static_cast<int>(rig.change(reply)));
    lock_manager::AdminState state;
    TEST_ASSERT_EQUAL_INT(ESP_OK, lock_manager::readAdminState(mac, state));
    TEST_ASSERT_TRUE(previous == state.record.adminPasscode);
    TEST_ASSERT_TRUE(candidate == state.metadata.pendingAdminPasscode.data());
    const size_t before = rig.lock.requests().size();
    rig.readback(candidate);
    TEST_ASSERT_EQUAL_INT(static_cast<int>(Status::Ok), static_cast<int>(rig.change(reply)));
    TEST_ASSERT_TRUE(reply.error == "admin_reconciled");
    TEST_ASSERT_EQUAL_UINT(before + 3, rig.lock.requests().size());
    TEST_ASSERT_EQUAL_INT(ESP_OK, lock_manager::readAdminState(mac, state));
    TEST_ASSERT_TRUE(candidate == state.record.adminPasscode);
    TEST_ASSERT_TRUE(state.metadata.pendingAdminPasscode[0] == 0);
}

static void test_third_code_retains_pending_without_any_admin_write() {
    TEST_ASSERT_EQUAL_INT(ESP_OK, lock_manager::stageAdminPasscode(mac, candidate, AdminProvenance::Owner));
    const auto storage = s_namespaces;
    Rig rig;
    rig.readback("975312468");
    rpc::Reply reply;
    TEST_ASSERT_EQUAL_INT(static_cast<int>(Status::Ok), static_cast<int>(rig.change(reply)));
    TEST_ASSERT_TRUE(reply.error == "admin_unresolved");
    TEST_ASSERT_TRUE(storage == s_namespaces);
    TEST_ASSERT_EQUAL_UINT(3, rig.lock.requests().size());
}

static void test_failed_staging_never_sends_admin_command() {
    Rig rig;
    rig.expect(cmd::kPasscodeList, {0, 0});
    s_failWrite = 1;
    rpc::Reply reply;
    TEST_ASSERT_EQUAL_INT(static_cast<int>(Status::Ok), static_cast<int>(rig.change(reply)));
    TEST_ASSERT_FALSE(reply.error.empty());
    TEST_ASSERT_EQUAL_UINT(3, rig.lock.requests().size());
}

static void test_refusal_cleanup_failure_is_reported_and_retains_pending() {
    Rig rig;
    rig.expect(cmd::kPasscodeList, {0, 0});
    rig.expect(cmd::kSetAdminKeyboardPassword, {}, true, true);
    s_failWrite = 3;
    rpc::Reply reply;
    TEST_ASSERT_EQUAL_INT(static_cast<int>(Status::Ok), static_cast<int>(rig.change(reply)));
    TEST_ASSERT_TRUE(reply.error == "admin_unresolved");
    lock_manager::AdminState state;
    TEST_ASSERT_EQUAL_INT(ESP_OK, lock_manager::readAdminState(mac, state));
    TEST_ASSERT_TRUE(previous == state.record.adminPasscode);
    TEST_ASSERT_TRUE(candidate == state.metadata.pendingAdminPasscode.data());
}

int main() {
    rpc::init();
    UNITY_BEGIN();
    RUN_TEST(test_owner_change_stages_before_write_and_confirms_owner_provenance);
    RUN_TEST(test_timeout_keeps_both_copies_and_retry_only_reconciles);
    RUN_TEST(test_third_code_retains_pending_without_any_admin_write);
    RUN_TEST(test_failed_staging_never_sends_admin_command);
    RUN_TEST(test_refusal_cleanup_failure_is_reported_and_retains_pending);
    return UNITY_END();
}
