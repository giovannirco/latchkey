// SPDX-License-Identifier: GPL-3.0-or-later
#include "latchkey_util/harden_plan.h"
#include "lock_manager_test_runtime.h"
#include "../reference/backup_fixture.h"
#include "../reference/hmac_sha256.h"
#include "../fake_lock/fake_lock.h"
#include "../../src/methods_harden.cpp"
#include "ttlock/commands.h"

namespace hmac {
bool sha256(const uint8_t* key, size_t keyLength, const uint8_t* data, size_t length, uint8_t (&out)[32]) {
    return reference::hmacSha256(key, keyLength, data, length, out);
}
}
namespace cmd = ttlock::command;
using latchkey_util::AdminProvenance;
static const std::string mac(kMac);
static constexpr std::string_view oldCode = "1357924";
static constexpr std::string_view managedCode = "2468135";
static constexpr std::string_view unmanagedCode = "9753124";
static const uint64_t features = ttlock::featureBit(ttlock::Feature::Passcode) | ttlock::featureBit(ttlock::Feature::GetAdminCode);

struct ObservedLock : fake::FakeLock {
    std::function<void(uint8_t)> sent;
    ttlock::Status send(const ttlock::Bytes& bytes) override {
        const auto status = FakeLock::send(bytes);
        if (sent && !requests().empty()) sent(requests().back().command);
        return status;
    }
};
struct Rig {
    ObservedLock lock;
    ttlock::AesKey key{};
    std::vector<std::pair<std::string_view, ttlock::PasscodeType>> listed{
        {oldCode, ttlock::PasscodeType::Permanent}, {managedCode, ttlock::PasscodeType::Permanent},
        {unmanagedCode, ttlock::PasscodeType::Permanent}};
    Rig(bool unknownFeatures = false) {
        fixtureClockSynced = true;
        bluetoothReady = true;
        fixtureTransport = &lock;
        const auto decoded = backup_fixture::make();
        store::locks::Record record;
        TEST_ASSERT_TRUE(key_store::makeRecord(decoded.locks()[0], record));
        key.fill(0x42);
        std::copy(key.begin(), key.end(), record.aesKey);
        std::strcpy(record.adminPasscode, oldCode.data());
        record.features = unknownFeatures ? 0 : features;
        record.flags &= ~store::locks::kFlagTimeCalibrated;
        TEST_ASSERT_EQUAL_INT(ESP_OK, lock_manager::persist(record));
        lock_manager::findLocked(mac)->live.watch.state().baselined = true;
        metadata(AdminProvenance::Owner, true);
        latchkey_util::PasscodeId id;
        TEST_ASSERT_TRUE(latchkey_util::passcodeId(key, managedCode, hmac::sha256, id));
        latchkey_util::LabelTable labels;
        labels.put({latchkey_util::passcodeIdNumber(id), true, "Managed", {}});
        labels.put({1, true, "Keep absent label", latchkey_util::WeeklyWindow{1, 60, 120}});
        s_namespaces["labels"][std::string(kKey) + 'p'] = {NVS_TYPE_BLOB, labels.encode()};
        s_writes = s_reads = auditWrites = 0;
    }
    void metadata(AdminProvenance source, bool backedUp, std::string_view pending = {}) {
        latchkey_util::LockMetadata value;
        value.provenance = source;
        value.lifecycle = backedUp ? latchkey_util::kBackupBackedUp : 0;
        if (!pending.empty()) {
            std::copy(pending.begin(), pending.end(), value.pendingAdminPasscode.begin());
            value.pendingProvenance = AdminProvenance::HardeningGenerated;
        }
        TEST_ASSERT_EQUAL_INT(ESP_OK, key_store::saveMetadata(mac, value));
    }
    void expect(uint8_t command, const ttlock::Bytes& data = {}, bool reply = true) {
        lock.expect(cmd::kCheckAdmin, key, {fake::success(key, cmd::kCheckAdmin, fake::be32(1))});
        lock.expect(cmd::kCheckRandom, key, {fake::success(key, cmd::kCheckRandom)});
        lock.expect(command, key, reply ? std::vector<ttlock::Bytes>{fake::success(key, command, data)} : std::vector<ttlock::Bytes>{});
    }
    void reads(bool unknownFeatures = false, std::string_view current = oldCode) {
        if (unknownFeatures) {
            auto data = fake::concat({ttlock::Bytes{0}, fake::be32(features), fake::be32(features >> 32)});
            expect(cmd::kSearchDeviceFeature, data);
        }
        ttlock::Bytes admin{0, static_cast<uint8_t>(current.size())};
        admin.insert(admin.end(), current.begin(), current.end());
        expect(cmd::kGetAdminCode, admin);
        ttlock::Bytes page{0, 1, 0, 0};
        for (auto [code, type] : listed) {
            ttlock::Bytes item{static_cast<uint8_t>(type), static_cast<uint8_t>(code.size())};
            item.insert(item.end(), code.begin(), code.end());
            item.insert(item.end(), {0, 26, 1, 1, 0, 0});
            page.push_back(item.size());
            page.insert(page.end(), item.begin(), item.end());
        }
        expect(cmd::kPasscodeList, page);
    }
    void clock(bool reply = true) {
        lock.expect(cmd::kGetOperateLog, key, {fake::success(key, cmd::kGetOperateLog, {0, 0})});
        expect(cmd::kTimeCalibrate, {}, reply);
    }
};

static const char* stringField(const cJSON* value, const char* name) {
    const auto* field = cJSON_GetObjectItemCaseSensitive(value, name);
    return cJSON_IsString(field) ? field->valuestring : "";
}
static const cJSON* resultOf(const rpc::Reply& reply) { return reply.result ? reply.result.get() : reply.errorData.get(); }
static const cJSON* step(const rpc::Reply& reply, size_t index) {
    return cJSON_GetArrayItem(cJSON_GetObjectItemCaseSensitive(resultOf(reply), "steps"), index);
}
static rpc::Response dispatch(bool dryRun, rpc::Transport origin = rpc::Transport::Web, const char* token = "fixture-session") {
    return dispatchRequest(request(dryRun ? R"({"id":1,"method":"lock.harden","params":{"lock":"00:00:5E:00:53:01","dryRun":true}})"
                                         : R"({"id":1,"method":"lock.harden","params":{"lock":"00:00:5E:00:53:01"}})"), origin, token);
}
static rpc::Reply finishQueued(bool expired = false) {
    TEST_ASSERT_TRUE(queuedWork.has_value());
    auto work = std::move(*queuedWork);
    queuedWork.reset();
    return rpc::executeJob(std::move(*work), expired);
}
static rpc::Reply run(bool dryRun) { dispatch(dryRun); return finishQueued(); }
void setUp() { resetManagerFixture(); }
void tearDown() { clearManagerFixture(); }

static void test_preview_has_zero_storage_audit_clock_or_switch_writes_even_without_cached_features() {
    Rig rig(true);
    rig.reads(true);
    const auto before = s_namespaces;
    const auto reply = run(true);
    TEST_ASSERT_TRUE(reply.error.empty());
    TEST_ASSERT_EQUAL_STRING("preview", stringField(resultOf(reply), "completion"));
    TEST_ASSERT_FALSE(cJSON_IsTrue(cJSON_GetObjectItemCaseSensitive(reply.result.get(), "hardened")));
    TEST_ASSERT_EQUAL_STRING("planned", stringField(step(reply, 0), "status"));
    TEST_ASSERT_EQUAL_STRING("skipped", stringField(step(reply, 3), "status"));
    TEST_ASSERT_EQUAL_UINT(0, confirmations);
    TEST_ASSERT_EQUAL_UINT(0, s_writes);
    TEST_ASSERT_EQUAL_UINT(0, auditWrites);
    TEST_ASSERT_TRUE(before == s_namespaces);
    TEST_ASSERT_EQUAL_UINT(0, rig.lock.unexpected());
    TEST_ASSERT_TRUE(rig.lock.scriptDone());
    auto text = rpc::render(rpc::Json(cJSON_Duplicate(reply.result.get(), true)));
    for (auto code : {oldCode, managedCode, unmanagedCode}) TEST_ASSERT_TRUE(text.view().find(code) == std::string_view::npos);
}
static void test_execution_is_button_gated_ordered_and_partial_with_no_switch_command() {
    Rig rig;
    rig.reads();
    rig.clock();
    rig.expect(cmd::kManageKeyboardPassword);
    const auto labels = s_namespaces["labels"];
    const auto reply = run(false);
    TEST_ASSERT_TRUE(reply.error.empty());
    TEST_ASSERT_EQUAL_STRING("partial", stringField(resultOf(reply), "completion"));
    TEST_ASSERT_EQUAL_STRING("done", stringField(step(reply, 0), "status"));
    TEST_ASSERT_EQUAL_STRING("done", stringField(step(reply, 1), "status"));
    TEST_ASSERT_EQUAL_STRING("preserved", stringField(step(reply, 2), "status"));
    TEST_ASSERT_EQUAL_STRING("skipped", stringField(step(reply, 3), "status"));
    TEST_ASSERT_EQUAL_UINT(1, confirmations);
    TEST_ASSERT_TRUE(labels == s_namespaces["labels"]);
    TEST_ASSERT_TRUE(rig.lock.scriptDone());
    TEST_ASSERT_EQUAL_UINT(0, rig.lock.unexpected());
    for (const auto& wire : rig.lock.requests()) TEST_ASSERT_NOT_EQUAL(cmd::kSwitch, wire.command);
}
static void test_preconditions_fail_before_button_and_are_rechecked_after_it() {
    Rig rig;
    rig.metadata(AdminProvenance::Owner, false);
    auto reply = run(false);
    TEST_ASSERT_EQUAL_STRING("backup_required", reply.error.c_str());
    TEST_ASSERT_EQUAL_UINT(0, confirmations);
    rig.metadata(AdminProvenance::Owner, true);
    beforePress = [&] { rig.metadata(AdminProvenance::Owner, false); };
    reply = run(false);
    TEST_ASSERT_EQUAL_STRING("backup_required", reply.error.c_str());
    TEST_ASSERT_EQUAL_UINT(1, confirmations);
    TEST_ASSERT_TRUE(rig.lock.requests().empty());
}
static void test_authentication_validation_expiry_and_session_end_precede_lock_io() {
    Rig rig;
    TEST_ASSERT_TRUE(hasError(dispatch(true, rpc::Transport::Web, "invalid"), "unauthorized"));
    TEST_ASSERT_FALSE(queuedWork.has_value());
    const auto invalid = dispatchRequest(request(R"({"method":"lock.harden","params":{"lock":"00:00:5E:00:53:01","dryRun":null}})"), rpc::Transport::Web, "fixture-session");
    auto reply = finishQueued();
    TEST_ASSERT_EQUAL_STRING("invalid_argument", reply.error.c_str());
    dispatch(true);
    reply = finishQueued(true);
    TEST_ASSERT_EQUAL_STRING("busy", reply.error.c_str());
    dispatch(false);
    beforePress = [] { openSession = false; };
    reply = finishQueued();
    TEST_ASSERT_EQUAL_STRING("unauthorized", reply.error.c_str());
    TEST_ASSERT_TRUE(rig.lock.requests().empty());
}
static void test_usb_runs_inline_without_button_or_job() {
    Rig rig;
    rig.reads();
    const auto response = dispatch(true, rpc::Transport::Serial, "");
    TEST_ASSERT_FALSE(queuedWork.has_value());
    TEST_ASSERT_EQUAL_UINT(0, confirmations);
    rpc::Json json(cJSON_Parse(response.json.c_str()));
    TEST_ASSERT_EQUAL_STRING("preview", stringField(cJSON_GetObjectItemCaseSensitive(json.get(), "result"), "completion"));
    TEST_ASSERT_EQUAL_UINT(0, auditWrites);
}
static void test_first_clock_failure_stops_all_later_mutations() {
    Rig rig;
    rig.reads();
    rig.clock(false);
    const auto reply = run(false);
    TEST_ASSERT_EQUAL_STRING("hardening_failed", reply.error.c_str());
    TEST_ASSERT_EQUAL_STRING("failed", stringField(resultOf(reply), "completion"));
    TEST_ASSERT_EQUAL_STRING("failed", stringField(step(reply, 0), "status"));
    TEST_ASSERT_EQUAL_STRING("skipped", stringField(step(reply, 1), "status"));
    TEST_ASSERT_TRUE(rig.lock.scriptDone());
    TEST_ASSERT_EQUAL_UINT(0, rig.lock.unexpected());
}
static void test_pending_preview_plans_reconciliation_without_persisting() {
    Rig rig;
    rig.metadata(AdminProvenance::PairingGenerated, true, "1111111");
    rig.reads(false, "1111111");
    const auto before = s_namespaces;
    s_writes = 0;
    const auto reply = run(true);
    TEST_ASSERT_TRUE(reply.error.empty());
    TEST_ASSERT_EQUAL_STRING("confirm_candidate", stringField(step(reply, 2), "reason"));
    TEST_ASSERT_TRUE(before == s_namespaces);
    TEST_ASSERT_EQUAL_UINT(0, s_writes);
}
static void test_unreadable_metadata_or_labels_fail_without_lock_mutations() {
    for (const bool metadata : {false, true}) {
        resetManagerFixture();
        Rig rig;
        s_namespaces[metadata ? "lockmeta" : "labels"][metadata ? kKey : (std::string(kKey) + 'p')] = {NVS_TYPE_BLOB, {255}};
        const auto before = s_namespaces;
        const auto reply = run(true);
        TEST_ASSERT_FALSE(reply.error.empty());
        TEST_ASSERT_TRUE(before == s_namespaces);
        TEST_ASSERT_TRUE(rig.lock.requests().empty());
    }
}
static size_t adminWrites(const Rig& rig) {
    return std::count_if(rig.lock.requests().begin(), rig.lock.requests().end(), [](const auto& request) {
        return request.command == cmd::kSetAdminKeyboardPassword;
    });
}
static void test_hardening_rotates_pairing_code_once_and_partial_retry_preserves_it() {
    Rig rig;
    rig.metadata(AdminProvenance::PairingGenerated, true);
    rig.reads();
    rig.clock();
    rig.expect(cmd::kManageKeyboardPassword);
    rig.expect(cmd::kSetAdminKeyboardPassword);
    auto reply = run(false);
    TEST_ASSERT_EQUAL_STRING("partial", stringField(resultOf(reply), "completion"));
    lock_manager::AdminState state;
    TEST_ASSERT_EQUAL_INT(ESP_OK, lock_manager::readAdminState(mac, state));
    TEST_ASSERT_EQUAL_INT(static_cast<int>(AdminProvenance::HardeningGenerated), static_cast<int>(state.metadata.provenance));
    TEST_ASSERT_TRUE(state.metadata.pendingAdminPasscode[0] == 0);
    TEST_ASSERT_TRUE(std::string_view(state.record.adminPasscode) == "1111111");
    rig.listed = {{"1111111", ttlock::PasscodeType::Permanent}, {managedCode, ttlock::PasscodeType::Permanent}};
    rig.reads(false, "1111111");
    rig.clock();
    reply = run(false);
    TEST_ASSERT_EQUAL_STRING("partial", stringField(resultOf(reply), "completion"));
    TEST_ASSERT_EQUAL_STRING("hardening_generated", stringField(step(reply, 2), "reason"));
    TEST_ASSERT_EQUAL_UINT(1, adminWrites(rig));
    TEST_ASSERT_TRUE(rig.lock.scriptDone());
}
static void test_lost_ack_restarts_and_reconciles_without_a_second_rotation() {
    Rig rig;
    rig.metadata(AdminProvenance::PairingGenerated, true);
    rig.reads();
    rig.clock();
    rig.expect(cmd::kManageKeyboardPassword);
    rig.expect(cmd::kSetAdminKeyboardPassword, {}, false);
    auto reply = run(false);
    TEST_ASSERT_EQUAL_STRING("failed", stringField(resultOf(reply), "completion"));
    lock_manager::s_locks = {};
    lock_manager::s_lockCount = 0;
    lock_manager::s_link = {};
    lock_manager::start();
    lock_manager::findLocked(mac)->live.watch.state().baselined = true;
    rig.listed = {{oldCode, ttlock::PasscodeType::Permanent}, {"1111111", ttlock::PasscodeType::Permanent},
                  {managedCode, ttlock::PasscodeType::Permanent}};
    rig.reads(false, "1111111");
    rig.clock();
    reply = run(false);
    TEST_ASSERT_EQUAL_STRING("partial", stringField(resultOf(reply), "completion"));
    TEST_ASSERT_EQUAL_STRING("confirm_candidate", stringField(step(reply, 2), "reason"));
    TEST_ASSERT_EQUAL_UINT(1, adminWrites(rig));
    lock_manager::AdminState state;
    TEST_ASSERT_EQUAL_INT(ESP_OK, lock_manager::readAdminState(mac, state));
    TEST_ASSERT_TRUE(state.metadata.pendingAdminPasscode[0] == 0);
    TEST_ASSERT_EQUAL_INT(static_cast<int>(AdminProvenance::HardeningGenerated), static_cast<int>(state.metadata.provenance));
    TEST_ASSERT_TRUE(rig.lock.scriptDone());
}
static void test_current_admin_readback_and_managed_cyclic_code_are_never_deleted() {
    Rig rig;
    rig.listed = {{oldCode, ttlock::PasscodeType::Permanent}, {managedCode, ttlock::PasscodeType::Cyclic},
                  {unmanagedCode, ttlock::PasscodeType::Permanent}, {"1111111", ttlock::PasscodeType::Cyclic}};
    rig.reads(false, unmanagedCode);
    rig.clock();
    rig.expect(cmd::kManageKeyboardPassword);
    const auto before = s_namespaces["labels"];
    const auto reply = run(false);
    TEST_ASSERT_EQUAL_STRING("partial", stringField(resultOf(reply), "completion"));
    TEST_ASSERT_TRUE(before == s_namespaces["labels"]);
    TEST_ASSERT_EQUAL_UINT(0, rig.lock.unexpected());
    TEST_ASSERT_TRUE(rig.lock.scriptDone());
    const auto& sent = rig.lock.requests().back();
    TEST_ASSERT_EQUAL_UINT(static_cast<uint8_t>(ttlock::PasscodeType::Cyclic), sent.payload[1]);
}
static void test_collision_never_stages_or_sends_a_new_admin_code() {
    Rig rig;
    rig.metadata(AdminProvenance::PairingGenerated, true);
    rig.listed = {{oldCode, ttlock::PasscodeType::Permanent}, {"1111111", ttlock::PasscodeType::Permanent}};
    rig.reads();
    rig.clock();
    rig.expect(cmd::kManageKeyboardPassword);
    const auto reply = run(false);
    TEST_ASSERT_EQUAL_STRING("failed", stringField(resultOf(reply), "completion"));
    TEST_ASSERT_EQUAL_STRING("code_collision", stringField(step(reply, 2), "error"));
    TEST_ASSERT_EQUAL_UINT(0, adminWrites(rig));
    lock_manager::AdminState state;
    TEST_ASSERT_EQUAL_INT(ESP_OK, lock_manager::readAdminState(mac, state));
    TEST_ASSERT_TRUE(state.metadata.pendingAdminPasscode[0] == 0);
    TEST_ASSERT_TRUE(oldCode == state.record.adminPasscode);
}
static void test_delete_failure_stops_remaining_deletes_and_admin_rotation() {
    Rig rig;
    rig.metadata(AdminProvenance::PairingGenerated, true);
    rig.listed.push_back({"1111111", ttlock::PasscodeType::Cyclic});
    rig.reads();
    rig.clock();
    rig.expect(cmd::kManageKeyboardPassword, {}, false);
    const auto reply = run(false);
    TEST_ASSERT_EQUAL_STRING("failed", stringField(resultOf(reply), "completion"));
    TEST_ASSERT_EQUAL_STRING("failed", stringField(step(reply, 1), "status"));
    TEST_ASSERT_EQUAL_STRING("skipped", stringField(step(reply, 2), "status"));
    TEST_ASSERT_TRUE(rig.lock.scriptDone());
    TEST_ASSERT_EQUAL_UINT(0, rig.lock.unexpected());
    TEST_ASSERT_EQUAL_UINT(0, adminWrites(rig));
}
static void test_clock_storage_failure_stops_the_next_storage_and_lock_mutation() {
    Rig rig;
    rig.reads();
    rig.clock();
    s_failWrite = 1;
    const auto reply = run(false);
    TEST_ASSERT_EQUAL_STRING("failed", stringField(resultOf(reply), "completion"));
    TEST_ASSERT_EQUAL_STRING("storage_error", stringField(step(reply, 0), "error"));
    TEST_ASSERT_EQUAL_UINT(1, s_writes);
    TEST_ASSERT_TRUE(rig.lock.scriptDone());
}
static void test_unresolved_third_code_and_confirmation_timeout_have_no_mutations() {
    Rig rig;
    pressAllowed = false;
    auto reply = run(false);
    TEST_ASSERT_EQUAL_STRING("confirm_timeout", reply.error.c_str());
    TEST_ASSERT_TRUE(rig.lock.requests().empty());
    pressAllowed = true;
    rig.metadata(AdminProvenance::PairingGenerated, true, "1111111");
    rig.reads(false, unmanagedCode);
    s_writes = 0;
    const auto before = s_namespaces;
    reply = run(false);
    TEST_ASSERT_EQUAL_STRING("failed", stringField(resultOf(reply), "completion"));
    TEST_ASSERT_EQUAL_STRING("admin_unresolved", stringField(step(reply, 2), "error"));
    TEST_ASSERT_TRUE(before == s_namespaces);
    TEST_ASSERT_EQUAL_UINT(0, s_writes);
    TEST_ASSERT_TRUE(rig.lock.scriptDone());
}

static void test_failed_execution_audit_records_failure_and_error_keeps_step_details() {
    Rig rig;
    rig.reads();
    rig.clock(false);
    const auto reply = run(false);
    TEST_ASSERT_EQUAL_STRING("hardening_failed", reply.error.c_str());
    TEST_ASSERT_EQUAL_STRING("hardening_failed", lastAuditResult.c_str());
    TEST_ASSERT_EQUAL_STRING("failed", stringField(reply.errorData.get(), "completion"));
    TEST_ASSERT_EQUAL_UINT(4, cJSON_GetArraySize(cJSON_GetObjectItemCaseSensitive(reply.errorData.get(), "steps")));
}
static void test_preview_reports_unsynced_clock_without_writes() {
    Rig rig;
    fixtureClockSynced = false;
    rig.reads();
    const auto reply = run(true);
    TEST_ASSERT_TRUE(reply.error.empty());
    TEST_ASSERT_FALSE(cJSON_IsTrue(cJSON_GetObjectItemCaseSensitive(reply.result.get(), "executable")));
    TEST_ASSERT_EQUAL_STRING("time_unsynced", stringField(step(reply, 0), "error"));
    TEST_ASSERT_EQUAL_UINT(0, s_writes);
    TEST_ASSERT_EQUAL_UINT(0, auditWrites);
}
static size_t serializeWithFailure(size_t at) {
    resetManagerFixture();
    Rig rig;
    rig.metadata(AdminProvenance::PairingGenerated, true);
    rig.reads();
    rig.clock();
    rig.expect(cmd::kManageKeyboardPassword);
    rig.expect(cmd::kSetAdminKeyboardPassword);
    rig.lock.sent = [at](uint8_t command) {
        if (command != cmd::kSetAdminKeyboardPassword) return;
        allocationAttempts = 0;
        failAllocation = at;
    };
    const auto reply = run(false);
    const auto attempts = allocationAttempts;
    failAllocation = 0;
    if (at != 0) {
        TEST_ASSERT_EQUAL_STRING("internal", reply.error.c_str());
        TEST_ASSERT_EQUAL_STRING("internal", lastAuditResult.c_str());
        TEST_ASSERT_NULL(reply.result.get());
    } else TEST_ASSERT_EQUAL_STRING("partial", stringField(resultOf(reply), "completion"));
    lock_manager::AdminState state;
    TEST_ASSERT_EQUAL_INT(ESP_OK, lock_manager::readAdminState(mac, state));
    TEST_ASSERT_EQUAL_INT(static_cast<int>(AdminProvenance::HardeningGenerated), static_cast<int>(state.metadata.provenance));
    TEST_ASSERT_TRUE(state.metadata.pendingAdminPasscode[0] == 0);
    TEST_ASSERT_EQUAL_UINT(1, adminWrites(rig));
    return attempts;
}
static void test_every_result_allocation_failure_is_explicit_and_preserves_confirmed_mutations() {
    const size_t allocations = serializeWithFailure(0);
    TEST_ASSERT_GREATER_THAN(20, allocations);
    for (size_t at = 1; at <= allocations; ++at) serializeWithFailure(at);
}

static void test_log_read_failure_does_not_retry_a_previous_storage_write() {
    Rig rig;
    rig.reads();
    rig.lock.expect(cmd::kGetOperateLog, rig.key, {});
    lock_manager::findLocked(mac)->live.watchWriteFailed = true;
    const auto reply = run(false);
    TEST_ASSERT_EQUAL_STRING("hardening_failed", reply.error.c_str());
    TEST_ASSERT_EQUAL_STRING("timeout", stringField(step(reply, 0), "error"));
    TEST_ASSERT_EQUAL_UINT(0, s_writes);
    TEST_ASSERT_TRUE(rig.lock.scriptDone());
}

int main() {
    rpc::init();
    methods::registerHarden();
    UNITY_BEGIN();
    RUN_TEST(test_preview_has_zero_storage_audit_clock_or_switch_writes_even_without_cached_features);
    RUN_TEST(test_execution_is_button_gated_ordered_and_partial_with_no_switch_command);
    RUN_TEST(test_preconditions_fail_before_button_and_are_rechecked_after_it);
    RUN_TEST(test_authentication_validation_expiry_and_session_end_precede_lock_io);
    RUN_TEST(test_usb_runs_inline_without_button_or_job);
    RUN_TEST(test_first_clock_failure_stops_all_later_mutations);
    RUN_TEST(test_pending_preview_plans_reconciliation_without_persisting);
    RUN_TEST(test_unreadable_metadata_or_labels_fail_without_lock_mutations);
    RUN_TEST(test_hardening_rotates_pairing_code_once_and_partial_retry_preserves_it);
    RUN_TEST(test_lost_ack_restarts_and_reconciles_without_a_second_rotation);
    RUN_TEST(test_current_admin_readback_and_managed_cyclic_code_are_never_deleted);
    RUN_TEST(test_collision_never_stages_or_sends_a_new_admin_code);
    RUN_TEST(test_delete_failure_stops_remaining_deletes_and_admin_rotation);
    RUN_TEST(test_clock_storage_failure_stops_the_next_storage_and_lock_mutation);
    RUN_TEST(test_unresolved_third_code_and_confirmation_timeout_have_no_mutations);
    RUN_TEST(test_failed_execution_audit_records_failure_and_error_keeps_step_details);
    RUN_TEST(test_preview_reports_unsynced_clock_without_writes);
    RUN_TEST(test_every_result_allocation_failure_is_explicit_and_preserves_confirmed_mutations);
    RUN_TEST(test_log_read_failure_does_not_retry_a_previous_storage_write);
    return UNITY_END();
}
