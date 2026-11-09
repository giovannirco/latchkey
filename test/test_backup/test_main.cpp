// SPDX-License-Identifier: GPL-3.0-or-later
#include "latchkey_util/key_restore.h"
#include "lock_manager_test_runtime.h"
#include "../reference/backup_crypto.h"
#include "../reference/backup_fixture.h"
#include "../../src/backup.cpp"
#include "../../src/methods_backup.cpp"

static ReferenceCrypto backupCrypto;
static std::function<void()> beforeDerive;
static bool watchEnvelope = false;

namespace backup_crypto {
bool PsaCrypto::random(std::span<uint8_t> bytes) { return backupCrypto.random(bytes); }
bool PsaCrypto::deriveKey(std::string_view password, std::span<const uint8_t, 16> salt, std::span<uint8_t, 32> key) {
    if (beforeDerive) beforeDerive();
    return backupCrypto.deriveKey(password, salt, key);
}
bool PsaCrypto::seal(std::span<const uint8_t, 32> key, std::span<const uint8_t, 12> nonce,
                      std::span<const uint8_t> aad, std::span<uint8_t> bytes) {
    return backupCrypto.seal(key, nonce, aad, bytes);
}
bool PsaCrypto::open(std::span<const uint8_t, 32> key, std::span<const uint8_t, 12> nonce,
                      std::span<const uint8_t> aad, std::span<uint8_t> bytes) {
    if (watchEnvelope) {
        allocation_failure::expectWiped(bytes.data() - latchkey_util::kBackupHeaderSize,
                                        bytes.size() + latchkey_util::kBackupHeaderSize);
    }
    return backupCrypto.open(key, nonce, aad, bytes);
}
}

void setUp() {
    resetManagerFixture();
    backupCrypto = {};
    beforeDerive = {};
    watchEnvelope = false;
}
void tearDown() { clearManagerFixture(); }

static rpc::Response call(std::string_view method, std::string_view params,
                          rpc::Transport origin = rpc::Transport::Serial) {
    const std::string text = "{\"id\":1,\"method\":\"" + std::string(method) + "\",\"params\":" +
                             std::string(params) + "}";
    return dispatchRequest(request(text), origin, "fixture-session");
}

static void seedDecoded(const latchkey_util::DecodedBackup& decoded) {
    const auto reply = lock_manager::runStorage("fixture.seed", [&](auto& storage, auto& publication) {
        const auto status = latchkey_util::restoreKeys(decoded, storage, publication);
        TEST_ASSERT_EQUAL_INT(static_cast<int>(latchkey_util::RestoreStatus::Ok), static_cast<int>(status));
        for (const auto& lock : decoded.locks()) {
            latchkey_util::LockMetadata metadata;
            TEST_ASSERT_EQUAL_INT(ESP_OK, key_store::loadMetadata(lock.mac, metadata));
            metadata.lifecycle &= ~latchkey_util::kBackupBackedUp;
            TEST_ASSERT_EQUAL_INT(ESP_OK, key_store::saveMetadata(lock.mac, metadata));
            publication.metadataChanged(lock.mac, &metadata);
        }
        return rpc::ok();
    });
    TEST_ASSERT_TRUE(reply.error.empty());
    s_writes = 0;
}

static void seed(size_t count = 1, bool maximum = false) { seedDecoded(backup_fixture::make(count, maximum)); }

static rpc::Json responseOf(const rpc::Response& response) {
    rpc::Json parsed(cJSON_Parse(response.json.c_str()));
    TEST_ASSERT_NOT_NULL(parsed.get());
    return parsed;
}

static std::string exportBackup() {
    const auto response = call("keys.export", R"({"passphrase":"fixture backup passphrase"})");
    const auto parsed = responseOf(response);
    TEST_ASSERT_NULL(cJSON_GetObjectItemCaseSensitive(parsed.get(), "error"));
    const auto* result = cJSON_GetObjectItemCaseSensitive(parsed.get(), "result");
    const auto* value = cJSON_GetObjectItemCaseSensitive(result, "backup");
    TEST_ASSERT_TRUE(cJSON_IsString(value));
    return value->valuestring;
}

static std::string importParams(std::string_view encoded, std::string_view password = backup_fixture::password) {
    return "{\"passphrase\":\"" + std::string(password) + "\",\"backup\":\"" + std::string(encoded) + "\"}";
}

static void test_backup_methods_require_owner_authentication_and_web_confirmation_but_usb_is_inline() {
    seed();
    openSession = false;
    auto denied = call("keys.export", R"({"passphrase":"fixture backup passphrase"})", rpc::Transport::Web);
    TEST_ASSERT_TRUE(hasError(denied, "unauthorized"));
    TEST_ASSERT_EQUAL_UINT(0, backupCrypto.derivations);
    TEST_ASSERT_EQUAL_UINT(0, confirmations);
    openSession = true;
    auto accepted = call("keys.export", R"({"passphrase":"fixture backup passphrase"})", rpc::Transport::Web);
    TEST_ASSERT_TRUE(queuedWork.has_value());
    TEST_ASSERT_EQUAL_UINT(0, backupCrypto.derivations);
    pressAllowed = false;
    auto unconfirmed = rpc::executeJob(std::move(**queuedWork), false);
    queuedWork.reset();
    TEST_ASSERT_FALSE(unconfirmed.error.empty());
    TEST_ASSERT_EQUAL_UINT(0, s_writes);
    TEST_ASSERT_EQUAL_UINT(0, backupCrypto.derivations);
    const size_t previous = confirmations;
    const auto encoded = exportBackup();
    TEST_ASSERT_FALSE(encoded.empty());
    TEST_ASSERT_EQUAL_UINT(previous, confirmations);
    TEST_ASSERT_EQUAL_UINT(1, backupCrypto.derivations);
    TEST_ASSERT_FALSE(queuedWork.has_value());
}

static void test_invalid_passphrases_types_and_noncanonical_lock_ids_fail_before_confirmation() {
    for (const std::string params : {
             R"({"passphrase":"short"})", R"({"passphrase":123})", R"({"passphrase":null})",
             R"({"passphrase":"fixture backup passphrase","lock":null})",
             R"({"passphrase":"fixture backup passphrase","lock":"00:00:5e:00:53:01"})",
             R"({"passphrase":"fixture backup passphrase","lock":""})",
             R"({"passphrase":"fixture backup passphrase","passphrase":"duplicate value"})"}) {
        const auto response = call("keys.export", params, rpc::Transport::Web);
        TEST_ASSERT_TRUE(queuedWork.has_value());
        const auto reply = rpc::executeJob(std::move(**queuedWork), false);
        queuedWork.reset();
        TEST_ASSERT_EQUAL_STRING("invalid_argument", reply.error.c_str());
    }
    const std::string tooLong = "{\"passphrase\":\"" + std::string(129, 'x') + "\"}";
    const auto response = call("keys.export", tooLong, rpc::Transport::Web);
    TEST_ASSERT_TRUE(queuedWork.has_value());
    const auto reply = rpc::executeJob(std::move(**queuedWork), false);
    queuedWork.reset();
    TEST_ASSERT_EQUAL_STRING("invalid_argument", reply.error.c_str());
    TEST_ASSERT_EQUAL_UINT(0, confirmations);
    TEST_ASSERT_EQUAL_UINT(0, backupCrypto.derivations);
    TEST_ASSERT_EQUAL_UINT(0, s_writes);
}

static void test_invalid_base64_size_padding_and_header_fail_before_confirmation() {
    for (const std::string encoded : std::vector<std::string>{"", "!@#$", "AAAA=AAA", "AAA", "AAAA\n",
                                                            std::string(11000, 'A'), std::string(76, 'A')}) {
        const auto response = call("keys.import", importParams(encoded), rpc::Transport::Web);
        if (queuedWork.has_value()) {
            const auto reply = rpc::executeJob(std::move(**queuedWork), false);
            queuedWork.reset();
            TEST_ASSERT_EQUAL_STRING("invalid_argument", reply.error.c_str());
        } else {
            TEST_ASSERT_TRUE(hasError(response, "bad_request"));
        }
    }
    TEST_ASSERT_EQUAL_UINT(0, confirmations);
    TEST_ASSERT_EQUAL_UINT(0, backupCrypto.derivations);
    TEST_ASSERT_EQUAL_UINT(0, s_writes);
}

static void test_export_import_roundtrip_preserves_pending_state_and_first_backup_lifecycle() {
    seed();
    const auto encoded = exportBackup();
    const auto expected = s_namespaces;
    resetManagerFixture();
    const auto response = call("keys.import", importParams(encoded));
    const auto parsed = responseOf(response);
    TEST_ASSERT_NULL(cJSON_GetObjectItemCaseSensitive(parsed.get(), "error"));
    const auto* result = cJSON_GetObjectItemCaseSensitive(parsed.get(), "result");
    const auto* imported = cJSON_GetObjectItemCaseSensitive(result, "imported");
    TEST_ASSERT_EQUAL_UINT(1, cJSON_GetArraySize(imported));
    TEST_ASSERT_TRUE(s_namespaces == expected);
    TEST_ASSERT_TRUE(lock_manager::holds(std::string(kMac)));
    latchkey_util::LockMetadata metadata;
    TEST_ASSERT_EQUAL_INT(ESP_OK, key_store::loadMetadata(kMac, metadata));
    TEST_ASSERT_TRUE((metadata.lifecycle & latchkey_util::kBackupBackedUp) != 0);
    TEST_ASSERT_TRUE(std::string_view(metadata.pendingAdminPasscode.data()) == "987654321");
    TEST_ASSERT_EQUAL_UINT(0, bluetoothCalls);
}

static void test_wrong_password_and_damaged_ciphertext_never_write_storage() {
    seed();
    const auto encoded = exportBackup();
    resetManagerFixture();
    const auto wrong = call("keys.import", importParams(encoded, "wrong fixture passphrase"));
    TEST_ASSERT_TRUE(hasError(wrong, "invalid_argument"));
    TEST_ASSERT_EQUAL_UINT(0, s_writes);
    for (const size_t position : {size_t{16}, size_t{40}, size_t{60}, encoded.size() - 5}) {
        auto damaged = encoded;
        damaged[position] = damaged[position] == 'A' ? 'B' : 'A';
        TEST_ASSERT_TRUE(hasError(call("keys.import", importParams(damaged)), "invalid_argument"));
        TEST_ASSERT_EQUAL_UINT(0, s_writes);
        TEST_ASSERT_FALSE(lock_manager::holds(std::string(kMac)));
    }
}

static void test_conflicts_and_capacity_shortage_preserve_storage_without_writes() {
    seed();
    const auto encoded = exportBackup();
    const auto before = s_namespaces;
    s_writes = 0;
    TEST_ASSERT_TRUE(hasError(call("keys.import", importParams(encoded)), "conflict"));
    TEST_ASSERT_TRUE(s_namespaces == before);
    TEST_ASSERT_EQUAL_UINT(0, s_writes);
    resetManagerFixture();
    s_available = 100;
    TEST_ASSERT_TRUE(hasError(call("keys.import", importParams(encoded)), "storage_full"));
    TEST_ASSERT_EQUAL_UINT(0, s_writes);
}

static void test_crypto_and_metadata_write_failures_never_report_a_successful_export() {
    seed();
    backupCrypto.failAt = 3;
    TEST_ASSERT_TRUE(hasError(call("keys.export", R"({"passphrase":"fixture backup passphrase"})"), "internal"));
    TEST_ASSERT_EQUAL_UINT(0, s_writes);
    backupCrypto.failAt = 0;
    s_failWrite = 1;
    TEST_ASSERT_TRUE(hasError(call("keys.export", R"({"passphrase":"fixture backup passphrase"})"), "internal"));
    const auto listed = lock_manager::list();
    const auto* lock = cJSON_GetArrayItem(cJSON_GetObjectItemCaseSensitive(listed.result.get(), "locks"), 0);
    TEST_ASSERT_FALSE(cJSON_IsTrue(cJSON_GetObjectItemCaseSensitive(lock, "backedUp")));
}

static void test_expired_job_and_ended_session_never_derive_or_touch_storage() {
    seed();
    for (bool expired : {false, true}) {
        openSession = true;
        auto response = call("keys.export", R"({"passphrase":"fixture backup passphrase"})", rpc::Transport::Web);
        TEST_ASSERT_TRUE(queuedWork.has_value());
        openSession = expired;
        auto reply = rpc::executeJob(std::move(**queuedWork), expired);
        queuedWork.reset();
        TEST_ASSERT_FALSE(reply.error.empty());
    }
    TEST_ASSERT_EQUAL_UINT(0, s_writes);
    TEST_ASSERT_EQUAL_UINT(0, backupCrypto.derivations);
    TEST_ASSERT_EQUAL_UINT(0, confirmations);
}

static void test_utf8_passphrase_limits_are_bytes_and_controls_remain_exact() {
    seed();
    for (size_t count : {size_t{6}, size_t{64}, size_t{65}}) {
        std::string password;
        for (size_t i = 0; i < count; ++i) password += "\xC3\xA9";
        const auto response = call("keys.export", "{\"passphrase\":\"" + password + "\"}");
        const auto parsed = responseOf(response);
        TEST_ASSERT_EQUAL_INT(count == 65, cJSON_GetObjectItemCaseSensitive(parsed.get(), "error") != nullptr);
    }
    const auto exported = call("keys.export", R"({"passphrase":"  fixture\n\t\r\u007f passphrase  "})");
    const auto parsed = responseOf(exported);
    const auto* result = cJSON_GetObjectItemCaseSensitive(parsed.get(), "result");
    const auto* blob = cJSON_GetObjectItemCaseSensitive(result, "backup");
    TEST_ASSERT_TRUE(cJSON_IsString(blob));
    const std::string encoded(blob->valuestring);
    resetManagerFixture();
    const auto restored = call("keys.import", R"({"passphrase":"  fixture\n\t\r\u007f passphrase  ","backup":")" +
                                               encoded + "\"}");
    TEST_ASSERT_FALSE(hasError(restored, "invalid_argument"));
    TEST_ASSERT_TRUE(lock_manager::holds(std::string(kMac)));
    const auto nul = call("keys.export", R"({"passphrase":"fixture\u0000passphrase"})", rpc::Transport::Web);
    TEST_ASSERT_TRUE(hasError(nul, "bad_request"));
}

static void test_single_lock_export_marks_only_the_selected_identity() {
    seed(2);
    const auto response = call("keys.export", R"({"passphrase":"fixture backup passphrase","lock":"00:00:5E:00:53:02"})");
    const auto parsed = responseOf(response);
    const auto* result = cJSON_GetObjectItemCaseSensitive(parsed.get(), "result");
    TEST_ASSERT_EQUAL_UINT(1, cJSON_GetArraySize(cJSON_GetObjectItemCaseSensitive(result, "locks")));
    latchkey_util::LockMetadata first;
    latchkey_util::LockMetadata second;
    TEST_ASSERT_EQUAL_INT(ESP_OK, key_store::loadMetadata(kMac, first));
    TEST_ASSERT_EQUAL_INT(ESP_OK, key_store::loadMetadata("00:00:5E:00:53:02", second));
    TEST_ASSERT_FALSE((first.lifecycle & latchkey_util::kBackupBackedUp) != 0);
    TEST_ASSERT_TRUE((second.lifecycle & latchkey_util::kBackupBackedUp) != 0);
}

static void test_unreadable_whole_export_and_aggregate_overflow_never_derive_or_mark_flags() {
    seed(1, true);
    const auto decoded = backup_fixture::make(2);
    key_store::Restore storage;
    auto other = decoded.locks()[1];
    for (const auto part : latchkey_util::kRestoreParts) TEST_ASSERT_TRUE(storage.writePart(other, part));
    s_namespaces["locks"][kOtherKey] = {NVS_TYPE_U32, {0xFF}};
    s_writes = 0;
    const auto unreadable = call("keys.export", R"({"passphrase":"fixture backup passphrase"})");
    TEST_ASSERT_TRUE(hasError(unreadable, "internal"));
    TEST_ASSERT_EQUAL_UINT(0, backupCrypto.derivations);
    TEST_ASSERT_EQUAL_UINT(0, s_writes);
    s_namespaces["locks"].erase(kOtherKey);
    const auto maximum = backup_fixture::make(1, true);
    other = maximum.locks()[0];
    other.mac = "00:00:5E:00:53:02";
    for (const auto part : latchkey_util::kRestoreParts) TEST_ASSERT_TRUE(storage.writePart(other, part));
    s_writes = 0;
    const auto tooLarge = call("keys.export", R"({"passphrase":"fixture backup passphrase"})");
    TEST_ASSERT_TRUE(hasError(tooLarge, "too_large"));
    TEST_ASSERT_EQUAL_UINT(0, backupCrypto.derivations);
    TEST_ASSERT_EQUAL_UINT(0, s_writes);
    const auto single = call("keys.export", R"({"passphrase":"fixture backup passphrase","lock":"00:00:5E:00:53:01"})");
    const auto parsed = responseOf(single);
    TEST_ASSERT_NULL(cJSON_GetObjectItemCaseSensitive(parsed.get(), "error"));
}

static void test_import_releases_encoded_input_before_derivation_and_clears_the_passphrase() {
    seed();
    const auto encoded = exportBackup();
    resetManagerFixture();
    rpc::Json params(cJSON_Parse(importParams(encoded).c_str()));
    watchedSecret = encoded;
    bool encodedReleased = false;
    beforeDerive = [&] { encodedReleased = cJSON_GetObjectItemCaseSensitive(params.get(), "backup") == nullptr; };
    const auto reply = lock_manager::runStorage("fixture.import", [&](auto& storage, auto& publication) {
        backup_crypto::PsaCrypto crypto;
        return backup::importKeys(params.get(), crypto, storage, publication);
    });
    beforeDerive = {};
    TEST_ASSERT_TRUE(reply.error.empty());
    TEST_ASSERT_TRUE(encodedReleased);
    TEST_ASSERT_NULL(cJSON_GetObjectItemCaseSensitive(params.get(), "passphrase"));
    TEST_ASSERT_EQUAL_UINT(0, unclearedSecrets);
}

static std::string maximumRequest(std::string_view method, std::string_view params, bool manyValues) {
    std::string text = "{\"method\":\"" + std::string(method) + "\",\"params\":" + std::string(params);
    if (manyValues) {
        text += ",\"extra\":[";
        for (size_t i = 0; i < 244; ++i) text += "null,";
        text += '"';
        text.append(latchkey_util::kMaxRpcText - text.size() - 3, 'x');
        text += "\"]}";
    } else {
        text += ",\"id\":\"";
        text.append(latchkey_util::kMaxRpcText - text.size() - 2, 'x');
        text += "\"}";
    }
    return text;
}

static void test_maximum_payload_roundtrip_respects_explicit_owned_allocation_budgets() {
    seedDecoded(backup_fixture::maximum());
    size_t existingLockBytes = 0;
    for (const auto& allocation : allocation_failure::allocations) existingLockBytes += allocation.size;
    const auto input = maximumRequest("keys.export", R"({"passphrase":"fixture backup passphrase"})", false);
    size_t exportPeak = 0;
    std::string encoded;
    {
        peakTransportBytes = 0;
        const auto response = dispatchRequest(request(input), rpc::Transport::Serial, {});
        exportPeak = peakTransportBytes;
        TEST_ASSERT_LESS_OR_EQUAL_UINT(80 * 1024, exportPeak);
        const auto parsed = responseOf(response);
        TEST_ASSERT_NULL(cJSON_GetObjectItemCaseSensitive(parsed.get(), "error"));
        const auto* result = cJSON_GetObjectItemCaseSensitive(parsed.get(), "result");
        const auto* blob = cJSON_GetObjectItemCaseSensitive(result, "backup");
        TEST_ASSERT_TRUE(cJSON_IsString(blob));
        encoded = blob->valuestring;
    }
    TEST_ASSERT_EQUAL_UINT(10996, encoded.size());
    const auto expected = s_namespaces;
    resetManagerFixture();
    const auto import = maximumRequest("keys.import", importParams(encoded), true);
    peakTransportBytes = 0;
    const auto restored = dispatchRequest(request(import), rpc::Transport::Serial, {});
    const size_t importPeak = peakTransportBytes;
    TEST_ASSERT_LESS_OR_EQUAL_UINT(56 * 1024, importPeak);
    TEST_ASSERT_FALSE(hasError(restored, "bad_request"));
    TEST_ASSERT_TRUE(s_namespaces == expected);
    std::printf("backup owned allocation peaks: export=%zu import=%zu existing-locks=%zu bytes\n",
                exportPeak, importPeak, existingLockBytes);
}

static void test_real_rpc_releases_raw_input_before_crypto_and_wipes_authenticated_plaintext() {
    seed();
    const auto encoded = exportBackup();
    resetManagerFixture();
    const std::string text = "{\"method\":\"keys.import\",\"params\":" + importParams(encoded) + "}";
    auto input = request(text);
    allocation_failure::expectWiped(reinterpret_cast<const uint8_t*>(input.data()), input.capacity() + 1);
    bool rawGone = false;
    beforeDerive = [&] { rawGone = allocation_failure::checkedWipes == 1 && allocation_failure::wiped; };
    watchEnvelope = true;
    watchedSecret = backup_fixture::password;
    const auto response = dispatchRequest(std::move(input), rpc::Transport::Serial, {});
    beforeDerive = {};
    TEST_ASSERT_TRUE(rawGone);
    TEST_ASSERT_EQUAL_UINT(2, allocation_failure::checkedWipes);
    TEST_ASSERT_TRUE(allocation_failure::wiped);
    TEST_ASSERT_EQUAL_UINT(0, unclearedSecrets);
    const auto parsed = responseOf(response);
    TEST_ASSERT_NULL(cJSON_GetObjectItemCaseSensitive(parsed.get(), "error"));
}

static void assertAtomicImportState() {
    const auto found = s_namespaces.find("locks");
    const size_t stored = found == s_namespaces.end() ? 0 : found->second.size();
    TEST_ASSERT_TRUE(stored == 0 || stored == 1);
    TEST_ASSERT_EQUAL_UINT(stored, lock_manager::s_lockCount);
    const auto journal = s_namespaces.find("restore");
    TEST_ASSERT_TRUE(journal == s_namespaces.end() || !journal->second.contains("pending"));
    if (stored == 0) TEST_ASSERT_EQUAL_UINT(0, s_writes);
}

static void test_all_owned_import_allocation_failures_leave_zero_or_complete_published_state() {
    seed();
    const auto encoded = exportBackup();
    const std::string text = "{\"method\":\"keys.import\",\"params\":" + importParams(encoded) + "}";
    size_t attempts = 0;
    resetManagerFixture();
    {
        auto input = request(text);
        allocation_failure::attempts = 0;
        const auto response = dispatchRequest(std::move(input), rpc::Transport::Serial, {});
        attempts = allocation_failure::attempts;
        assertAtomicImportState();
    }
    TEST_ASSERT_GREATER_THAN_UINT(3, attempts);
    for (size_t at = 1; at <= attempts; ++at) {
        resetManagerFixture();
        auto input = request(text);
        allocation_failure::attempts = 0;
        allocation_failure::failAt = at;
        const auto response = dispatchRequest(std::move(input), rpc::Transport::Serial, {});
        allocation_failure::resume();
        assertAtomicImportState();
    }
}

static void test_all_import_json_allocation_failures_release_secret_parameters_and_preserve_atomicity() {
    seed();
    const auto encoded = exportBackup();
    const std::string text = "{\"method\":\"keys.import\",\"params\":" + importParams(encoded) + "}";
    resetManagerFixture();
    size_t attempts = 0;
    {
        allocationAttempts = 0;
        const auto response = dispatchRequest(request(text), rpc::Transport::Serial, {});
        attempts = allocationAttempts;
    }
    for (size_t at = 1; at <= attempts; ++at) {
        resetManagerFixture();
        watchedSecret = backup_fixture::password;
        {
            auto input = request(text);
            allocationAttempts = 0;
            failAllocation = at;
            const auto response = dispatchRequest(std::move(input), rpc::Transport::Serial, {});
            failAllocation = 0;
            assertAtomicImportState();
        }
        TEST_ASSERT_EQUAL_UINT(0, liveBytes);
        TEST_ASSERT_EQUAL_UINT(0, unclearedSecrets);
    }
}

static void test_export_owned_allocation_failures_never_lose_source_keys_or_report_partial_payloads() {
    seed();
    const auto source = s_namespaces;
    const std::string text = R"({"method":"keys.export","params":{"passphrase":"fixture backup passphrase"}})";
    size_t attempts = 0;
    {
        auto input = request(text);
        allocation_failure::attempts = 0;
        const auto response = dispatchRequest(std::move(input), rpc::Transport::Serial, {});
        attempts = allocation_failure::attempts;
    }
    for (size_t at = 1; at <= attempts; ++at) {
        resetManagerFixture();
        s_namespaces = source;
        lock_manager::start();
        auto input = request(text);
        allocation_failure::attempts = 0;
        allocation_failure::failAt = at;
        const auto response = dispatchRequest(std::move(input), rpc::Transport::Serial, {});
        allocation_failure::resume();
        TEST_ASSERT_TRUE(s_namespaces["locks"] == source.at("locks"));
        TEST_ASSERT_TRUE(s_namespaces["seeds"] == source.at("seeds"));
        TEST_ASSERT_TRUE(s_namespaces["labels"] == source.at("labels"));
        if (response.json.empty()) continue;
        const auto parsed = responseOf(response);
        const auto* result = cJSON_GetObjectItemCaseSensitive(parsed.get(), "result");
        if (result == nullptr) continue;
        const auto* blob = cJSON_GetObjectItemCaseSensitive(result, "backup");
        TEST_ASSERT_TRUE(cJSON_IsString(blob));
        TEST_ASSERT_GREATER_THAN_UINT(76, std::strlen(blob->valuestring));
    }
}

int main() {
    rpc::init();
    methods::registerBackup();
    UNITY_BEGIN();
    RUN_TEST(test_backup_methods_require_owner_authentication_and_web_confirmation_but_usb_is_inline);
    RUN_TEST(test_invalid_passphrases_types_and_noncanonical_lock_ids_fail_before_confirmation);
    RUN_TEST(test_invalid_base64_size_padding_and_header_fail_before_confirmation);
    RUN_TEST(test_export_import_roundtrip_preserves_pending_state_and_first_backup_lifecycle);
    RUN_TEST(test_wrong_password_and_damaged_ciphertext_never_write_storage);
    RUN_TEST(test_conflicts_and_capacity_shortage_preserve_storage_without_writes);
    RUN_TEST(test_crypto_and_metadata_write_failures_never_report_a_successful_export);
    RUN_TEST(test_expired_job_and_ended_session_never_derive_or_touch_storage);
    RUN_TEST(test_utf8_passphrase_limits_are_bytes_and_controls_remain_exact);
    RUN_TEST(test_single_lock_export_marks_only_the_selected_identity);
    RUN_TEST(test_unreadable_whole_export_and_aggregate_overflow_never_derive_or_mark_flags);
    RUN_TEST(test_import_releases_encoded_input_before_derivation_and_clears_the_passphrase);
    RUN_TEST(test_maximum_payload_roundtrip_respects_explicit_owned_allocation_budgets);
    RUN_TEST(test_real_rpc_releases_raw_input_before_crypto_and_wipes_authenticated_plaintext);
    RUN_TEST(test_all_owned_import_allocation_failures_leave_zero_or_complete_published_state);
    RUN_TEST(test_all_import_json_allocation_failures_release_secret_parameters_and_preserve_atomicity);
    RUN_TEST(test_export_owned_allocation_failures_never_lose_source_keys_or_report_partial_payloads);
    return UNITY_END();
}
