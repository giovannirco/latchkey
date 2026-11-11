// SPDX-License-Identifier: GPL-3.0-or-later
#include "lock_manager_test_runtime.h"
#include "../reference/backup_fixture.h"
#include "../fake_lock/fake_lock.h"
#include "../../src/methods_credentials.cpp"

void setUp() { resetManagerFixture(); }
void tearDown() { clearManagerFixture(); }

struct Rig {
    fake::FakeLock lock;
    ttlock::AesKey key{};
    Rig() {
        bluetoothReady = true;
        fixtureTransport = &lock;
        const auto decoded = backup_fixture::make();
        store::locks::Record record;
        TEST_ASSERT_TRUE(key_store::makeRecord(decoded.locks()[0], record));
        std::copy(std::begin(record.aesKey), std::end(record.aesKey), key.begin());
        record.features = ttlock::featureBit(ttlock::Feature::FingerPrint) | ttlock::featureBit(ttlock::Feature::Ic);
        record.flags |= store::locks::kFlagTimeCalibrated;
        TEST_ASSERT_EQUAL_INT(ESP_OK, lock_manager::persist(record));
        latchkey_util::LabelTable labels;
        labels.put({17, false, "Entry method", {}});
        for (char kind : {'f', 'c'}) s_namespaces["labels"][std::string(kKey) + kind] = {NVS_TYPE_BLOB, labels.encode()};
    }
    void expect(uint8_t command, const ttlock::Bytes& data) {
        lock.expect(ttlock::command::kCheckAdmin, key, {fake::success(key, ttlock::command::kCheckAdmin, fake::be32(1))});
        lock.expect(ttlock::command::kCheckRandom, key, {fake::success(key, ttlock::command::kCheckRandom)});
        lock.expect(command, key, {fake::success(key, command, data)});
    }
};

static rpc::Json params() { return rpc::Json(cJSON_Parse(R"({"lock":"00:00:5E:00:53:01","id":"17"})")); }

static void test_failed_retention_prevents_fingerprint_and_card_delete_or_clear() {
    for (const auto* kind : {&methods::kFingerprints, &methods::kCards}) {
        for (bool clear : {false, true}) {
            resetManagerFixture();
            Rig rig;
            s_failWrite = s_writes + 1;
            const auto input = params();
            const auto reply = clear ? methods::credentialsClear(*kind, input.get()) : methods::credentialsDelete(*kind, input.get());
            TEST_ASSERT_FALSE(reply.error.empty());
            TEST_ASSERT_TRUE(rig.lock.requests().empty());
        }
    }
}

static void test_failed_pruning_is_reported_and_keeps_the_original_label() {
    Rig rig;
    rig.expect(ttlock::command::kManageFingerprint, {0, 6, 0xFF, 0xFF});
    s_failWrite = s_writes + 1;
    const auto input = params();
    const auto reply = methods::credentialsList(methods::kFingerprints, input.get());
    TEST_ASSERT_TRUE(rig.lock.scriptDone());
    TEST_ASSERT_EQUAL_UINT(0, rig.lock.unexpected());
    TEST_ASSERT_FALSE(reply.error.empty());
    latchkey_util::LabelTable loaded;
    TEST_ASSERT_EQUAL_INT(ESP_OK, lock_manager::loadLabels(std::string(kMac), store::labels::Kind::Fingerprints, loaded));
    TEST_ASSERT_NOT_NULL(loaded.find(17));
}

static void test_successful_deletion_keeps_the_name_for_log_attribution() {
    for (const auto* kind : {&methods::kFingerprints, &methods::kCards}) {
        resetManagerFixture();
        Rig rig;
        rig.expect(kind == &methods::kFingerprints ? ttlock::command::kManageFingerprint : ttlock::command::kManageIcCard, {});
        const auto input = params();
        const auto reply = methods::credentialsDelete(*kind, input.get());
        TEST_ASSERT_TRUE(reply.error.empty());
        TEST_ASSERT_EQUAL_UINT(0, rig.lock.unexpected());
        TEST_ASSERT_TRUE(rig.lock.scriptDone());
        latchkey_util::LogLabels labels;
        TEST_ASSERT_EQUAL_INT(ESP_OK, lock_manager::loadLogLabels(std::string(kMac), labels));
        TEST_ASSERT_NOT_NULL(labels.retired.find(static_cast<char>(kind->labels), 17));
        TEST_ASSERT_EQUAL_STRING("Entry method", labels.retired.find(static_cast<char>(kind->labels), 17)->name.c_str());
        const auto& current = kind == &methods::kFingerprints ? labels.fingerprints : labels.cards;
        TEST_ASSERT_NULL(current.find(17));
    }
}

static void test_unnamed_reenrollment_clears_previous_current_and_retired_names() {
    for (const auto* kind : {&methods::kFingerprints, &methods::kCards}) {
        resetManagerFixture();
        Rig rig;
        latchkey_util::RetiredLabels retired;
        TEST_ASSERT_TRUE(retired.remember(static_cast<char>(kind->labels), 17, "Previous holder"));
        TEST_ASSERT_EQUAL_INT(ESP_OK, store::labels::saveRetired(kMac.data(), retired));
        const uint8_t command = kind == &methods::kFingerprints ? ttlock::command::kManageFingerprint : ttlock::command::kManageIcCard;
        ttlock::Bytes added{80, 2, 1};
        added.insert(added.end(), kind == &methods::kFingerprints ? 5 : 3, 0);
        added.push_back(17);
        rig.expect(command, added);
        rig.lock.expect(command, rig.key, {fake::success(rig.key, command, {80, 5})});
        const auto input = params();
        const auto reply = methods::credentialsEnroll(*kind, input.get());
        TEST_ASSERT_TRUE(reply.error.empty());
        TEST_ASSERT_EQUAL_UINT(0, rig.lock.unexpected());
        TEST_ASSERT_TRUE(rig.lock.scriptDone());
        latchkey_util::LogLabels labels;
        TEST_ASSERT_EQUAL_INT(ESP_OK, lock_manager::loadLogLabels(std::string(kMac), labels));
        TEST_ASSERT_NULL(labels.retired.find(static_cast<char>(kind->labels), 17));
        const auto& current = kind == &methods::kFingerprints ? labels.fingerprints : labels.cards;
        TEST_ASSERT_NULL(current.find(17));
    }
}

static void test_listing_a_live_unnamed_id_invalidates_its_retired_label() {
    Rig rig;
    latchkey_util::RetiredLabels retired;
    TEST_ASSERT_TRUE(retired.remember('f', 17, "Previous holder"));
    TEST_ASSERT_EQUAL_INT(ESP_OK, store::labels::saveRetired(kMac.data(), retired));
    TEST_ASSERT_EQUAL_INT(ESP_OK, store::labels::save(kMac.data(), store::labels::Kind::Fingerprints, {}));
    ttlock::Bytes page{80, 6, 0xFF, 0xFF};
    const auto record = ttlock::buildFingerprintSetValidity(17, {});
    page.insert(page.end(), record.begin() + 1, record.end());
    rig.expect(ttlock::command::kManageFingerprint, page);
    const auto input = params();
    const auto reply = methods::credentialsList(methods::kFingerprints, input.get());
    TEST_ASSERT_TRUE(reply.error.empty());
    TEST_ASSERT_EQUAL_UINT(0, rig.lock.unexpected());
    TEST_ASSERT_TRUE(rig.lock.scriptDone());
    latchkey_util::LogLabels labels;
    TEST_ASSERT_EQUAL_INT(ESP_OK, lock_manager::loadLogLabels(std::string(kMac), labels));
    TEST_ASSERT_NULL(labels.retired.find('f', 17));
}

int main() {
    rpc::init();
    UNITY_BEGIN();
    RUN_TEST(test_failed_retention_prevents_fingerprint_and_card_delete_or_clear);
    RUN_TEST(test_failed_pruning_is_reported_and_keeps_the_original_label);
    RUN_TEST(test_successful_deletion_keeps_the_name_for_log_attribution);
    RUN_TEST(test_unnamed_reenrollment_clears_previous_current_and_retired_names);
    RUN_TEST(test_listing_a_live_unnamed_id_invalidates_its_retired_label);
    return UNITY_END();
}
