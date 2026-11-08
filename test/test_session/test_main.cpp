// SPDX-License-Identifier: GPL-3.0-or-later
#include <unity.h>

#include <cstddef>
#include <cstdint>
#include <initializer_list>
#include <string>
#include <utility>
#include <vector>

#include "../fake_lock/fake_lock.h"
#include "ttlock/aes.h"
#include "ttlock/commands.h"
#include "ttlock/features.h"
#include "ttlock/session.h"
#include "ttlock/status.h"
#include "ttlock/types.h"

using fake::After;
using fake::be32;
using fake::concat;
using fake::failure;
using fake::FakeClock;
using fake::FakeLock;
using fake::FakeRandom;
using fake::lockFrame;
using fake::success;
using fake::text;
using ttlock::AesKey;
using ttlock::Bytes;
using ttlock::Feature;
using ttlock::Status;
namespace cmd = ttlock::command;

static const AesKey kDefault = ttlock::kDefaultAesKey;
static const AesKey kLockKey{0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77,
                             0x88, 0x99, 0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF};
static const AesKey kOtherKey{0x0F, 0x0E, 0x0D, 0x0C, 0x0B, 0x0A, 0x09, 0x08,
                              0x07, 0x06, 0x05, 0x04, 0x03, 0x02, 0x01, 0x00};
static constexpr uint32_t kAdminPs = 12345678;
static constexpr uint32_t kUnlockKey = 87654321;
static constexpr uint32_t kPs = 0x0A0B0C0D;
static const char* const kMac = "11:22:33:44:55:66";

struct Rig {
    FakeLock lock;
    FakeClock clock;
    FakeRandom random;
    ttlock::Session session{lock, clock, random};
    std::vector<ttlock::LockEvent> events;

    Rig() {
        session.setEventSink([this](const ttlock::LockEvent& event) { events.push_back(event); });
    }
};

void setUp() {}

void tearDown() {}

static void assertStatus(Status expected, Status actual) {
    TEST_ASSERT_EQUAL_STRING(ttlock::toString(expected), ttlock::toString(actual));
}

static void assertCommands(std::initializer_list<uint8_t> expected, const FakeLock& lock) {
    const std::vector<uint8_t> want(expected);
    const std::vector<uint8_t> got = lock.commands();
    TEST_ASSERT_EQUAL_UINT_MESSAGE(want.size(), got.size(), "number of commands sent");
    if (!want.empty()) {
        TEST_ASSERT_EQUAL_HEX8_ARRAY(want.data(), got.data(), want.size());
    }
}

static void assertPayload(const Bytes& expected, const fake::Request& request) {
    TEST_ASSERT_EQUAL_UINT_MESSAGE(expected.size(), request.payload.size(), "payload size");
    if (!expected.empty()) {
        TEST_ASSERT_EQUAL_HEX8_ARRAY(expected.data(), request.payload.data(), expected.size());
    }
}

static uint64_t bits(std::initializer_list<Feature> features) {
    uint64_t mask = 0;
    for (Feature feature : features) {
        mask |= ttlock::featureBit(feature);
    }
    return mask;
}

static uint64_t everyFeature() {
    uint64_t mask = 0;
    for (Feature feature : ttlock::kAllFeatures) {
        mask |= ttlock::featureBit(feature);
    }
    return mask;
}

static Bytes keyBytes(const AesKey& key) {
    return Bytes(key.begin(), key.end());
}

static Bytes featureData(uint64_t mask) {
    return concat({Bytes{0x64}, be32(static_cast<uint32_t>(mask)), be32(static_cast<uint32_t>(mask >> 32))});
}

static Bytes statePush(uint8_t state) {
    return success(kLockKey, cmd::kSearchStatus, Bytes{0x5A, state, 0x00});
}

static Bytes logPush() {
    return success(kLockKey, cmd::kSearchStatus,
                   concat({Bytes{0x5A}, be32(0), be32(42), Bytes{25, 11, 7, 14, 0, 5}}));
}

static ttlock::LockKeys pairedKeys(uint64_t features = everyFeature()) {
    ttlock::LockKeys keys;
    keys.mac = kMac;
    keys.version = fake::kRequestVersion;
    keys.aesKey = kLockKey;
    keys.adminPs = kAdminPs;
    keys.unlockKey = kUnlockKey;
    keys.features = features;
    keys.adminPasscode = "3141592";
    return keys;
}

static void attach(Rig& rig, uint64_t features = everyFeature()) {
    assertStatus(Status::Ok, rig.session.attach(pairedKeys(features)));
}

static void expectAdminLogin(FakeLock& lock) {
    lock.expect(cmd::kCheckAdmin, kLockKey, {success(kLockKey, cmd::kCheckAdmin, be32(0x01020304))});
    lock.expect(cmd::kCheckRandom, kLockKey, {success(kLockKey, cmd::kCheckRandom)});
}

struct PairStep {
    uint8_t command;
    AesKey key;
    std::vector<Bytes> replies;
    After after = After::Stay;
};

static std::vector<PairStep> pairingSteps(uint64_t features) {
    std::vector<PairStep> steps;
    steps.push_back({cmd::kInitialization, kDefault, {success(kDefault, cmd::kInitialization)}});
    steps.push_back({cmd::kGetAesKey, kDefault, {success(kDefault, cmd::kGetAesKey, keyBytes(kLockKey))}});
    steps.push_back({cmd::kAddAdmin, kLockKey, {success(kLockKey, cmd::kAddAdmin, text("SCIENER"))}});
    steps.push_back({cmd::kTimeCalibrate, kLockKey, {success(kLockKey, cmd::kTimeCalibrate)}});
    steps.push_back({cmd::kSearchDeviceFeature, kLockKey,
                     {success(kLockKey, cmd::kSearchDeviceFeature, featureData(features))}});
    const uint64_t switches = bits({Feature::ResetButton, Feature::TamperAlert, Feature::PrivacyLock});
    if ((features & switches) != 0) {
        steps.push_back({cmd::kSwitch, kLockKey, {success(kLockKey, cmd::kSwitch, Bytes{0x64, 0x01, 0, 0, 0, 2})}});
    }
    if (ttlock::hasFeature(features, Feature::AudioManagement)) {
        steps.push_back({cmd::kAudioManage, kLockKey, {success(kLockKey, cmd::kAudioManage, Bytes{0x64, 0x01, 0x01})}});
    }
    if (ttlock::hasFeature(features, Feature::PasswordDisplayOrHide)) {
        steps.push_back({cmd::kShowPassword, kLockKey, {success(kLockKey, cmd::kShowPassword, Bytes{0x01, 0x01})}});
    }
    if (ttlock::hasFeature(features, Feature::AutoLock)) {
        steps.push_back({cmd::kAutoLockManage, kLockKey,
                         {success(kLockKey, cmd::kAutoLockManage, Bytes{0x64, 0x01, 0x00, 0x00, 0x00, 0x05, 0x00, 0xB4})}});
    }
    if (ttlock::hasFeature(features, Feature::GetAdminCode)) {
        steps.push_back({cmd::kGetAdminCode, kLockKey, {success(kLockKey, cmd::kGetAdminCode, Bytes{0x00, 0x00})}});
    }
    steps.push_back({cmd::kSetAdminKeyboardPassword, kLockKey, {success(kLockKey, cmd::kSetAdminKeyboardPassword)}});
    steps.push_back({cmd::kInitPasswords, kLockKey, {success(kLockKey, cmd::kInitPasswords)}});
    if (ttlock::hasFeature(features, Feature::ConfigGatewayUnlock)) {
        steps.push_back({cmd::kControlRemoteUnlock, kLockKey,
                         {success(kLockKey, cmd::kControlRemoteUnlock, Bytes{0x64, 0x01, 0x00})}});
    }
    steps.push_back({cmd::kOperateFinished, kLockKey, {success(kLockKey, cmd::kOperateFinished)}});
    return steps;
}

static PairStep& stepFor(std::vector<PairStep>& steps, uint8_t command) {
    for (PairStep& step : steps) {
        if (step.command == command) {
            return step;
        }
    }
    TEST_FAIL_MESSAGE("no such pairing step");
    return steps.front();
}

static void load(FakeLock& lock, std::vector<PairStep> steps) {
    for (PairStep& step : steps) {
        lock.expect(step.command, step.key, std::move(step.replies), step.after);
    }
}

struct Persisted {
    std::vector<ttlock::LockKeys> calls;
    std::vector<size_t> requestsSeen;
    ttlock::PairResult result;
};

static Status pair(Rig& rig, ttlock::LockKeys& out, Persisted& persisted) {
    out.mac = kMac;
    return rig.session.pair(
        fake::kRequestVersion, out,
        [&persisted, &rig](const ttlock::LockKeys& keys) {
            persisted.calls.push_back(keys);
            persisted.requestsSeen.push_back(rig.lock.requests().size());
        },
        persisted.result);
}

static size_t indexOf(const FakeLock& lock, uint8_t command) {
    const std::vector<uint8_t> commands = lock.commands();
    for (size_t i = 0; i < commands.size(); ++i) {
        if (commands[i] == command) {
            return i;
        }
    }
    TEST_FAIL_MESSAGE("command was not sent");
    return 0;
}

static bool undecodable(const Bytes& raw, const AesKey& key) {
    ttlock::DecodedFrame frame;
    return ttlock::decodeFrame(raw, key, frame) != Status::Ok;
}

static const uint64_t kAllOptionalReads =
    bits({Feature::Passcode, Feature::ResetButton, Feature::AudioManagement, Feature::PasswordDisplayOrHide,
          Feature::AutoLock, Feature::GetAdminCode, Feature::ConfigGatewayUnlock});

static void test_pair_runs_the_kind3r_sequence_with_every_optional_read() {
    Rig rig;
    load(rig.lock, pairingSteps(kAllOptionalReads));
    ttlock::LockKeys keys;
    Persisted persisted;
    assertStatus(Status::Ok, pair(rig, keys, persisted));
    assertCommands({0x45, 0x19, 0x56, 0x43, 0x01, 0x68, 0x62, 0x59, 0x36, 0x65, 0x53, 0x31, 0x37, 0x57}, rig.lock);
    TEST_ASSERT_TRUE(rig.lock.scriptDone());
    TEST_ASSERT_EQUAL_UINT(0, rig.lock.unexpected());
}

static void test_pair_without_optional_features_sends_only_the_mandatory_steps() {
    Rig rig;
    load(rig.lock, pairingSteps(bits({Feature::Passcode})));
    ttlock::LockKeys keys;
    Persisted persisted;
    assertStatus(Status::Ok, pair(rig, keys, persisted));
    assertCommands({0x45, 0x19, 0x56, 0x43, 0x01, 0x53, 0x31, 0x57}, rig.lock);
    TEST_ASSERT_TRUE(rig.lock.scriptDone());
}

static void test_pair_uses_the_default_key_until_the_lock_hands_over_its_own() {
    Rig rig;
    load(rig.lock, pairingSteps(kAllOptionalReads));
    ttlock::LockKeys keys;
    Persisted persisted;
    assertStatus(Status::Ok, pair(rig, keys, persisted));
    TEST_ASSERT_EQUAL_UINT(0, rig.lock.unexpected());
    for (const fake::Request& request : rig.lock.requests()) {
        TEST_ASSERT_TRUE(request.crlf);
        TEST_ASSERT_TRUE(request.decoded);
        TEST_ASSERT_TRUE(request.crcOk);
        TEST_ASSERT_EQUAL_UINT8(5, request.version.protocolType);
        TEST_ASSERT_EQUAL_UINT8(3, request.version.protocolVersion);
        TEST_ASSERT_EQUAL_UINT8(1, request.version.scene);
        TEST_ASSERT_EQUAL_UINT16(1, request.version.groupId);
        TEST_ASSERT_EQUAL_UINT16(1, request.version.orgId);
    }
    assertPayload(Bytes{}, rig.lock.requests()[0]);
    assertPayload(text("SCIENER"), rig.lock.requests()[1]);
    TEST_ASSERT_EQUAL_HEX8_ARRAY(kLockKey.data(), keys.aesKey.data(), 16);
}

static void test_pair_persists_after_add_admin_before_the_admin_passcode_and_when_final() {
    Rig rig;
    load(rig.lock, pairingSteps(kAllOptionalReads));
    ttlock::LockKeys keys;
    Persisted persisted;
    assertStatus(Status::Ok, pair(rig, keys, persisted));
    TEST_ASSERT_EQUAL_UINT(3, persisted.calls.size());
    TEST_ASSERT_EQUAL_UINT(3, persisted.requestsSeen[0]);
    const ttlock::LockKeys& early = persisted.calls[0];
    TEST_ASSERT_EQUAL_STRING(kMac, early.mac.c_str());
    TEST_ASSERT_EQUAL_HEX8_ARRAY(kLockKey.data(), early.aesKey.data(), 16);
    TEST_ASSERT_NOT_EQUAL(0, early.adminPs);
    TEST_ASSERT_NOT_EQUAL(0, early.unlockKey);
    TEST_ASSERT_EQUAL_HEX64(0, early.features);
    TEST_ASSERT_TRUE(early.adminPasscode.empty());
    TEST_ASSERT_EQUAL_UINT(indexOf(rig.lock, cmd::kSetAdminKeyboardPassword), persisted.requestsSeen[1]);
    TEST_ASSERT_EQUAL_HEX64(kAllOptionalReads, persisted.calls[1].features);
    TEST_ASSERT_EQUAL_STRING(keys.adminPasscode.c_str(), persisted.calls[1].adminPasscode.c_str());
    TEST_ASSERT_EQUAL_UINT(rig.lock.requests().size(), persisted.requestsSeen[2]);
    const ttlock::LockKeys& last = persisted.calls[2];
    TEST_ASSERT_EQUAL_HEX64(kAllOptionalReads, last.features);
    TEST_ASSERT_EQUAL_HEX64(kAllOptionalReads, keys.features);
    TEST_ASSERT_EQUAL_STRING(last.adminPasscode.c_str(), keys.adminPasscode.c_str());
    TEST_ASSERT_EQUAL_UINT(ttlock::kAdminPasscodeDigits, keys.adminPasscode.size());
    TEST_ASSERT_EQUAL_UINT32(early.adminPs, keys.adminPs);
    TEST_ASSERT_EQUAL_UINT32(early.unlockKey, keys.unlockKey);
    TEST_ASSERT_EQUAL_UINT32(0, keys.lockFlagPos);
    TEST_ASSERT_EQUAL_STRING(kMac, keys.mac.c_str());
    TEST_ASSERT_EQUAL_UINT8(5, keys.version.protocolType);
    TEST_ASSERT_EQUAL_UINT8(1, keys.version.scene);
    TEST_ASSERT_EQUAL_STRING(kMac, rig.session.keys().mac.c_str());
}

static void test_add_admin_carries_the_random_secrets_and_sciener() {
    Rig rig;
    load(rig.lock, pairingSteps(bits({Feature::Passcode})));
    ttlock::LockKeys keys;
    Persisted persisted;
    assertStatus(Status::Ok, pair(rig, keys, persisted));
    assertPayload(concat({be32(keys.adminPs), be32(keys.unlockKey), text("SCIENER")}), rig.lock.requests()[2]);
    TEST_ASSERT_TRUE(keys.adminPs >= 1 && keys.adminPs <= 999999999);
    TEST_ASSERT_TRUE(keys.unlockKey >= 1 && keys.unlockKey <= 999999999);
}

static void scriptSecrets(FakeRandom& random) {
    random.scriptU32(12345677);
    random.scriptU32(87654320);
    for (uint32_t digit : {3u, 1u, 4u, 1u, 5u, 9u, 2u}) {
        random.scriptU32(digit);
    }
}

static void test_secrets_and_admin_passcode_are_drawn_from_random() {
    Rig rig;
    scriptSecrets(rig.random);
    load(rig.lock, pairingSteps(bits({Feature::Passcode})));
    ttlock::LockKeys keys;
    Persisted persisted;
    assertStatus(Status::Ok, pair(rig, keys, persisted));
    TEST_ASSERT_EQUAL_UINT32(kAdminPs, keys.adminPs);
    TEST_ASSERT_EQUAL_UINT32(kUnlockKey, keys.unlockKey);
    TEST_ASSERT_EQUAL_STRING("3141592", keys.adminPasscode.c_str());
    const auto& requests = rig.lock.requests();
    assertPayload(Bytes{3, 1, 4, 1, 5, 9, 2}, requests[5]);
    TEST_ASSERT_EQUAL_HEX8(cmd::kSetAdminKeyboardPassword, requests[5].command);
}

static void test_random_draws_reject_the_biased_tail() {
    Rig rig;
    rig.random.scriptU32(0xFFFFFFFF);
    rig.random.scriptU32(41);
    rig.random.scriptU32(87654320);
    rig.random.scriptU32(0xFFFFFFFF);
    for (uint32_t digit : {7u, 0u, 0u, 0u, 0u, 0u, 1u}) {
        rig.random.scriptU32(digit);
    }
    load(rig.lock, pairingSteps(bits({Feature::Passcode})));
    ttlock::LockKeys keys;
    Persisted persisted;
    assertStatus(Status::Ok, pair(rig, keys, persisted));
    TEST_ASSERT_EQUAL_UINT32(42, keys.adminPs);
    TEST_ASSERT_EQUAL_STRING("7000001", keys.adminPasscode.c_str());
}

static void test_pair_calibrates_the_lock_to_local_wall_time() {
    Rig rig;
    load(rig.lock, pairingSteps(bits({Feature::Passcode})));
    ttlock::LockKeys keys;
    Persisted persisted;
    assertStatus(Status::Ok, pair(rig, keys, persisted));
    assertPayload(Bytes{25, 11, 7, 11, 0, 0}, rig.lock.requests()[3]);
}

static void assertInitPasswordsYear(int64_t utc, int32_t offset, uint8_t year) {
    Rig rig;
    rig.clock.utc = utc;
    rig.clock.offset = offset;
    load(rig.lock, pairingSteps(bits({Feature::Passcode})));
    ttlock::LockKeys keys;
    Persisted persisted;
    assertStatus(Status::Ok, pair(rig, keys, persisted));
    const fake::Request& request = rig.lock.requests()[6];
    TEST_ASSERT_EQUAL_HEX8(cmd::kInitPasswords, request.command);
    TEST_ASSERT_EQUAL_UINT(1 + 10 * 6, request.payload.size());
    TEST_ASSERT_EQUAL_UINT8(year, request.payload[0]);
    for (size_t i = 0; i < 10; ++i) {
        const uint8_t* combo = request.payload.data() + 1 + i * 6;
        const unsigned code = static_cast<unsigned>(combo[0]) << 4 | combo[1] >> 4;
        const uint64_t secret = static_cast<uint64_t>(combo[1] & 0x0F) << 32 | static_cast<uint64_t>(combo[2]) << 24 |
                                static_cast<uint64_t>(combo[3]) << 16 | static_cast<uint64_t>(combo[4]) << 8 | combo[5];
        TEST_ASSERT_TRUE(code < 1071);
        TEST_ASSERT_TRUE(secret < 10000000000ULL);
    }
}

static void test_init_passwords_uses_the_local_year_except_on_new_years_day() {
    assertInitPasswordsYear(1762524000, -3 * 3600, 25);
    assertInitPasswordsYear(1767236400, -3 * 3600, 25);
    assertInitPasswordsYear(1767236400, 0, 25);
    assertInitPasswordsYear(1767322800, -3 * 3600, 26);
}

static void test_link_drop_after_add_admin_is_pair_incomplete_with_keys_persisted() {
    Rig rig;
    std::vector<PairStep> steps = pairingSteps(bits({Feature::Passcode}));
    steps.resize(3);
    steps[2].after = After::Drop;
    load(rig.lock, std::move(steps));
    ttlock::LockKeys keys;
    Persisted persisted;
    assertStatus(Status::PairIncomplete, pair(rig, keys, persisted));
    TEST_ASSERT_EQUAL_UINT(1, persisted.calls.size());
    TEST_ASSERT_EQUAL_UINT(3, persisted.requestsSeen[0]);
    TEST_ASSERT_EQUAL_HEX8_ARRAY(kLockKey.data(), keys.aesKey.data(), 16);
    TEST_ASSERT_EQUAL_UINT32(persisted.calls[0].adminPs, keys.adminPs);
    TEST_ASSERT_EQUAL_UINT32(persisted.calls[0].unlockKey, keys.unlockKey);
    TEST_ASSERT_EQUAL_UINT(3, rig.lock.requests().size());
    TEST_ASSERT_EQUAL_UINT32(keys.adminPs, rig.session.keys().adminPs);
}

static void test_add_admin_without_a_reply_persists_and_is_pair_incomplete() {
    Rig rig;
    std::vector<PairStep> steps = pairingSteps(bits({Feature::Passcode}));
    steps.resize(3);
    steps[2].replies.clear();
    load(rig.lock, std::move(steps));
    ttlock::LockKeys keys;
    Persisted persisted;
    assertStatus(Status::PairIncomplete, pair(rig, keys, persisted));
    TEST_ASSERT_EQUAL_UINT(1, persisted.calls.size());
    TEST_ASSERT_EQUAL_UINT(3, rig.lock.requests().size());
}

static void test_add_admin_without_the_sciener_echo_is_pair_incomplete() {
    Rig rig;
    std::vector<PairStep> steps = pairingSteps(bits({Feature::Passcode}));
    steps.resize(3);
    steps[2].replies = {success(kLockKey, cmd::kAddAdmin, text("SCIENEX"))};
    load(rig.lock, std::move(steps));
    ttlock::LockKeys keys;
    Persisted persisted;
    assertStatus(Status::PairIncomplete, pair(rig, keys, persisted));
    TEST_ASSERT_EQUAL_UINT(1, persisted.calls.size());
}

static void test_add_admin_refused_by_the_lock_persists_nothing() {
    Rig rig;
    std::vector<PairStep> steps = pairingSteps(bits({Feature::Passcode}));
    steps.resize(3);
    steps[2].replies = {failure(kLockKey, cmd::kAddAdmin, 0x05)};
    load(rig.lock, std::move(steps));
    ttlock::LockKeys keys;
    Persisted persisted;
    assertStatus(Status::LockError, pair(rig, keys, persisted));
    TEST_ASSERT_EQUAL_HEX8(0x05, rig.session.lockErrorCode());
    TEST_ASSERT_EQUAL_UINT(0, persisted.calls.size());
    ttlock::LockStatus status;
    assertStatus(Status::NotPaired, rig.session.status(status));
    TEST_ASSERT_EQUAL_UINT(3, rig.lock.requests().size());
}

static void test_get_aes_key_timeout_fails_before_any_key_exists() {
    Rig rig;
    std::vector<PairStep> steps = pairingSteps(bits({Feature::Passcode}));
    steps.resize(2);
    steps[1].replies.clear();
    load(rig.lock, std::move(steps));
    ttlock::LockKeys keys;
    Persisted persisted;
    assertStatus(Status::Timeout, pair(rig, keys, persisted));
    TEST_ASSERT_EQUAL_UINT(0, persisted.calls.size());
    TEST_ASSERT_EQUAL_UINT(2, rig.lock.requests().size());
}

static void test_short_aes_key_reply_is_bad_response() {
    Rig rig;
    std::vector<PairStep> steps = pairingSteps(bits({Feature::Passcode}));
    steps.resize(2);
    steps[1].replies = {success(kDefault, cmd::kGetAesKey, Bytes(15, 0x42))};
    load(rig.lock, std::move(steps));
    ttlock::LockKeys keys;
    Persisted persisted;
    assertStatus(Status::BadResponse, pair(rig, keys, persisted));
    TEST_ASSERT_EQUAL_UINT(0, persisted.calls.size());
}

static void test_pair_with_an_unsynced_clock_sends_nothing() {
    Rig rig;
    rig.clock.isSynced = false;
    ttlock::LockKeys keys;
    Persisted persisted;
    assertStatus(Status::TimeUnsynced, pair(rig, keys, persisted));
    TEST_ASSERT_EQUAL_UINT(0, rig.lock.requests().size());
    TEST_ASSERT_EQUAL_UINT(0, rig.random.drawn());
}

static void test_pair_with_a_clock_before_2024_sends_nothing() {
    Rig rig;
    rig.clock.utc = ttlock::kEarliestUsableUtc - 1;
    ttlock::LockKeys keys;
    Persisted persisted;
    assertStatus(Status::TimeUnsynced, pair(rig, keys, persisted));
    TEST_ASSERT_EQUAL_UINT(0, rig.lock.requests().size());
}

static void test_pair_rejects_a_legacy_frame_layout_without_traffic() {
    Rig rig;
    ttlock::LockKeys keys;
    ttlock::PairResult result;
    Status status = rig.session.pair(ttlock::LockVersion{3, 0, 0, 0, 0}, keys, nullptr, result);
    assertStatus(Status::Unsupported, status);
    TEST_ASSERT_EQUAL_UINT(0, rig.lock.requests().size());
}

static void test_pair_accepts_an_empty_initialization_reply_and_no_persist_callback() {
    Rig rig;
    std::vector<PairStep> steps = pairingSteps(bits({Feature::Passcode}));
    steps[0].replies = {lockFrame(kDefault, Bytes{})};
    load(rig.lock, std::move(steps));
    ttlock::LockKeys keys;
    ttlock::PairResult result;
    assertStatus(Status::Ok, rig.session.pair(fake::kRequestVersion, keys, nullptr, result));
    TEST_ASSERT_TRUE(rig.lock.scriptDone());
}

static void test_refused_optional_reads_and_calibration_do_not_stop_pairing() {
    Rig rig;
    std::vector<PairStep> steps = pairingSteps(kAllOptionalReads);
    stepFor(steps, cmd::kTimeCalibrate).replies = {failure(kLockKey, cmd::kTimeCalibrate, 0x01)};
    stepFor(steps, cmd::kSwitch).replies = {failure(kLockKey, cmd::kSwitch, 0x02)};
    stepFor(steps, cmd::kAudioManage).replies = {failure(kLockKey, cmd::kAudioManage, 0x02)};
    stepFor(steps, cmd::kShowPassword).replies = {failure(kLockKey, cmd::kShowPassword, 0x02)};
    stepFor(steps, cmd::kAutoLockManage).replies = {failure(kLockKey, cmd::kAutoLockManage, 0x02)};
    stepFor(steps, cmd::kGetAdminCode).replies = {failure(kLockKey, cmd::kGetAdminCode, 0x02)};
    stepFor(steps, cmd::kControlRemoteUnlock).replies = {failure(kLockKey, cmd::kControlRemoteUnlock, 0x02)};
    load(rig.lock, std::move(steps));
    ttlock::LockKeys keys;
    Persisted persisted;
    assertStatus(Status::Ok, pair(rig, keys, persisted));
    TEST_ASSERT_TRUE(rig.lock.scriptDone());
    TEST_ASSERT_EQUAL_UINT(3, persisted.calls.size());
    TEST_ASSERT_FALSE(persisted.result.timeCalibrated);
    TEST_ASSERT_TRUE(persisted.result.adminPasscodeConfirmed);
}

static void test_a_silent_time_calibration_does_not_stop_pairing() {
    Rig rig;
    std::vector<PairStep> steps = pairingSteps(bits({Feature::Passcode}));
    stepFor(steps, cmd::kTimeCalibrate).replies.clear();
    load(rig.lock, std::move(steps));
    ttlock::LockKeys keys;
    Persisted persisted;
    assertStatus(Status::Ok, pair(rig, keys, persisted));
    TEST_ASSERT_FALSE(persisted.result.timeCalibrated);
    TEST_ASSERT_TRUE(persisted.result.adminPasscodeConfirmed);
    assertCommands({0x45, 0x19, 0x56, 0x43, 0x01, 0x53, 0x31, 0x57}, rig.lock);
    TEST_ASSERT_TRUE(rig.lock.scriptDone());

    Rig calibrated;
    load(calibrated.lock, pairingSteps(bits({Feature::Passcode})));
    ttlock::LockKeys calibratedKeys;
    Persisted calibratedPersisted;
    assertStatus(Status::Ok, pair(calibrated, calibratedKeys, calibratedPersisted));
    TEST_ASSERT_TRUE(calibratedPersisted.result.timeCalibrated);
}

static void test_a_broken_time_calibration_reply_still_stops_pairing() {
    Rig rig;
    std::vector<PairStep> steps = pairingSteps(bits({Feature::Passcode}));
    stepFor(steps, cmd::kTimeCalibrate).replies = {fake::withBadCrc(success(kLockKey, cmd::kTimeCalibrate))};
    load(rig.lock, std::move(steps));
    ttlock::LockKeys keys;
    Persisted persisted;
    assertStatus(Status::PairIncomplete, pair(rig, keys, persisted));
    TEST_ASSERT_EQUAL_HEX8(cmd::kTimeCalibrate, rig.lock.commands().back());
}

static void test_a_confirmed_admin_passcode_is_persisted_before_it_is_sent() {
    Rig rig;
    load(rig.lock, pairingSteps(bits({Feature::Passcode})));
    ttlock::LockKeys keys;
    Persisted persisted;
    assertStatus(Status::Ok, pair(rig, keys, persisted));
    TEST_ASSERT_TRUE(persisted.result.adminPasscodeConfirmed);
    TEST_ASSERT_EQUAL_UINT(3, persisted.calls.size());
    const size_t sent = indexOf(rig.lock, cmd::kSetAdminKeyboardPassword);
    TEST_ASSERT_EQUAL_UINT(sent, persisted.requestsSeen[1]);
    TEST_ASSERT_EQUAL_UINT(ttlock::kAdminPasscodeDigits, persisted.calls[1].adminPasscode.size());
    TEST_ASSERT_EQUAL_STRING(persisted.calls[1].adminPasscode.c_str(), keys.adminPasscode.c_str());
    TEST_ASSERT_EQUAL_STRING(keys.adminPasscode.c_str(), persisted.calls[2].adminPasscode.c_str());
}

static void test_a_refused_admin_passcode_rolls_back_and_makes_pairing_incomplete() {
    Rig rig;
    std::vector<PairStep> steps = pairingSteps(bits({Feature::Passcode}));
    stepFor(steps, cmd::kSetAdminKeyboardPassword).replies = {
        failure(kLockKey, cmd::kSetAdminKeyboardPassword, 0x04)};
    load(rig.lock, std::move(steps));
    ttlock::LockKeys keys;
    Persisted persisted;
    assertStatus(Status::PairIncomplete, pair(rig, keys, persisted));
    TEST_ASSERT_EQUAL_HEX8(0x04, rig.session.lockErrorCode());
    TEST_ASSERT_FALSE(persisted.result.adminPasscodeConfirmed);
    TEST_ASSERT_EQUAL_UINT(3, persisted.calls.size());
    TEST_ASSERT_EQUAL_UINT(ttlock::kAdminPasscodeDigits, persisted.calls[1].adminPasscode.size());
    TEST_ASSERT_TRUE(persisted.calls[2].adminPasscode.empty());
    TEST_ASSERT_TRUE(keys.adminPasscode.empty());
    TEST_ASSERT_TRUE(rig.session.keys().adminPasscode.empty());
    TEST_ASSERT_EQUAL_HEX8(cmd::kSetAdminKeyboardPassword, rig.lock.commands().back());
}

static void test_a_silent_admin_passcode_keeps_the_tentative_code() {
    Rig rig;
    std::vector<PairStep> steps = pairingSteps(bits({Feature::Passcode}));
    stepFor(steps, cmd::kSetAdminKeyboardPassword).replies.clear();
    load(rig.lock, std::move(steps));
    ttlock::LockKeys keys;
    Persisted persisted;
    assertStatus(Status::Ok, pair(rig, keys, persisted));
    TEST_ASSERT_FALSE(persisted.result.adminPasscodeConfirmed);
    TEST_ASSERT_TRUE(persisted.result.timeCalibrated);
    TEST_ASSERT_EQUAL_UINT(ttlock::kAdminPasscodeDigits, keys.adminPasscode.size());
    TEST_ASSERT_EQUAL_STRING(persisted.calls[1].adminPasscode.c_str(), keys.adminPasscode.c_str());
    TEST_ASSERT_EQUAL_STRING(keys.adminPasscode.c_str(), persisted.calls.back().adminPasscode.c_str());
    assertCommands({0x45, 0x19, 0x56, 0x43, 0x01, 0x53, 0x31, 0x57}, rig.lock);
    TEST_ASSERT_TRUE(rig.lock.scriptDone());
}

static void assertMandatoryStepFailure(uint8_t command, size_t persists) {
    Rig rig;
    std::vector<PairStep> steps = pairingSteps(bits({Feature::Passcode}));
    stepFor(steps, command).replies = {failure(kLockKey, command, 0x04)};
    load(rig.lock, std::move(steps));
    ttlock::LockKeys keys;
    Persisted persisted;
    assertStatus(Status::PairIncomplete, pair(rig, keys, persisted));
    TEST_ASSERT_EQUAL_UINT(persists, persisted.calls.size());
    TEST_ASSERT_EQUAL_HEX8(command, rig.lock.commands().back());
}

static void test_refused_mandatory_steps_make_pairing_incomplete() {
    assertMandatoryStepFailure(cmd::kSearchDeviceFeature, 1);
    assertMandatoryStepFailure(cmd::kInitPasswords, 2);
    assertMandatoryStepFailure(cmd::kOperateFinished, 2);
}

static void test_a_silent_optional_read_makes_pairing_incomplete() {
    Rig rig;
    std::vector<PairStep> steps = pairingSteps(kAllOptionalReads);
    stepFor(steps, cmd::kAudioManage).replies.clear();
    load(rig.lock, std::move(steps));
    ttlock::LockKeys keys;
    Persisted persisted;
    assertStatus(Status::PairIncomplete, pair(rig, keys, persisted));
    TEST_ASSERT_EQUAL_HEX8(cmd::kAudioManage, rig.lock.commands().back());
}

static void expectUserTime(FakeLock& lock, uint32_t ps = kPs) {
    lock.expect(cmd::kCheckUserTime, kLockKey, {success(kLockKey, cmd::kCheckUserTime, be32(ps))});
}

static const Bytes kUnlockReplyData{0x5A, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
                                    0x2A, 0x19, 0x0B, 0x07, 0x0E, 0x00, 0x05};

static void test_unlock_checks_user_time_then_sends_the_sum_and_utc_time() {
    Rig rig;
    attach(rig);
    expectUserTime(rig.lock);
    rig.lock.expect(cmd::kUnlock, kLockKey, {success(kLockKey, cmd::kUnlock, kUnlockReplyData)});
    ttlock::OperationResult result;
    assertStatus(Status::Ok, rig.session.unlock(result));
    assertCommands({cmd::kCheckUserTime, cmd::kUnlock}, rig.lock);
    assertPayload(ttlock::buildCheckUserTime(0, 0), rig.lock.requests()[0]);
    assertPayload(concat({be32(kPs + kUnlockKey), be32(static_cast<uint32_t>(rig.clock.utc))}), rig.lock.requests()[1]);
    TEST_ASSERT_EQUAL_INT(90, result.battery);
    TEST_ASSERT_TRUE(result.hasRecord);
    TEST_ASSERT_EQUAL_UINT32(42, result.recordId);
    TEST_ASSERT_EQUAL_UINT8(5, result.time.second);
}

static void test_lock_uses_function_lock_0x58() {
    Rig rig;
    attach(rig);
    expectUserTime(rig.lock);
    rig.lock.expect(cmd::kLock, kLockKey, {success(kLockKey, cmd::kLock, Bytes{0x5A})});
    ttlock::OperationResult result;
    assertStatus(Status::Ok, rig.session.lock(result));
    assertCommands({0x55, 0x58}, rig.lock);
    TEST_ASSERT_EQUAL_INT(90, result.battery);
    TEST_ASSERT_FALSE(result.hasRecord);
}

static void test_unlock_sum_wraps_modulo_2_32() {
    Rig rig;
    attach(rig);
    expectUserTime(rig.lock, 0xFFFFFFFF);
    rig.lock.expect(cmd::kUnlock, kLockKey, {success(kLockKey, cmd::kUnlock)});
    ttlock::OperationResult result;
    assertStatus(Status::Ok, rig.session.unlock(result));
    assertPayload(concat({be32(kUnlockKey - 1), be32(static_cast<uint32_t>(rig.clock.utc))}), rig.lock.requests()[1]);
}

static void test_lock_error_replies_map_to_lock_error_with_the_code() {
    Rig rig;
    attach(rig);
    rig.lock.expect(cmd::kCheckUserTime, kLockKey, {failure(kLockKey, cmd::kCheckUserTime, 0x0D)});
    ttlock::OperationResult result;
    assertStatus(Status::LockError, rig.session.unlock(result));
    TEST_ASSERT_EQUAL_HEX8(0x0D, rig.session.lockErrorCode());
    assertCommands({cmd::kCheckUserTime}, rig.lock);
}

static void test_unlock_with_an_unsynced_clock_sends_nothing() {
    Rig rig;
    attach(rig);
    rig.clock.isSynced = false;
    ttlock::OperationResult result;
    assertStatus(Status::TimeUnsynced, rig.session.unlock(result));
    assertStatus(Status::TimeUnsynced, rig.session.lock(result));
    assertStatus(Status::TimeUnsynced, rig.session.syncTime());
    TEST_ASSERT_EQUAL_UINT(0, rig.lock.requests().size());
}

static void test_pushes_while_waiting_go_to_the_event_sink() {
    Rig rig;
    attach(rig);
    rig.lock.expect(cmd::kCheckUserTime, kLockKey, {statePush(1), success(kLockKey, cmd::kCheckUserTime, be32(kPs))});
    rig.lock.expect(cmd::kUnlock, kLockKey, {success(kLockKey, cmd::kUnlock, kUnlockReplyData), statePush(1)});
    ttlock::OperationResult result;
    assertStatus(Status::Ok, rig.session.unlock(result));
    TEST_ASSERT_EQUAL_UINT(1, rig.events.size());
    TEST_ASSERT_EQUAL_HEX8(cmd::kSearchStatus, rig.events[0].command);
    TEST_ASSERT_EQUAL_INT(90, rig.events[0].battery);
    TEST_ASSERT_EQUAL(ttlock::LockState::Unlocked, rig.events[0].state);
    assertStatus(Status::Ok, rig.session.receiveEvent(1000));
    TEST_ASSERT_EQUAL_UINT(2, rig.events.size());
    assertStatus(Status::Timeout, rig.session.receiveEvent(1000));
    TEST_ASSERT_EQUAL_UINT(2, rig.events.size());
}

static void test_a_log_push_during_a_status_query_is_not_the_reply() {
    Rig rig;
    attach(rig);
    rig.lock.expect(cmd::kSearchStatus, kLockKey,
                    {logPush(), success(kLockKey, cmd::kSearchStatus, Bytes{0x2C, 0x01})});
    ttlock::LockStatus status;
    assertStatus(Status::Ok, rig.session.status(status));
    TEST_ASSERT_EQUAL(ttlock::LockState::Unlocked, status.state);
    TEST_ASSERT_EQUAL_INT(0x2C, status.battery);
    assertPayload(text("SCIENER"), rig.lock.requests()[0]);
    TEST_ASSERT_EQUAL_UINT(1, rig.events.size());
    TEST_ASSERT_TRUE(rig.events[0].hasRecord);
    TEST_ASSERT_EQUAL_UINT32(42, rig.events[0].recordId);
}

static void test_too_many_unsolicited_frames_time_out() {
    Rig rig;
    attach(rig);
    std::vector<Bytes> pushes;
    for (size_t i = 0; i < ttlock::kMaxFramesPerReply; ++i) {
        pushes.push_back(statePush(0));
    }
    pushes.push_back(success(kLockKey, cmd::kCheckUserTime, be32(kPs)));
    rig.lock.expect(cmd::kCheckUserTime, kLockKey, std::move(pushes));
    ttlock::OperationResult result;
    assertStatus(Status::Timeout, rig.session.unlock(result));
    TEST_ASSERT_EQUAL_UINT(ttlock::kMaxFramesPerReply, rig.events.size());
    assertCommands({cmd::kCheckUserTime}, rig.lock);
}

static void test_a_reply_with_a_bad_crc_fails_without_resending() {
    Rig rig;
    attach(rig);
    rig.lock.expect(cmd::kCheckUserTime, kLockKey,
                    {fake::withBadCrc(success(kLockKey, cmd::kCheckUserTime, be32(kPs)))});
    ttlock::OperationResult result;
    assertStatus(Status::BadCrc, rig.session.unlock(result));
    assertCommands({cmd::kCheckUserTime}, rig.lock);
}

static void test_a_push_with_a_bad_crc_is_dropped() {
    Rig rig;
    attach(rig);
    rig.lock.expect(cmd::kCheckUserTime, kLockKey,
                    {fake::withBadCrc(statePush(1)), success(kLockKey, cmd::kCheckUserTime, be32(kPs))});
    rig.lock.expect(cmd::kLock, kLockKey, {success(kLockKey, cmd::kLock, Bytes{0x5A})});
    ttlock::OperationResult result;
    assertStatus(Status::Ok, rig.session.lock(result));
    TEST_ASSERT_EQUAL_UINT(0, rig.events.size());
    TEST_ASSERT_EQUAL_UINT(1, rig.session.droppedFrames());
}

static const Bytes kWrongKeyStatus = success(kOtherKey, cmd::kSearchStatus, Bytes{0x2C, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00});

static void test_undecodable_frames_are_dropped_and_the_wait_continues() {
    Rig rig;
    attach(rig);
    TEST_ASSERT_TRUE(undecodable(kWrongKeyStatus, kLockKey));
    rig.lock.expect(cmd::kSearchStatus, kLockKey,
                    {Bytes{0x7F, 0x5A, 0x05}, Bytes{0x01, 0x02, 0x03}, kWrongKeyStatus, lockFrame(kLockKey, Bytes{}),
                     lockFrame(kLockKey, Bytes{cmd::kUnlock}), success(kLockKey, cmd::kSearchStatus, Bytes{0x2C, 0x00})});
    ttlock::LockStatus status;
    assertStatus(Status::Ok, rig.session.status(status));
    TEST_ASSERT_EQUAL(ttlock::LockState::Locked, status.state);
    TEST_ASSERT_EQUAL_UINT(5, rig.session.droppedFrames());
    TEST_ASSERT_EQUAL_UINT(0, rig.events.size());
}

static void test_a_stray_frame_under_another_key_mid_pairing_is_dropped() {
    Rig rig;
    std::vector<PairStep> steps = pairingSteps(bits({Feature::Passcode}));
    const Bytes stray = success(kDefault, cmd::kSearchStatus, Bytes{0x5A, 0x01, 0x00});
    TEST_ASSERT_TRUE(undecodable(stray, kLockKey));
    PairStep& addAdmin = stepFor(steps, cmd::kAddAdmin);
    addAdmin.replies.insert(addAdmin.replies.begin(), stray);
    load(rig.lock, std::move(steps));
    ttlock::LockKeys keys;
    Persisted persisted;
    assertStatus(Status::Ok, pair(rig, keys, persisted));
    TEST_ASSERT_EQUAL_UINT(1, rig.session.droppedFrames());
    TEST_ASSERT_TRUE(rig.lock.scriptDone());
}

static void test_a_matching_reply_that_does_not_parse_is_bad_response() {
    Rig rig;
    attach(rig);
    rig.lock.expect(cmd::kSearchStatus, kLockKey, {success(kLockKey, cmd::kSearchStatus, Bytes{0x2C})});
    ttlock::LockStatus status;
    assertStatus(Status::BadResponse, rig.session.status(status));
    Rig echoOnly;
    attach(echoOnly);
    echoOnly.lock.expect(cmd::kSearchStatus, kLockKey, {lockFrame(kLockKey, Bytes{cmd::kSearchStatus})});
    assertStatus(Status::BadResponse, echoOnly.session.status(status));
}

static void test_a_wait_that_only_sees_undecodable_frames_times_out() {
    Rig rig;
    attach(rig);
    rig.lock.expect(cmd::kSearchStatus, kLockKey, {Bytes{0x7F, 0x5A, 0x05}, kWrongKeyStatus});
    ttlock::LockStatus status;
    assertStatus(Status::Timeout, rig.session.status(status));
    TEST_ASSERT_EQUAL_UINT(2, rig.session.droppedFrames());
}

static void test_receive_event_skips_frames_it_cannot_use() {
    Rig rig;
    attach(rig);
    rig.lock.push(Bytes{0x7F, 0x5A, 0x05});
    rig.lock.push(fake::withBadCrc(statePush(0)));
    rig.lock.push(statePush(1));
    assertStatus(Status::Ok, rig.session.receiveEvent(1000));
    TEST_ASSERT_EQUAL_UINT(1, rig.events.size());
    TEST_ASSERT_EQUAL(ttlock::LockState::Unlocked, rig.events[0].state);
    TEST_ASSERT_EQUAL_UINT(2, rig.session.droppedFrames());
    rig.lock.push(kWrongKeyStatus);
    assertStatus(Status::Timeout, rig.session.receiveEvent(1000));
    TEST_ASSERT_EQUAL_UINT(3, rig.session.droppedFrames());
}

static void test_a_long_status_frame_is_taken_as_a_log_push() {
    Rig rig;
    attach(rig);
    Bytes longReply{0x2C, 0x01};
    longReply.resize(15, 0x00);
    rig.lock.expect(cmd::kSearchStatus, kLockKey, {success(kLockKey, cmd::kSearchStatus, longReply)});
    ttlock::LockStatus status;
    assertStatus(Status::Timeout, rig.session.status(status));
    TEST_ASSERT_EQUAL_UINT(1, rig.events.size());
    TEST_ASSERT_TRUE(rig.events[0].hasRecord);
}

static void test_methods_before_attach_return_not_paired_without_traffic() {
    Rig rig;
    ttlock::OperationResult result;
    ttlock::LockStatus status;
    ttlock::AutoLockSetting autolock;
    std::vector<ttlock::Passcode> passcodes;
    std::vector<ttlock::LogEntry> logs;
    assertStatus(Status::NotPaired, rig.session.unlock(result));
    assertStatus(Status::NotPaired, rig.session.status(status));
    assertStatus(Status::NotPaired, rig.session.autolockGet(autolock));
    assertStatus(Status::NotPaired, rig.session.passcodeList(passcodes));
    assertStatus(Status::NotPaired, rig.session.fetchLog(ttlock::kLogSinceLastRead, logs));
    assertStatus(Status::NotPaired, rig.session.factoryReset());
    assertStatus(Status::NotPaired, rig.session.receiveEvent(10));
    TEST_ASSERT_EQUAL_UINT(0, rig.lock.requests().size());
}

static void test_attach_rejects_a_legacy_frame_layout() {
    Rig rig;
    ttlock::LockKeys keys = pairedKeys();
    keys.version = ttlock::LockVersion{3, 0, 0, 0, 0};
    assertStatus(Status::Unsupported, rig.session.attach(keys));
    ttlock::LockStatus status;
    assertStatus(Status::NotPaired, rig.session.status(status));
}

static void test_feature_gated_methods_return_unsupported_without_traffic() {
    Rig rig;
    attach(rig, 0);
    ttlock::AutoLockSetting autolock;
    std::vector<ttlock::PassageMode> passages;
    std::vector<ttlock::Passcode> passcodes;
    std::vector<ttlock::Credential> credentials;
    ttlock::SoundSetting sound;
    bool enabled = false;
    uint64_t id = 0;
    const ttlock::Passcode code{ttlock::PasscodeType::Permanent, "13579", {}};
    const auto none = [](const ttlock::EnrollProgress&) {};
    assertStatus(Status::Unsupported, rig.session.autolockGet(autolock));
    assertStatus(Status::Unsupported, rig.session.autolockSet(30));
    assertStatus(Status::Unsupported, rig.session.passageList(passages));
    assertStatus(Status::Unsupported, rig.session.passageAdd(ttlock::PassageMode{}));
    assertStatus(Status::Unsupported, rig.session.passageDelete(ttlock::PassageMode{}));
    assertStatus(Status::Unsupported, rig.session.passageClear());
    assertStatus(Status::Unsupported, rig.session.passcodeList(passcodes));
    assertStatus(Status::Unsupported, rig.session.passcodeAdd(code));
    assertStatus(Status::Unsupported, rig.session.passcodeUpdate("24680", code));
    assertStatus(Status::Unsupported, rig.session.passcodeDelete(ttlock::PasscodeType::Permanent, "13579"));
    assertStatus(Status::Unsupported, rig.session.passcodeClear());
    assertStatus(Status::Unsupported, rig.session.setAdminPasscode("1234567"));
    assertStatus(Status::Unsupported, rig.session.fingerprintList(credentials));
    assertStatus(Status::Unsupported, rig.session.fingerprintEnroll({}, none, id));
    assertStatus(Status::Unsupported, rig.session.fingerprintDelete(1));
    assertStatus(Status::Unsupported, rig.session.fingerprintClear());
    assertStatus(Status::Unsupported, rig.session.fingerprintSetValidity(1, {}));
    assertStatus(Status::Unsupported, rig.session.cardList(credentials));
    assertStatus(Status::Unsupported, rig.session.cardEnroll({}, none, id));
    assertStatus(Status::Unsupported, rig.session.cardDelete(1));
    assertStatus(Status::Unsupported, rig.session.cardClear());
    assertStatus(Status::Unsupported, rig.session.cardSetValidity(1, {}));
    assertStatus(Status::Unsupported, rig.session.soundGet(sound));
    assertStatus(Status::Unsupported, rig.session.soundSet(true));
    assertStatus(Status::Unsupported, rig.session.soundVolumeSet(3));
    assertStatus(Status::Unsupported, rig.session.resetButtonGet(enabled));
    assertStatus(Status::Unsupported, rig.session.resetButtonSet(false));
    assertStatus(Status::Unsupported, rig.session.remoteUnlockGet(enabled));
    assertStatus(Status::Unsupported, rig.session.remoteUnlockSet(true));
    TEST_ASSERT_EQUAL_UINT(0, rig.lock.requests().size());
}

static void test_admin_methods_log_in_with_check_admin_and_check_random() {
    Rig rig;
    attach(rig);
    expectAdminLogin(rig.lock);
    rig.lock.expect(cmd::kAutoLockManage, kLockKey,
                    {success(kLockKey, cmd::kAutoLockManage, Bytes{0x5A, 0x01, 0x00, 0x1E, 0x00, 0x05, 0x03, 0x84})});
    ttlock::AutoLockSetting setting;
    assertStatus(Status::Ok, rig.session.autolockGet(setting));
    assertCommands({cmd::kCheckAdmin, cmd::kCheckRandom, cmd::kAutoLockManage}, rig.lock);
    assertPayload(ttlock::buildCheckAdmin(kAdminPs, 0, 0), rig.lock.requests()[0]);
    assertPayload(be32(0x01020304 + kUnlockKey), rig.lock.requests()[1]);
    assertPayload(Bytes{0x01}, rig.lock.requests()[2]);
    TEST_ASSERT_EQUAL_UINT16(30, setting.seconds);
    TEST_ASSERT_EQUAL_UINT16(5, setting.minSeconds);
    TEST_ASSERT_EQUAL_UINT16(900, setting.maxSeconds);
}

static void test_a_failed_admin_login_stops_the_command() {
    Rig rig;
    attach(rig);
    rig.lock.expect(cmd::kCheckAdmin, kLockKey, {failure(kLockKey, cmd::kCheckAdmin, 0x03)});
    assertStatus(Status::LockError, rig.session.autolockSet(30));
    TEST_ASSERT_EQUAL_HEX8(0x03, rig.session.lockErrorCode());
    assertCommands({cmd::kCheckAdmin}, rig.lock);
}

static void test_commands_wait_five_seconds_for_each_reply() {
    Rig rig;
    attach(rig);
    expectAdminLogin(rig.lock);
    rig.lock.expect(cmd::kAutoLockManage, kLockKey, {success(kLockKey, cmd::kAutoLockManage, Bytes{0x5A, 0x02})});
    assertStatus(Status::Ok, rig.session.autolockSet(300));
    assertPayload(Bytes{0x02, 0x01, 0x2C}, rig.lock.requests()[2]);
    for (uint32_t timeout : rig.lock.receiveTimeouts()) {
        TEST_ASSERT_EQUAL_UINT32(ttlock::kCommandTimeoutMs, timeout);
    }
}

static Bytes passcodePage(uint16_t next, const std::string& code) {
    const Bytes item = concat({Bytes{0x01, static_cast<uint8_t>(code.size())}, text(code),
                               Bytes{static_cast<uint8_t>(code.size())}, text(code), Bytes{0x00, 0x01, 0x01, 0x00, 0x00}});
    const Bytes body = concat({Bytes{static_cast<uint8_t>(next >> 8), static_cast<uint8_t>(next),
                                     static_cast<uint8_t>(item.size())},
                               item});
    return concat({Bytes{0x00, static_cast<uint8_t>(body.size())}, body});
}

static void test_passcode_list_follows_the_cursor_until_zero() {
    Rig rig;
    attach(rig);
    expectAdminLogin(rig.lock);
    rig.lock.expect(cmd::kPasscodeList, kLockKey, {success(kLockKey, cmd::kPasscodeList, passcodePage(5, "13579"))});
    rig.lock.expect(cmd::kPasscodeList, kLockKey, {success(kLockKey, cmd::kPasscodeList, passcodePage(0, "24680"))});
    std::vector<ttlock::Passcode> passcodes;
    assertStatus(Status::Ok, rig.session.passcodeList(passcodes));
    TEST_ASSERT_EQUAL_UINT(2, passcodes.size());
    TEST_ASSERT_EQUAL_STRING("13579", passcodes[0].code.c_str());
    TEST_ASSERT_EQUAL_STRING("24680", passcodes[1].code.c_str());
    assertPayload(Bytes{0x00, 0x00}, rig.lock.requests()[2]);
    assertPayload(Bytes{0x00, 0x05}, rig.lock.requests()[3]);
}

static void test_passcode_list_stops_at_the_end_of_list_marker() {
    Rig rig;
    attach(rig);
    expectAdminLogin(rig.lock);
    rig.lock.expect(cmd::kPasscodeList, kLockKey, {success(kLockKey, cmd::kPasscodeList, passcodePage(3, "13579"))});
    rig.lock.expect(cmd::kPasscodeList, kLockKey, {success(kLockKey, cmd::kPasscodeList, Bytes{0x00, 0x00})});
    std::vector<ttlock::Passcode> passcodes;
    assertStatus(Status::Ok, rig.session.passcodeList(passcodes));
    TEST_ASSERT_EQUAL_UINT(1, passcodes.size());
    TEST_ASSERT_TRUE(rig.lock.scriptDone());
}

static void test_a_list_cursor_that_does_not_advance_is_bad_response() {
    Rig rig;
    attach(rig);
    expectAdminLogin(rig.lock);
    rig.lock.expect(cmd::kPasscodeList, kLockKey, {success(kLockKey, cmd::kPasscodeList, passcodePage(7, "13579"))});
    rig.lock.expect(cmd::kPasscodeList, kLockKey, {success(kLockKey, cmd::kPasscodeList, passcodePage(7, "13579"))});
    std::vector<ttlock::Passcode> passcodes;
    assertStatus(Status::BadResponse, rig.session.passcodeList(passcodes));
    TEST_ASSERT_TRUE(rig.lock.scriptDone());
}

static void test_card_and_fingerprint_lists_page_until_ffff() {
    Rig rig;
    attach(rig);
    expectAdminLogin(rig.lock);
    rig.lock.expect(cmd::kManageIcCard, kLockKey,
                    {success(kLockKey, cmd::kManageIcCard,
                             Bytes{0x55, 0x01, 0x00, 0x01, 0x12, 0x34, 0x56, 0x78, 0x00, 0x01, 0x01, 0x00, 0x00, 0x63,
                                   0x01, 0x01, 0x00, 0x00})});
    rig.lock.expect(cmd::kManageIcCard, kLockKey,
                    {success(kLockKey, cmd::kManageIcCard, Bytes{0x55, 0x01, 0xFF, 0xFF})});
    std::vector<ttlock::Credential> cards;
    assertStatus(Status::Ok, rig.session.cardList(cards));
    TEST_ASSERT_EQUAL_UINT(1, cards.size());
    TEST_ASSERT_EQUAL_UINT64(0x12345678, cards[0].id);
    TEST_ASSERT_TRUE(cards[0].validity == ttlock::Validity{});
    assertPayload(Bytes{0x01, 0x00, 0x00}, rig.lock.requests()[2]);
    assertPayload(Bytes{0x01, 0x00, 0x01}, rig.lock.requests()[3]);

    Rig other;
    attach(other);
    expectAdminLogin(other.lock);
    other.lock.expect(cmd::kManageFingerprint, kLockKey,
                      {success(kLockKey, cmd::kManageFingerprint, Bytes{0x64, 0x06, 0xFF, 0xFF})});
    std::vector<ttlock::Credential> fingerprints;
    assertStatus(Status::Ok, other.session.fingerprintList(fingerprints));
    TEST_ASSERT_TRUE(fingerprints.empty());
    assertPayload(Bytes{0x06, 0x00, 0x00}, other.lock.requests()[2]);
}

static void test_passage_list_pages_until_ff() {
    Rig rig;
    attach(rig);
    expectAdminLogin(rig.lock);
    rig.lock.expect(cmd::kConfigurePassageMode, kLockKey,
                    {success(kLockKey, cmd::kConfigurePassageMode, Bytes{0x5A, 0x01, 0x01, 0x01, 0x05, 0x00, 0x08,
                                                                         0x00, 0x11, 0x1E})});
    rig.lock.expect(cmd::kConfigurePassageMode, kLockKey,
                    {success(kLockKey, cmd::kConfigurePassageMode, Bytes{0x5A, 0x01, 0xFF, 0x02, 0x0F, 0x00, 0x00,
                                                                         0x00, 0x00, 0x00})});
    std::vector<ttlock::PassageMode> modes;
    assertStatus(Status::Ok, rig.session.passageList(modes));
    TEST_ASSERT_EQUAL_UINT(2, modes.size());
    TEST_ASSERT_EQUAL_UINT8(17, modes[0].endHour);
    TEST_ASSERT_EQUAL(ttlock::PassageType::Monthly, modes[1].type);
    assertPayload(Bytes{0x01, 0x00}, rig.lock.requests()[2]);
    assertPayload(Bytes{0x01, 0x01}, rig.lock.requests()[3]);
}

static const ttlock::Validity kTimed{ttlock::LockTime{2025, 11, 7, 9, 0, 0}, ttlock::LockTime{2026, 12, 31, 23, 59, 0}};

static void test_fingerprint_enroll_reports_each_scan_then_sets_validity() {
    Rig rig;
    attach(rig);
    expectAdminLogin(rig.lock);
    const Bytes fingerprintId{0x01, 0x1F, 0x71, 0xFB, 0x04, 0xCB};
    rig.lock.expect(cmd::kManageFingerprint, kLockKey,
                    {success(kLockKey, cmd::kManageFingerprint, Bytes{0x64, 0x02, 0x02}),
                     success(kLockKey, cmd::kManageFingerprint, Bytes{0x64, 0x02, 0x03}),
                     statePush(0),
                     success(kLockKey, cmd::kManageFingerprint, Bytes{0x64, 0x02, 0x03}),
                     success(kLockKey, cmd::kManageFingerprint, Bytes{0x64, 0x02, 0x03}),
                     success(kLockKey, cmd::kManageFingerprint, concat({Bytes{0x64, 0x02, 0x01}, fingerprintId}))});
    rig.lock.expect(cmd::kManageFingerprint, kLockKey, {success(kLockKey, cmd::kManageFingerprint, Bytes{0x64, 0x05})});
    std::vector<ttlock::EnrollProgress> progress;
    uint64_t id = 0;
    assertStatus(Status::Ok, rig.session.fingerprintEnroll(
                                 kTimed, [&progress](const ttlock::EnrollProgress& step) { progress.push_back(step); },
                                 id));
    TEST_ASSERT_EQUAL_UINT64(1234567890123ULL, id);
    TEST_ASSERT_EQUAL_UINT(4, progress.size());
    TEST_ASSERT_EQUAL(ttlock::EnrollStage::Waiting, progress[0].stage);
    TEST_ASSERT_EQUAL(ttlock::EnrollStage::Scanned, progress[3].stage);
    TEST_ASSERT_EQUAL_UINT8(3, progress[3].scans);
    TEST_ASSERT_EQUAL_UINT(1, rig.events.size());
    assertPayload(Bytes{0x02}, rig.lock.requests()[2]);
    assertPayload(ttlock::buildFingerprintSetValidity(id, kTimed), rig.lock.requests()[3]);
    const auto& timeouts = rig.lock.receiveTimeouts();
    TEST_ASSERT_EQUAL_UINT32(ttlock::kCommandTimeoutMs, timeouts[2]);
    TEST_ASSERT_EQUAL_UINT32(ttlock::kEnrollStepTimeoutMs, timeouts[3]);
    TEST_ASSERT_EQUAL_UINT32(ttlock::kCommandTimeoutMs, timeouts.back());
}

static void test_card_enroll_waits_for_the_card_then_sets_validity() {
    Rig rig;
    attach(rig);
    expectAdminLogin(rig.lock);
    rig.lock.expect(cmd::kManageIcCard, kLockKey,
                    {success(kLockKey, cmd::kManageIcCard, Bytes{0x55, 0x02, 0x02}),
                     success(kLockKey, cmd::kManageIcCard, Bytes{0x55, 0x02, 0x01, 0x12, 0x34, 0x56, 0x78})});
    rig.lock.expect(cmd::kManageIcCard, kLockKey, {success(kLockKey, cmd::kManageIcCard, Bytes{0x55, 0x05})});
    size_t calls = 0;
    uint64_t number = 0;
    assertStatus(Status::Ok,
                 rig.session.cardEnroll(kTimed, [&calls](const ttlock::EnrollProgress&) { ++calls; }, number));
    TEST_ASSERT_EQUAL_UINT64(305419896ULL, number);
    TEST_ASSERT_EQUAL_UINT(1, calls);
    assertPayload(ttlock::buildCardSetValidity(number, kTimed), rig.lock.requests()[3]);
}

static void test_enroll_without_a_scan_times_out_and_a_refusal_is_a_lock_error() {
    Rig rig;
    attach(rig);
    expectAdminLogin(rig.lock);
    rig.lock.expect(cmd::kManageIcCard, kLockKey, {success(kLockKey, cmd::kManageIcCard, Bytes{0x55, 0x02, 0x02})});
    uint64_t number = 0;
    assertStatus(Status::Timeout, rig.session.cardEnroll({}, nullptr, number));
    TEST_ASSERT_EQUAL_UINT32(ttlock::kEnrollStepTimeoutMs, rig.lock.receiveTimeouts().back());

    Rig refused;
    attach(refused);
    expectAdminLogin(refused.lock);
    refused.lock.expect(cmd::kManageFingerprint, kLockKey,
                        {success(kLockKey, cmd::kManageFingerprint, Bytes{0x64, 0x02, 0x02}),
                         failure(kLockKey, cmd::kManageFingerprint, 0x1A)});
    uint64_t id = 0;
    assertStatus(Status::LockError, refused.session.fingerprintEnroll({}, nullptr, id));
    TEST_ASSERT_EQUAL_HEX8(0x1A, refused.session.lockErrorCode());
}

static Bytes logPage(uint16_t sequence, uint8_t recordType) {
    const Bytes record{recordType, 25, 11, 7, 14, 23, 7, 90};
    const Bytes body = concat({Bytes{static_cast<uint8_t>(sequence >> 8), static_cast<uint8_t>(sequence),
                                     static_cast<uint8_t>(record.size())},
                               record});
    return concat({Bytes{0x00, static_cast<uint8_t>(body.size())}, body});
}

static void test_fetch_log_follows_the_cursor_until_an_empty_page() {
    Rig rig;
    attach(rig);
    rig.lock.expect(cmd::kGetOperateLog, kLockKey, {success(kLockKey, cmd::kGetOperateLog, logPage(3, 27))});
    rig.lock.expect(cmd::kGetOperateLog, kLockKey, {success(kLockKey, cmd::kGetOperateLog, logPage(4, 36))});
    rig.lock.expect(cmd::kGetOperateLog, kLockKey, {success(kLockKey, cmd::kGetOperateLog, Bytes{0x00, 0x00})});
    std::vector<ttlock::LogEntry> entries;
    assertStatus(Status::Ok, rig.session.fetchLog(ttlock::kLogSinceLastRead, entries));
    TEST_ASSERT_EQUAL_UINT(2, entries.size());
    TEST_ASSERT_EQUAL_UINT16(2, entries[0].recordNumber);
    TEST_ASSERT_EQUAL_UINT8(36, entries[1].type);
    assertCommands({cmd::kGetOperateLog, cmd::kGetOperateLog, cmd::kGetOperateLog}, rig.lock);
    assertPayload(Bytes{0xFF, 0xFF}, rig.lock.requests()[0]);
    assertPayload(Bytes{0x00, 0x03}, rig.lock.requests()[1]);
    assertPayload(Bytes{0x00, 0x04}, rig.lock.requests()[2]);
}

static void test_fetch_log_stops_when_the_cursor_repeats_or_reaches_zero() {
    Rig rig;
    attach(rig);
    rig.lock.expect(cmd::kGetOperateLog, kLockKey, {success(kLockKey, cmd::kGetOperateLog, logPage(5, 27))});
    rig.lock.expect(cmd::kGetOperateLog, kLockKey, {success(kLockKey, cmd::kGetOperateLog, logPage(5, 27))});
    std::vector<ttlock::LogEntry> entries;
    assertStatus(Status::Ok, rig.session.fetchLog(ttlock::kLogSinceLastRead, entries));
    TEST_ASSERT_EQUAL_UINT(1, entries.size());
    TEST_ASSERT_TRUE(rig.lock.scriptDone());

    Rig zero;
    attach(zero);
    zero.lock.expect(cmd::kGetOperateLog, kLockKey, {success(kLockKey, cmd::kGetOperateLog, logPage(0, 27))});
    std::vector<ttlock::LogEntry> single;
    assertStatus(Status::Ok, zero.session.fetchLog(7, single));
    TEST_ASSERT_EQUAL_UINT(1, single.size());
    assertPayload(Bytes{0x00, 0x07}, zero.lock.requests()[0]);
    TEST_ASSERT_TRUE(zero.lock.scriptDone());
}

static void test_factory_reset_logs_in_accepts_an_empty_reply_and_detaches() {
    Rig rig;
    attach(rig);
    expectAdminLogin(rig.lock);
    rig.lock.expect(cmd::kResetLock, kLockKey, {lockFrame(kLockKey, Bytes{})});
    assertStatus(Status::Ok, rig.session.factoryReset());
    assertCommands({cmd::kCheckAdmin, cmd::kCheckRandom, cmd::kResetLock}, rig.lock);
    assertPayload(Bytes{}, rig.lock.requests()[2]);
    ttlock::LockStatus status;
    assertStatus(Status::NotPaired, rig.session.status(status));
}

static void test_factory_reset_maps_a_refusal_to_lock_error_and_stays_attached() {
    Rig rig;
    attach(rig);
    expectAdminLogin(rig.lock);
    rig.lock.expect(cmd::kResetLock, kLockKey, {failure(kLockKey, cmd::kResetLock, 0x02)});
    rig.lock.expect(cmd::kSearchStatus, kLockKey, {success(kLockKey, cmd::kSearchStatus, Bytes{0x2C, 0x00})});
    assertStatus(Status::LockError, rig.session.factoryReset());
    TEST_ASSERT_EQUAL_HEX8(0x02, rig.session.lockErrorCode());
    TEST_ASSERT_EQUAL_UINT32(kAdminPs, rig.session.keys().adminPs);
    ttlock::LockStatus status;
    assertStatus(Status::Ok, rig.session.status(status));

    Rig acknowledged;
    attach(acknowledged);
    expectAdminLogin(acknowledged.lock);
    acknowledged.lock.expect(cmd::kResetLock, kLockKey, {success(kLockKey, cmd::kResetLock)});
    assertStatus(Status::Ok, acknowledged.session.factoryReset());
    assertStatus(Status::NotPaired, acknowledged.session.status(status));
}

static void test_sync_time_logs_in_and_sends_local_wall_time() {
    Rig rig;
    attach(rig);
    expectAdminLogin(rig.lock);
    rig.lock.expect(cmd::kTimeCalibrate, kLockKey, {success(kLockKey, cmd::kTimeCalibrate)});
    rig.clock.utc = 1762524005;
    rig.clock.offset = 2 * 3600;
    assertStatus(Status::Ok, rig.session.syncTime());
    assertPayload(Bytes{25, 11, 7, 16, 0, 5}, rig.lock.requests()[2]);
}

static Bytes infoString(const char* value) {
    Bytes data = text(value);
    data.push_back(0x00);
    return data;
}

static void test_device_info_reads_the_four_strings() {
    Rig rig;
    attach(rig);
    expectAdminLogin(rig.lock);
    for (const char* value : {"LK100", "1.3", "6.4.43", "20250101"}) {
        rig.lock.expect(cmd::kReadDeviceInfo, kLockKey, {success(kLockKey, cmd::kReadDeviceInfo, infoString(value))});
    }
    ttlock::DeviceInfo info;
    assertStatus(Status::Ok, rig.session.deviceInfo(info));
    TEST_ASSERT_EQUAL_STRING("LK100", info.model.c_str());
    TEST_ASSERT_EQUAL_STRING("1.3", info.hardware.c_str());
    TEST_ASSERT_EQUAL_STRING("6.4.43", info.firmware.c_str());
    TEST_ASSERT_EQUAL_STRING("20250101", info.manufactureDate.c_str());
    TEST_ASSERT_TRUE(info.name.empty());
    for (size_t i = 0; i < 4; ++i) {
        assertPayload(Bytes{static_cast<uint8_t>(i + 1)}, rig.lock.requests()[2 + i]);
    }
}

static void test_features_refreshes_the_mask() {
    Rig rig;
    attach(rig, bits({Feature::Passcode}));
    expectAdminLogin(rig.lock);
    const uint64_t mask = bits({Feature::Passcode, Feature::Ic, Feature::DeadLock});
    rig.lock.expect(cmd::kSearchDeviceFeature, kLockKey,
                    {success(kLockKey, cmd::kSearchDeviceFeature, featureData(mask))});
    uint64_t features = 0;
    assertStatus(Status::Ok, rig.session.features(features));
    TEST_ASSERT_EQUAL_HEX64(mask, features);
    TEST_ASSERT_EQUAL_HEX64(mask, rig.session.keys().features);
}

static void test_sound_reset_button_and_remote_unlock_settings() {
    Rig rig;
    attach(rig);
    expectAdminLogin(rig.lock);
    rig.lock.expect(cmd::kAudioManage, kLockKey, {success(kLockKey, cmd::kAudioManage, Bytes{0x5A, 0x01, 0x01, 0x04})});
    expectAdminLogin(rig.lock);
    rig.lock.expect(cmd::kAudioManage, kLockKey, {success(kLockKey, cmd::kAudioManage, Bytes{0x5A, 0x02})});
    expectAdminLogin(rig.lock);
    rig.lock.expect(cmd::kAudioManage, kLockKey, {success(kLockKey, cmd::kAudioManage, Bytes{0x5A, 0x02})});
    expectAdminLogin(rig.lock);
    rig.lock.expect(cmd::kSwitch, kLockKey, {success(kLockKey, cmd::kSwitch, Bytes{0x5A, 0x01, 0x00, 0x00, 0x00, 0x06})});
    expectAdminLogin(rig.lock);
    rig.lock.expect(cmd::kSwitch, kLockKey, {success(kLockKey, cmd::kSwitch, Bytes{0x5A, 0x02})});
    expectAdminLogin(rig.lock);
    rig.lock.expect(cmd::kControlRemoteUnlock, kLockKey,
                    {success(kLockKey, cmd::kControlRemoteUnlock, Bytes{0x5A, 0x01, 0x00})});
    expectAdminLogin(rig.lock);
    rig.lock.expect(cmd::kControlRemoteUnlock, kLockKey,
                    {success(kLockKey, cmd::kControlRemoteUnlock, Bytes{0x5A, 0x02})});
    ttlock::SoundSetting sound;
    assertStatus(Status::Ok, rig.session.soundGet(sound));
    TEST_ASSERT_TRUE(sound.enabled);
    TEST_ASSERT_EQUAL_UINT8(4, sound.volume);
    assertStatus(Status::Ok, rig.session.soundSet(false));
    assertStatus(Status::Ok, rig.session.soundVolumeSet(2));
    bool resetButton = false;
    assertStatus(Status::Ok, rig.session.resetButtonGet(resetButton));
    TEST_ASSERT_TRUE(resetButton);
    assertStatus(Status::Ok, rig.session.resetButtonSet(false));
    bool remote = true;
    assertStatus(Status::Ok, rig.session.remoteUnlockGet(remote));
    TEST_ASSERT_FALSE(remote);
    assertStatus(Status::Ok, rig.session.remoteUnlockSet(true));
    const auto& requests = rig.lock.requests();
    assertPayload(Bytes{0x01}, requests[2]);
    assertPayload(Bytes{0x02, 0x00}, requests[5]);
    assertPayload(Bytes{0x02, 0x01, 0x02, 0x00}, requests[8]);
    assertPayload(Bytes{0x01}, requests[11]);
    assertPayload(Bytes{0x02, 0x00, 0x00, 0x00, 0x02, 0x00, 0x00, 0x00, 0x00}, requests[14]);
    assertPayload(Bytes{0x01}, requests[17]);
    assertPayload(Bytes{0x02, 0x01}, requests[20]);
    TEST_ASSERT_TRUE(rig.lock.scriptDone());
}

static void test_volume_outside_one_to_five_is_rejected_without_traffic() {
    Rig rig;
    attach(rig);
    assertStatus(Status::InvalidArgument, rig.session.soundVolumeSet(0));
    assertStatus(Status::InvalidArgument, rig.session.soundVolumeSet(6));
    TEST_ASSERT_EQUAL_UINT(0, rig.lock.requests().size());
}

static void test_passcode_writes_validate_input_before_sending() {
    Rig rig;
    attach(rig);
    const ttlock::Validity permanent{};
    assertStatus(Status::InvalidArgument,
                 rig.session.passcodeAdd(ttlock::Passcode{ttlock::PasscodeType::Permanent, "12a4", permanent}));
    assertStatus(Status::InvalidArgument,
                 rig.session.passcodeAdd(ttlock::Passcode{ttlock::PasscodeType::Permanent, "123", permanent}));
    assertStatus(Status::InvalidArgument,
                 rig.session.passcodeAdd(ttlock::Passcode{ttlock::PasscodeType::Permanent, "1234567890", permanent}));
    assertStatus(Status::InvalidArgument,
                 rig.session.passcodeAdd(ttlock::Passcode{static_cast<ttlock::PasscodeType>(9), "1234", permanent}));
    assertStatus(Status::Unsupported,
                 rig.session.passcodeAdd(ttlock::Passcode{ttlock::PasscodeType::Cyclic, "1234", permanent}));
    assertStatus(Status::InvalidArgument,
                 rig.session.passcodeUpdate("12", ttlock::Passcode{ttlock::PasscodeType::Permanent, "1234", permanent}));
    assertStatus(Status::InvalidArgument, rig.session.passcodeDelete(ttlock::PasscodeType::Permanent, "12345678901"));
    assertStatus(Status::InvalidArgument, rig.session.setAdminPasscode("12"));
    assertStatus(Status::InvalidArgument, rig.session.setAdminPasscode("12345x7"));
    TEST_ASSERT_EQUAL_UINT(0, rig.lock.requests().size());
}

static void test_dates_and_passage_fields_are_validated_before_sending() {
    Rig rig;
    attach(rig);
    const auto none = [](const ttlock::EnrollProgress&) {};
    const ttlock::LockTime start{2025, 11, 7, 9, 0, 0};
    const auto window = [&start](ttlock::LockTime end) { return ttlock::Validity{start, end}; };
    uint64_t id = 0;
    assertStatus(Status::InvalidArgument,
                 rig.session.passcodeAdd(ttlock::Passcode{ttlock::PasscodeType::Period, "1234",
                                                          ttlock::Validity{{1999, 12, 31, 0, 0, 0}, start}}));
    assertStatus(Status::InvalidArgument,
                 rig.session.passcodeAdd(ttlock::Passcode{ttlock::PasscodeType::Period, "1234",
                                                          window({2025, 11, 7, 8, 59, 0})}));
    assertStatus(Status::InvalidArgument,
                 rig.session.passcodeUpdate("1234", ttlock::Passcode{ttlock::PasscodeType::Count, "5678",
                                                                     window({2025, 13, 1, 0, 0, 0})}));
    assertStatus(Status::InvalidArgument, rig.session.cardSetValidity(1, window({2026, 4, 31, 0, 0, 0})));
    assertStatus(Status::InvalidArgument, rig.session.fingerprintSetValidity(1, window({2026, 2, 29, 0, 0, 0})));
    assertStatus(Status::InvalidArgument, rig.session.cardEnroll(window({2026, 1, 1, 24, 0, 0}), none, id));
    assertStatus(Status::InvalidArgument, rig.session.fingerprintEnroll(window({2100, 1, 1, 0, 0, 0}), none, id));
    assertStatus(Status::InvalidArgument,
                 rig.session.passageAdd(ttlock::PassageMode{ttlock::PassageType::Weekly, 1, 0, 24, 0, 23, 0}));
    assertStatus(Status::InvalidArgument,
                 rig.session.passageAdd(ttlock::PassageMode{ttlock::PassageType::Weekly, 1, 0, 8, 60, 23, 0}));
    assertStatus(Status::InvalidArgument,
                 rig.session.passageAdd(ttlock::PassageMode{ttlock::PassageType::Weekly, 8, 0, 8, 0, 17, 0}));
    assertStatus(Status::InvalidArgument,
                 rig.session.passageDelete(ttlock::PassageMode{ttlock::PassageType::Monthly, 0, 0, 8, 0, 17, 0}));
    assertStatus(Status::InvalidArgument,
                 rig.session.passageAdd(ttlock::PassageMode{static_cast<ttlock::PassageType>(3), 1, 0, 8, 0, 17, 0}));
    TEST_ASSERT_EQUAL_UINT(0, rig.lock.requests().size());
}

static void test_passcode_writes_send_the_documented_frames() {
    Rig rig;
    attach(rig);
    for (int i = 0; i < 5; ++i) {
        expectAdminLogin(rig.lock);
        rig.lock.expect(i < 4 ? cmd::kManageKeyboardPassword : cmd::kSetAdminKeyboardPassword, kLockKey,
                        {success(kLockKey, i < 4 ? cmd::kManageKeyboardPassword : cmd::kSetAdminKeyboardPassword,
                                 Bytes{0x5A, 0x02})});
    }
    const ttlock::Passcode added{ttlock::PasscodeType::Period, "246810", kTimed};
    assertStatus(Status::Ok, rig.session.passcodeAdd(added));
    assertStatus(Status::Ok, rig.session.passcodeUpdate("13579", added));
    assertStatus(Status::Ok, rig.session.passcodeDelete(ttlock::PasscodeType::Permanent, "13579"));
    assertStatus(Status::Ok, rig.session.passcodeClear());
    assertStatus(Status::Ok, rig.session.setAdminPasscode("8675309"));
    const auto& requests = rig.lock.requests();
    assertPayload(ttlock::buildPasscodeAdd(added), requests[2]);
    assertPayload(ttlock::buildPasscodeUpdate("13579", added), requests[5]);
    assertPayload(ttlock::buildPasscodeDelete(ttlock::PasscodeType::Permanent, "13579"), requests[8]);
    assertPayload(Bytes{0x01}, requests[11]);
    assertPayload(Bytes{8, 6, 7, 5, 3, 0, 9}, requests[14]);
    TEST_ASSERT_EQUAL_STRING("8675309", rig.session.keys().adminPasscode.c_str());
}

static void test_credential_writes_send_the_documented_frames() {
    Rig rig;
    attach(rig);
    for (int i = 0; i < 4; ++i) {
        const uint8_t command = i < 2 ? cmd::kManageFingerprint : cmd::kManageIcCard;
        expectAdminLogin(rig.lock);
        rig.lock.expect(command, kLockKey, {success(kLockKey, command, Bytes{0x5A, 0x03})});
    }
    for (const uint8_t command : {cmd::kManageFingerprint, cmd::kManageIcCard}) {
        expectAdminLogin(rig.lock);
        rig.lock.expect(command, kLockKey, {success(kLockKey, command, Bytes{0x5A, 0x05})});
    }
    assertStatus(Status::Ok, rig.session.fingerprintDelete(1234567890123ULL));
    assertStatus(Status::Ok, rig.session.fingerprintClear());
    assertStatus(Status::Ok, rig.session.cardDelete(305419896ULL));
    assertStatus(Status::Ok, rig.session.cardClear());
    assertStatus(Status::Ok, rig.session.fingerprintSetValidity(1234567890123ULL, kTimed));
    assertStatus(Status::Ok, rig.session.cardSetValidity(305419896ULL, kTimed));
    const auto& requests = rig.lock.requests();
    assertPayload(ttlock::buildFingerprintDelete(1234567890123ULL), requests[2]);
    assertPayload(Bytes{0x04}, requests[5]);
    assertPayload(ttlock::buildCardDelete(305419896ULL), requests[8]);
    assertPayload(Bytes{0x04}, requests[11]);
    assertPayload(ttlock::buildFingerprintSetValidity(1234567890123ULL, kTimed), requests[14]);
    assertPayload(ttlock::buildCardSetValidity(305419896ULL, kTimed), requests[17]);
}

static void test_passage_writes_send_the_documented_frames() {
    Rig rig;
    attach(rig);
    for (int i = 0; i < 3; ++i) {
        expectAdminLogin(rig.lock);
        rig.lock.expect(cmd::kConfigurePassageMode, kLockKey,
                        {success(kLockKey, cmd::kConfigurePassageMode, Bytes{0x5A, 0x02})});
    }
    const ttlock::PassageMode mode{ttlock::PassageType::Weekly, 5, 0, 8, 0, 17, 30};
    assertStatus(Status::Ok, rig.session.passageAdd(mode));
    assertStatus(Status::Ok, rig.session.passageDelete(mode));
    assertStatus(Status::Ok, rig.session.passageClear());
    const auto& requests = rig.lock.requests();
    assertPayload(ttlock::buildPassageAdd(mode), requests[2]);
    assertPayload(ttlock::buildPassageDelete(mode), requests[5]);
    assertPayload(Bytes{0x04}, requests[8]);
}

static void test_events_without_a_sink_are_dropped_quietly() {
    FakeLock lock;
    FakeClock clock;
    FakeRandom random;
    ttlock::Session session(lock, clock, random);
    assertStatus(Status::Ok, session.attach(pairedKeys()));
    lock.push(statePush(1));
    assertStatus(Status::Ok, session.receiveEvent(100));
}

int main() {
    UNITY_BEGIN();
    RUN_TEST(test_pair_runs_the_kind3r_sequence_with_every_optional_read);
    RUN_TEST(test_pair_without_optional_features_sends_only_the_mandatory_steps);
    RUN_TEST(test_pair_uses_the_default_key_until_the_lock_hands_over_its_own);
    RUN_TEST(test_pair_persists_after_add_admin_before_the_admin_passcode_and_when_final);
    RUN_TEST(test_add_admin_carries_the_random_secrets_and_sciener);
    RUN_TEST(test_secrets_and_admin_passcode_are_drawn_from_random);
    RUN_TEST(test_random_draws_reject_the_biased_tail);
    RUN_TEST(test_pair_calibrates_the_lock_to_local_wall_time);
    RUN_TEST(test_init_passwords_uses_the_local_year_except_on_new_years_day);
    RUN_TEST(test_link_drop_after_add_admin_is_pair_incomplete_with_keys_persisted);
    RUN_TEST(test_add_admin_without_a_reply_persists_and_is_pair_incomplete);
    RUN_TEST(test_add_admin_without_the_sciener_echo_is_pair_incomplete);
    RUN_TEST(test_add_admin_refused_by_the_lock_persists_nothing);
    RUN_TEST(test_get_aes_key_timeout_fails_before_any_key_exists);
    RUN_TEST(test_short_aes_key_reply_is_bad_response);
    RUN_TEST(test_pair_with_an_unsynced_clock_sends_nothing);
    RUN_TEST(test_pair_with_a_clock_before_2024_sends_nothing);
    RUN_TEST(test_pair_rejects_a_legacy_frame_layout_without_traffic);
    RUN_TEST(test_pair_accepts_an_empty_initialization_reply_and_no_persist_callback);
    RUN_TEST(test_refused_optional_reads_and_calibration_do_not_stop_pairing);
    RUN_TEST(test_a_silent_time_calibration_does_not_stop_pairing);
    RUN_TEST(test_a_broken_time_calibration_reply_still_stops_pairing);
    RUN_TEST(test_a_confirmed_admin_passcode_is_persisted_before_it_is_sent);
    RUN_TEST(test_a_refused_admin_passcode_rolls_back_and_makes_pairing_incomplete);
    RUN_TEST(test_a_silent_admin_passcode_keeps_the_tentative_code);
    RUN_TEST(test_refused_mandatory_steps_make_pairing_incomplete);
    RUN_TEST(test_a_silent_optional_read_makes_pairing_incomplete);
    RUN_TEST(test_unlock_checks_user_time_then_sends_the_sum_and_utc_time);
    RUN_TEST(test_lock_uses_function_lock_0x58);
    RUN_TEST(test_unlock_sum_wraps_modulo_2_32);
    RUN_TEST(test_lock_error_replies_map_to_lock_error_with_the_code);
    RUN_TEST(test_unlock_with_an_unsynced_clock_sends_nothing);
    RUN_TEST(test_pushes_while_waiting_go_to_the_event_sink);
    RUN_TEST(test_a_log_push_during_a_status_query_is_not_the_reply);
    RUN_TEST(test_too_many_unsolicited_frames_time_out);
    RUN_TEST(test_a_reply_with_a_bad_crc_fails_without_resending);
    RUN_TEST(test_a_push_with_a_bad_crc_is_dropped);
    RUN_TEST(test_undecodable_frames_are_dropped_and_the_wait_continues);
    RUN_TEST(test_a_stray_frame_under_another_key_mid_pairing_is_dropped);
    RUN_TEST(test_a_matching_reply_that_does_not_parse_is_bad_response);
    RUN_TEST(test_a_wait_that_only_sees_undecodable_frames_times_out);
    RUN_TEST(test_receive_event_skips_frames_it_cannot_use);
    RUN_TEST(test_a_long_status_frame_is_taken_as_a_log_push);
    RUN_TEST(test_methods_before_attach_return_not_paired_without_traffic);
    RUN_TEST(test_attach_rejects_a_legacy_frame_layout);
    RUN_TEST(test_feature_gated_methods_return_unsupported_without_traffic);
    RUN_TEST(test_admin_methods_log_in_with_check_admin_and_check_random);
    RUN_TEST(test_a_failed_admin_login_stops_the_command);
    RUN_TEST(test_commands_wait_five_seconds_for_each_reply);
    RUN_TEST(test_passcode_list_follows_the_cursor_until_zero);
    RUN_TEST(test_passcode_list_stops_at_the_end_of_list_marker);
    RUN_TEST(test_a_list_cursor_that_does_not_advance_is_bad_response);
    RUN_TEST(test_card_and_fingerprint_lists_page_until_ffff);
    RUN_TEST(test_passage_list_pages_until_ff);
    RUN_TEST(test_fingerprint_enroll_reports_each_scan_then_sets_validity);
    RUN_TEST(test_card_enroll_waits_for_the_card_then_sets_validity);
    RUN_TEST(test_enroll_without_a_scan_times_out_and_a_refusal_is_a_lock_error);
    RUN_TEST(test_fetch_log_follows_the_cursor_until_an_empty_page);
    RUN_TEST(test_fetch_log_stops_when_the_cursor_repeats_or_reaches_zero);
    RUN_TEST(test_factory_reset_logs_in_accepts_an_empty_reply_and_detaches);
    RUN_TEST(test_factory_reset_maps_a_refusal_to_lock_error_and_stays_attached);
    RUN_TEST(test_sync_time_logs_in_and_sends_local_wall_time);
    RUN_TEST(test_device_info_reads_the_four_strings);
    RUN_TEST(test_features_refreshes_the_mask);
    RUN_TEST(test_sound_reset_button_and_remote_unlock_settings);
    RUN_TEST(test_volume_outside_one_to_five_is_rejected_without_traffic);
    RUN_TEST(test_passcode_writes_validate_input_before_sending);
    RUN_TEST(test_dates_and_passage_fields_are_validated_before_sending);
    RUN_TEST(test_passcode_writes_send_the_documented_frames);
    RUN_TEST(test_credential_writes_send_the_documented_frames);
    RUN_TEST(test_passage_writes_send_the_documented_frames);
    RUN_TEST(test_events_without_a_sink_are_dropped_quietly);
    return UNITY_END();
}
