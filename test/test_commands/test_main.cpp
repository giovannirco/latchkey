// SPDX-License-Identifier: GPL-3.0-or-later
#include <unity.h>

#include <algorithm>
#include <array>
#include <cstddef>
#include <cstdint>
#include <cstdio>
#include <cstring>
#include <set>
#include <string>

#include "../vectors/command_vectors.h"
#include "../vectors/kind3r_admin_code_vectors.h"
#include "../vectors/kind3r_vectors.h"
#include "ttlock/aes.h"
#include "ttlock/commands.h"
#include "ttlock/errors.h"
#include "ttlock/features.h"
#include "ttlock/frame.h"
#include "ttlock/types.h"

namespace k3 = vectors::kind3r;
namespace k3a = vectors::kind3r_admin;
namespace tb = vectors::command;

using ttlock::Bytes;
using ttlock::LockTime;

void setUp() {}

void tearDown() {}

static Bytes toBytes(const uint8_t* data, size_t size) {
    return Bytes(data, data + size);
}

template <size_t N>
static Bytes toBytes(const uint8_t (&data)[N]) {
    return Bytes(data, data + N);
}

static void assertBytes(const uint8_t* expected, size_t size, const Bytes& actual, const char* name) {
    TEST_ASSERT_EQUAL_UINT_MESSAGE(size, actual.size(), name);
    if (size > 0) {
        TEST_ASSERT_EQUAL_HEX8_ARRAY_MESSAGE(expected, actual.data(), size, name);
    }
}

template <size_t N>
static void assertBytes(const uint8_t (&expected)[N], const Bytes& actual, const char* name) {
    assertBytes(expected, N, actual, name);
}

static std::string minutes(const LockTime& time) {
    char buffer[16];
    std::snprintf(buffer, sizeof(buffer), "%04u%02u%02u%02u%02u", time.year, time.month, time.day, time.hour,
                  time.minute);
    return buffer;
}

static std::string seconds(const LockTime& time) {
    char buffer[16];
    std::snprintf(buffer, sizeof(buffer), "%02u%02u%02u%02u%02u%02u", time.year % 100, time.month, time.day,
                  time.hour, time.minute, time.second);
    return buffer;
}

static LockTime timeOf(const uint16_t (&fields)[6]) {
    return LockTime{fields[0],
                    static_cast<uint8_t>(fields[1]),
                    static_cast<uint8_t>(fields[2]),
                    static_cast<uint8_t>(fields[3]),
                    static_cast<uint8_t>(fields[4]),
                    static_cast<uint8_t>(fields[5])};
}

static void assertTime(const LockTime& expected, const LockTime& actual, const char* name) {
    TEST_ASSERT_EQUAL_UINT16_MESSAGE(expected.year, actual.year, name);
    TEST_ASSERT_EQUAL_UINT8_MESSAGE(expected.month, actual.month, name);
    TEST_ASSERT_EQUAL_UINT8_MESSAGE(expected.day, actual.day, name);
    TEST_ASSERT_EQUAL_UINT8_MESSAGE(expected.hour, actual.hour, name);
    TEST_ASSERT_EQUAL_UINT8_MESSAGE(expected.minute, actual.minute, name);
    TEST_ASSERT_EQUAL_UINT8_MESSAGE(expected.second, actual.second, name);
}

static const LockTime kStart{2025, 11, 7, 9, 0, 0};
static const LockTime kEnd{2026, 12, 31, 23, 59, 0};

static void test_reply_splits_echo_status_and_data() {
    ttlock::Reply reply;
    TEST_ASSERT_TRUE(ttlock::parseReply(Bytes{0x41, 0x01, 0xAA, 0xBB}, reply));
    TEST_ASSERT_EQUAL_HEX8(0x41, reply.command);
    TEST_ASSERT_EQUAL_HEX8(0x01, reply.status);
    TEST_ASSERT_EQUAL_UINT(2, reply.data.size());
    TEST_ASSERT_EQUAL_HEX8(0xBB, reply.data[1]);
    TEST_ASSERT_TRUE(ttlock::parseReply(Bytes{0x57, 0x01}, reply));
    TEST_ASSERT_TRUE(reply.data.empty());
    TEST_ASSERT_FALSE(ttlock::parseReply(Bytes{0x57}, reply));
}

static void test_aes_key_request_is_sciener_like_kind3r_not_the_ttlock_ble_vendor_token() {
    assertBytes(k3::kAesKeyRequest, ttlock::buildGetAesKey(), "get aes key");
}

static void test_aes_key_reply_needs_exactly_16_bytes() {
    ttlock::AesKey key{};
    const Bytes sixteen{0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88, 0x99, 0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF};
    TEST_ASSERT_TRUE(ttlock::parseAesKey(sixteen, key));
    TEST_ASSERT_EQUAL_HEX8_ARRAY(sixteen.data(), key.data(), 16);
    TEST_ASSERT_FALSE(ttlock::parseAesKey(Bytes(15, 0x01), key));
    TEST_ASSERT_FALSE(ttlock::parseAesKey(Bytes(17, 0x01), key));
}

static void test_add_admin_matches_kind3r() {
    assertBytes(k3::kAddAdmin, ttlock::buildAddAdmin(k3::kAddAdminAdminPs, k3::kAddAdminUnlockKey), "add admin");
}

static void test_add_admin_is_accepted_only_when_the_lock_echoes_sciener() {
    TEST_ASSERT_TRUE(ttlock::isAddAdminAccepted(Bytes{'S', 'C', 'I', 'E', 'N', 'E', 'R'}));
    TEST_ASSERT_FALSE(ttlock::isAddAdminAccepted(Bytes{'S', 'C', 'I', 'E', 'N', 'E', 'X'}));
    TEST_ASSERT_FALSE(ttlock::isAddAdminAccepted(Bytes{}));
}

static void test_check_admin_matches_kind3r_and_ttlock_ble() {
    assertBytes(k3::kCheckAdmin, ttlock::buildCheckAdmin(12345678, 0, 0), "kind3r check admin");
    assertBytes(tb::kCheckAdminDefault, ttlock::buildCheckAdmin(12345678, 0, 0), "ttlock-ble check admin");
    assertBytes(tb::kCheckAdminFlagAndUid, ttlock::buildCheckAdmin(12345678, 0x123456, 0x01020304), "flag and uid");
}

static void test_check_random_sums_modulo_2_32() {
    assertBytes(k3::kCheckRandom, ttlock::buildCheckRandom(0x01020304, 87654321), "kind3r check random");
    assertBytes(tb::kCheckRandom, ttlock::buildCheckRandom(0x01020304, 87654321), "ttlock-ble check random");
    assertBytes(tb::kCheckRandomWraps, ttlock::buildCheckRandom(0xFFFFFFF0, 0x20), "wraps");
}

static void test_check_user_time_matches_kind3r_and_ttlock_ble() {
    assertBytes(k3::kCheckUserTime, ttlock::buildCheckUserTime(0, 0), "kind3r default");
    assertBytes(tb::kCheckUserTimeDefault, ttlock::buildCheckUserTime(0, 0), "ttlock-ble default");
    assertBytes(k3::kCheckUserTimeFlag, ttlock::buildCheckUserTime(0x123456, 0), "kind3r lock flag");
    assertBytes(tb::kCheckUserTimeFlagAndUid, ttlock::buildCheckUserTime(0x123456, 0x01020304), "flag and uid");
}

static void test_ps_from_lock_is_the_first_four_bytes_big_endian() {
    uint32_t ps = 0;
    TEST_ASSERT_TRUE(ttlock::parsePsFromLock(toBytes(tb::kPsFromLockData), ps));
    TEST_ASSERT_EQUAL_HEX32(tb::kPsFromLock, ps);
    TEST_ASSERT_FALSE(ttlock::parsePsFromLock(Bytes{0x01, 0x02, 0x03}, ps));
}

static void test_unlock_and_lock_payloads_match_kind3r_and_ttlock_ble() {
    const auto now = static_cast<uint32_t>(k3::kFixedNowUtc);
    const Bytes payload = ttlock::buildLockControl(0x0A0B0C0D, 87654321, now);
    assertBytes(k3::kUnlock, payload, "kind3r unlock");
    assertBytes(k3::kLock, payload, "kind3r lock");
    assertBytes(tb::kUnlock, payload, "ttlock-ble unlock");
    assertBytes(tb::kUnlockWraps, ttlock::buildLockControl(0xFFFFFFFF, 2, now), "sum wraps");
}

static void test_operation_result_matches_kind3r_unlock_reply() {
    const ttlock::OperationResult result = ttlock::parseOperationResult(toBytes(k3::kUnlockReplyData));
    TEST_ASSERT_EQUAL_INT(k3::kUnlockReplyBattery, result.battery);
    TEST_ASSERT_TRUE(result.hasRecord);
    TEST_ASSERT_EQUAL_UINT32(k3::kUnlockReplyUid, result.uid);
    TEST_ASSERT_EQUAL_UINT32(k3::kUnlockReplyUniqueId, result.recordId);
    TEST_ASSERT_EQUAL_STRING(k3::kUnlockReplyDateTime, seconds(result.time).c_str());
}

static void test_operation_result_with_battery_only_or_nothing() {
    const ttlock::OperationResult batteryOnly = ttlock::parseOperationResult(Bytes{0x40});
    TEST_ASSERT_EQUAL_INT(0x40, batteryOnly.battery);
    TEST_ASSERT_FALSE(batteryOnly.hasRecord);
    const ttlock::OperationResult empty = ttlock::parseOperationResult(Bytes{});
    TEST_ASSERT_EQUAL_INT(-1, empty.battery);
    TEST_ASSERT_FALSE(empty.hasRecord);
}

static void test_calibrate_time_is_six_decimal_bytes() {
    assertBytes(k3::kCalibrateTime, ttlock::buildCalibrateTime(LockTime{2025, 11, 7, 14, 0, 0}), "kind3r calibrate");
    assertBytes(tb::kCalibrateTime, ttlock::buildCalibrateTime(LockTime{2025, 11, 7, 11, 0, 5}), "ttlock-ble calibrate");
}

static void test_epoch_seconds_become_civil_time() {
    for (const auto& c : tb::kEpochCases) {
        char name[32];
        std::snprintf(name, sizeof(name), "epoch %lld", static_cast<long long>(c.seconds));
        const LockTime expected{c.year, c.month, c.day, c.hour, c.minute, c.second};
        assertTime(expected, ttlock::lockTimeFromEpoch(c.seconds), name);
    }
}

static void test_status_request_and_reply() {
    assertBytes(k3::kSearchStatus, ttlock::buildSearchStatus(), "kind3r status");
    assertBytes(tb::kSearchStatus, ttlock::buildSearchStatus(), "ttlock-ble status");
    for (const auto& c : tb::kStatusCases) {
        ttlock::LockStatus status;
        TEST_ASSERT_TRUE(ttlock::parseLockStatus(toBytes(c.data, c.size), status));
        TEST_ASSERT_EQUAL_INT(c.battery, status.battery);
        const int state = status.state == ttlock::LockState::Unknown ? -1 : static_cast<int>(status.state);
        TEST_ASSERT_EQUAL_INT(c.state, state);
    }
    ttlock::LockStatus kind3r;
    TEST_ASSERT_TRUE(ttlock::parseLockStatus(toBytes(k3::kStatusReplyData), kind3r));
    TEST_ASSERT_EQUAL_INT(k3::kStatusReplyState, static_cast<int>(kind3r.state));
    ttlock::LockStatus shortReply;
    TEST_ASSERT_FALSE(ttlock::parseLockStatus(Bytes{0x2C}, shortReply));
}

static void test_features_stitch_words_low_word_first() {
    for (const auto& c : tb::kFeatureCases) {
        uint64_t mask = 0;
        TEST_ASSERT_TRUE(ttlock::parseFeatures(toBytes(c.data, c.size), mask));
        TEST_ASSERT_EQUAL_HEX64(c.mask, mask);
    }
    uint64_t mask = 0;
    TEST_ASSERT_FALSE(ttlock::parseFeatures(Bytes{0x64, 0x00, 0x00, 0x00}, mask));
    TEST_ASSERT_TRUE(ttlock::hasFeature(tb::kFeatureCases[0].mask, ttlock::Feature::Passcode));
    TEST_ASSERT_TRUE(ttlock::hasFeature(tb::kFeatureCases[0].mask, ttlock::Feature::PrivacyLock));
    TEST_ASSERT_TRUE(ttlock::hasFeature(tb::kFeatureCases[0].mask, ttlock::Feature::CyclicIcOrFingerPrint));
    TEST_ASSERT_FALSE(ttlock::hasFeature(tb::kFeatureCases[0].mask, ttlock::Feature::FreezeLock));
}

static void test_device_info_requests_and_strings() {
    assertBytes(k3::kReadDeviceInfoModel, ttlock::buildReadDeviceInfo(ttlock::DeviceInfoItem::Model), "model");
    assertBytes(k3::kReadDeviceInfoHardware, ttlock::buildReadDeviceInfo(ttlock::DeviceInfoItem::Hardware), "hw");
    assertBytes(k3::kReadDeviceInfoFirmware, ttlock::buildReadDeviceInfo(ttlock::DeviceInfoItem::Firmware), "fw");
    assertBytes(k3::kReadDeviceInfoManufactureDate,
                ttlock::buildReadDeviceInfo(ttlock::DeviceInfoItem::ManufactureDate), "date");
    assertBytes(tb::kReadDeviceInfo1, ttlock::buildReadDeviceInfo(ttlock::DeviceInfoItem::Model), "ttlock-ble 1");
    assertBytes(tb::kReadDeviceInfo4, ttlock::buildReadDeviceInfo(ttlock::DeviceInfoItem::ManufactureDate),
                "ttlock-ble 4");
    TEST_ASSERT_EQUAL_STRING(tb::kDeviceInfoString,
                             ttlock::parseDeviceInfoString(toBytes(tb::kDeviceInfoStringData)).c_str());
    TEST_ASSERT_EQUAL_STRING("1.2", ttlock::parseDeviceInfoString(Bytes{'1', '.', '2'}).c_str());
}

static void test_admin_passcode_digits_are_raw_values_like_kind3r() {
    assertBytes(k3::kSetAdminPasscode, ttlock::buildSetAdminPasscode(k3::kSetAdminPasscodeCode), "admin passcode");
}

static void test_admin_code_parses_like_kind3r_where_kind3r_is_consistent() {
    std::string code = "unchanged";
    TEST_ASSERT_TRUE(ttlock::parseAdminCode(toBytes(k3a::kAdminCodeEmpty), code));
    TEST_ASSERT_EQUAL_STRING(k3a::kAdminCodeEmptyKind3r, code.c_str());
    TEST_ASSERT_TRUE(ttlock::parseAdminCode(toBytes(k3a::kAdminCodeTrailed), code));
    TEST_ASSERT_EQUAL_STRING(k3a::kAdminCodeTrailedKind3r, code.c_str());
}

static void test_admin_code_takes_the_declared_length_where_kind3r_drops_two_digits() {
    std::string code;
    TEST_ASSERT_TRUE(ttlock::parseAdminCode(toBytes(k3a::kAdminCodeExact), code));
    TEST_ASSERT_EQUAL_UINT(k3a::kAdminCodeExact[1], code.size());
    TEST_ASSERT_EQUAL_STRING("3141592", code.c_str());
    TEST_ASSERT_EQUAL_UINT(code.size() - 2, std::strlen(k3a::kAdminCodeExactKind3r));
}

static void test_admin_code_refuses_short_or_non_digit_replies() {
    std::string code = "unchanged";
    TEST_ASSERT_FALSE(ttlock::parseAdminCode(Bytes{}, code));
    TEST_ASSERT_FALSE(ttlock::parseAdminCode(Bytes{0x5A}, code));
    TEST_ASSERT_FALSE(ttlock::parseAdminCode(Bytes{0x5A, 0x08, '1', '2'}, code));
    TEST_ASSERT_FALSE(ttlock::parseAdminCode(Bytes{0x5A, 0x04, 0x03, 0x01, 0x04, 0x01}, code));
    TEST_ASSERT_FALSE(ttlock::parseAdminCode(Bytes{0x5A, 0x09, '3', '1', '4', '1', '5', '9', '2', 0x00, 0x00}, code));
    TEST_ASSERT_EQUAL_STRING("unchanged", code.c_str());
}

static void test_init_passwords_matches_kind3r() {
    std::array<ttlock::CodeSecret, ttlock::kCodeSecretCount> seeds{};
    for (size_t i = 0; i < seeds.size(); ++i) {
        seeds[i] = ttlock::CodeSecret{k3::kInitPasswordsCodes[i], k3::kInitPasswordsSecrets[i]};
    }
    assertBytes(k3::kInitPasswords, ttlock::buildInitPasswords(k3::kInitPasswordsYear, seeds), "init passwords");
}

static void test_empty_payload_commands_match_kind3r() {
    TEST_ASSERT_EQUAL_UINT(0, k3::kInitializationPayloadSize);
    TEST_ASSERT_EQUAL_UINT(0, k3::kOperateFinishedPayloadSize);
    TEST_ASSERT_EQUAL_UINT(0, k3::kResetLockPayloadSize);
    TEST_ASSERT_EQUAL_UINT(0, k3::kSearchDeviceFeaturePayloadSize);
    TEST_ASSERT_EQUAL_UINT(0, k3::kGetAdminCodePayloadSize);
}

static ttlock::Passcode passcode(ttlock::PasscodeType type, const char* code, LockTime start, LockTime end) {
    return ttlock::Passcode{type, code, ttlock::Validity{start, end}};
}

static void test_passcode_add_follows_ttlock_ble() {
    assertBytes(tb::kPasscodeAddPermanent,
                ttlock::buildPasscodeAdd(passcode(ttlock::PasscodeType::Permanent, "13579", ttlock::kPermanentStart,
                                                  ttlock::kPermanentEnd)),
                "permanent");
    assertBytes(tb::kPasscodeAddPeriod,
                ttlock::buildPasscodeAdd(passcode(ttlock::PasscodeType::Period, "246810", kStart,
                                                  LockTime{2025, 12, 31, 23, 59, 0})),
                "period");
    assertBytes(tb::kPasscodeAddCount,
                ttlock::buildPasscodeAdd(passcode(ttlock::PasscodeType::Count, "8642", kStart,
                                                  LockTime{2025, 11, 7, 15, 0, 0})),
                "count");
}

static void test_passcode_update_delete_clear_and_list_requests() {
    assertBytes(k3::kPasscodeUpdate,
                ttlock::buildPasscodeUpdate("13579", passcode(ttlock::PasscodeType::Period, "246810", kStart,
                                                              LockTime{2025, 12, 31, 23, 59, 0})),
                "kind3r update");
    const Bytes deleted = ttlock::buildPasscodeDelete(ttlock::PasscodeType::Permanent, "13579");
    assertBytes(k3::kPasscodeDelete, deleted, "kind3r delete");
    assertBytes(tb::kPasscodeDelete, deleted, "ttlock-ble delete");
    assertBytes(k3::kPasscodeClear, ttlock::buildPasscodeClear(), "kind3r clear");
    assertBytes(tb::kPasscodeClear, ttlock::buildPasscodeClear(), "ttlock-ble clear");
    assertBytes(k3::kPasscodeListRequest0, ttlock::buildPasscodeListRequest(0), "kind3r list 0");
    assertBytes(k3::kPasscodeListRequestB4, ttlock::buildPasscodeListRequest(0xB4), "kind3r list b4");
    assertBytes(tb::kPasscodeListRequest0, ttlock::buildPasscodeListRequest(0), "ttlock-ble list 0");
    assertBytes(tb::kPasscodeListRequest336, ttlock::buildPasscodeListRequest(336), "ttlock-ble list 336");
}

static void test_passcode_pages_match_ttlock_ble() {
    for (const auto& c : tb::kPasscodePages) {
        ttlock::PasscodePage page;
        TEST_ASSERT_TRUE_MESSAGE(ttlock::parsePasscodePage(toBytes(c.data, c.size), page), c.name);
        TEST_ASSERT_EQUAL_UINT_MESSAGE(c.hasItem ? 1 : 0, page.items.size(), c.name);
        TEST_ASSERT_EQUAL_UINT16_MESSAGE(c.next, page.next, c.name);
        TEST_ASSERT_EQUAL_MESSAGE(c.next == 0, page.last, c.name);
        if (!c.hasItem) {
            continue;
        }
        const ttlock::Passcode& item = page.items[0];
        TEST_ASSERT_EQUAL_UINT8_MESSAGE(c.type, static_cast<uint8_t>(item.type), c.name);
        TEST_ASSERT_EQUAL_STRING_MESSAGE(c.code, item.code.c_str(), c.name);
        if (item.type == ttlock::PasscodeType::Cyclic) {
            assertTime(LockTime{2000, 1, 1, 17, 0, 0}, item.validity.start, c.name);
            continue;
        }
        assertTime(timeOf(c.start), item.validity.start, c.name);
        assertTime(timeOf(c.end), item.validity.end, c.name);
    }
}

static void test_passcode_page_matches_kind3r_capture() {
    ttlock::PasscodePage page;
    TEST_ASSERT_TRUE(ttlock::parsePasscodePage(toBytes(k3::kPasscodeCaptureData), page));
    TEST_ASSERT_EQUAL_UINT16(k3::kPasscodeCaptureSequence, page.next);
    TEST_ASSERT_FALSE(page.last);
    TEST_ASSERT_EQUAL_UINT(1, page.items.size());
    TEST_ASSERT_EQUAL_INT(k3::kPasscodeCaptureType, static_cast<int>(page.items[0].type));
    TEST_ASSERT_EQUAL_STRING(k3::kPasscodeCaptureCode, page.items[0].code.c_str());
    TEST_ASSERT_EQUAL_STRING(k3::kPasscodeCaptureStart, minutes(page.items[0].validity.start).c_str());
    ttlock::PasscodePage end;
    TEST_ASSERT_TRUE(ttlock::parsePasscodePage(Bytes{0x00, 0x00}, end));
    TEST_ASSERT_EQUAL_UINT(k3::kPasscodeEndCount, end.items.size());
    TEST_ASSERT_TRUE(end.last);
}

static void test_passcode_page_with_two_items_and_an_unknown_type() {
    const Bytes data{0x00, 0x21, 0x00, 0x09, 0x10, 0x01, 0x04, '1', '3', '5', '7', 0x04, '1', '3', '5', '7', 0x00,
                     0x01, 0x01, 0x00, 0x00, 0x0D, 0x07, 0x04, '2', '4', '6', '8', 0x04, '2', '4', '6', '8', 0xAA,
                     0xBB};
    ttlock::PasscodePage page;
    TEST_ASSERT_TRUE(ttlock::parsePasscodePage(data, page));
    TEST_ASSERT_EQUAL_UINT(2, page.items.size());
    TEST_ASSERT_EQUAL_STRING("1357", page.items[0].code.c_str());
    TEST_ASSERT_EQUAL_UINT8(7, static_cast<uint8_t>(page.items[1].type));
    TEST_ASSERT_EQUAL_STRING("2468", page.items[1].code.c_str());
    TEST_ASSERT_EQUAL_UINT16(9, page.next);
}

static void test_malformed_passcode_pages_are_rejected() {
    ttlock::PasscodePage page;
    TEST_ASSERT_FALSE(ttlock::parsePasscodePage(Bytes{0x00}, page));
    TEST_ASSERT_FALSE(ttlock::parsePasscodePage(Bytes{0x00, 0x05, 0x00}, page));
    TEST_ASSERT_FALSE(ttlock::parsePasscodePage(Bytes{0x00, 0x05, 0x00, 0x01, 0x09, 0x01, 0x04, '1'}, page));
    TEST_ASSERT_FALSE(ttlock::parsePasscodePage(Bytes{0x00, 0x05, 0x00, 0x01, 0x03, 0x01, 0x09, '1'}, page));
}

static void test_fingerprint_requests_match_kind3r_and_ttlock_ble() {
    assertBytes(k3::kFingerprintListRequest0, ttlock::buildFingerprintListRequest(0), "kind3r list");
    assertBytes(tb::kFingerprintListRequest0, ttlock::buildFingerprintListRequest(0), "ttlock-ble list 0");
    assertBytes(tb::kFingerprintListRequest300, ttlock::buildFingerprintListRequest(300), "ttlock-ble list 300");
    assertBytes(k3::kFingerprintEnrollStart, ttlock::buildFingerprintEnrollStart(), "enroll start");
    const uint64_t id = 1234567890123ULL;
    assertBytes(k3::kFingerprintSetValidity, ttlock::buildFingerprintSetValidity(id, ttlock::Validity{kStart, kEnd}),
                "set validity");
    assertBytes(k3::kFingerprintDelete, ttlock::buildFingerprintDelete(id), "delete");
    assertBytes(k3::kFingerprintClear, ttlock::buildFingerprintClear(), "clear");
}

static void test_fingerprint_pages_match_ttlock_ble_and_kind3r() {
    for (const auto& c : tb::kFingerprintPages) {
        ttlock::CredentialPage page;
        TEST_ASSERT_TRUE_MESSAGE(ttlock::parseFingerprintPage(toBytes(c.data, c.size), page), c.name);
        TEST_ASSERT_EQUAL_UINT_MESSAGE(c.hasItem ? 1 : 0, page.items.size(), c.name);
        TEST_ASSERT_EQUAL_MESSAGE(!c.hasItem, page.last, c.name);
        if (c.hasItem) {
            TEST_ASSERT_EQUAL_HEX64_MESSAGE(c.id, page.items[0].id, c.name);
            assertTime(timeOf(c.start), page.items[0].validity.start, c.name);
            assertTime(timeOf(c.end), page.items[0].validity.end, c.name);
        }
    }
    ttlock::CredentialPage page;
    TEST_ASSERT_TRUE(ttlock::parseFingerprintPage(toBytes(k3::kFingerprintPageData), page));
    TEST_ASSERT_EQUAL_UINT16(k3::kFingerprintPageSequence, page.next);
    TEST_ASSERT_EQUAL_UINT(k3::kFingerprintPageCount, page.items.size());
    TEST_ASSERT_EQUAL_STRING(k3::kFingerprintPageNumber, std::to_string(page.items[0].id).c_str());
    TEST_ASSERT_EQUAL_STRING(k3::kFingerprintPageStart, minutes(page.items[0].validity.start).c_str());
    TEST_ASSERT_EQUAL_STRING(k3::kFingerprintPageEnd, minutes(page.items[0].validity.end).c_str());
    TEST_ASSERT_FALSE(ttlock::parseFingerprintPage(Bytes{0x64, 0x06, 0x00, 0x01, 0x01}, page));
    TEST_ASSERT_FALSE(ttlock::parseFingerprintPage(Bytes{0x64, 0x01, 0xFF, 0xFF}, page));
}

static void test_fingerprint_enroll_replies_match_kind3r() {
    ttlock::EnrollReply reply;
    TEST_ASSERT_TRUE(ttlock::parseFingerprintEnrollReply(toBytes(k3::kFingerprintWaitingData), reply));
    TEST_ASSERT_EQUAL_INT(k3::kFingerprintWaitingStatus, static_cast<int>(reply.status));
    TEST_ASSERT_TRUE(ttlock::parseFingerprintEnrollReply(toBytes(k3::kFingerprintProgressData), reply));
    TEST_ASSERT_EQUAL_INT(k3::kFingerprintProgressStatus, static_cast<int>(reply.status));
    TEST_ASSERT_TRUE(ttlock::parseFingerprintEnrollReply(toBytes(k3::kFingerprintAddedData), reply));
    TEST_ASSERT_EQUAL_INT(k3::kFingerprintAddedStatus, static_cast<int>(reply.status));
    TEST_ASSERT_EQUAL_STRING(k3::kFingerprintAddedNumber, std::to_string(reply.id).c_str());
    TEST_ASSERT_FALSE(ttlock::parseFingerprintEnrollReply(Bytes{0x64, 0x02, 0x01, 0x01}, reply));
    TEST_ASSERT_FALSE(ttlock::parseFingerprintEnrollReply(Bytes{0x64, 0x05, 0x01}, reply));
}

static void test_card_requests_match_kind3r_and_ttlock_ble() {
    assertBytes(k3::kCardListRequest0, ttlock::buildCardListRequest(0), "kind3r list 0");
    assertBytes(k3::kCardListRequest258, ttlock::buildCardListRequest(258), "kind3r list 258");
    assertBytes(tb::kCardListRequest0, ttlock::buildCardListRequest(0), "ttlock-ble list 0");
    assertBytes(tb::kCardListRequest300, ttlock::buildCardListRequest(300), "ttlock-ble list 300");
    assertBytes(k3::kCardEnrollStart, ttlock::buildCardEnrollStart(), "enroll start");
    const ttlock::Validity validity{kStart, kEnd};
    assertBytes(k3::kCardSetValidity4, ttlock::buildCardSetValidity(305419896ULL, validity), "4-byte validity");
    assertBytes(k3::kCardSetValidity8, ttlock::buildCardSetValidity(1234605616436508552ULL, validity),
                "8-byte validity");
    assertBytes(k3::kCardDelete4, ttlock::buildCardDelete(305419896ULL), "4-byte delete");
    assertBytes(k3::kCardClear, ttlock::buildCardClear(), "clear");
}

static void test_eight_byte_card_delete_uses_the_long_id_kind3r_drops() {
    TEST_ASSERT_EQUAL_UINT(0, k3::kCardDelete8Kind3rSize);
    const Bytes expected{0x03, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88};
    assertBytes(expected.data(), expected.size(), ttlock::buildCardDelete(0x1122334455667788ULL), "8-byte delete");
}

static void test_card_pages_match_ttlock_ble_and_kind3r() {
    for (const auto& c : tb::kCardPages) {
        ttlock::CredentialPage page;
        TEST_ASSERT_TRUE_MESSAGE(ttlock::parseCardPage(toBytes(c.data, c.size), page), c.name);
        TEST_ASSERT_EQUAL_UINT_MESSAGE(c.hasItem ? 1 : 0, page.items.size(), c.name);
        TEST_ASSERT_EQUAL_MESSAGE(!c.hasItem, page.last, c.name);
        if (c.hasItem) {
            TEST_ASSERT_EQUAL_HEX64_MESSAGE(c.id, page.items[0].id, c.name);
            assertTime(timeOf(c.start), page.items[0].validity.start, c.name);
            assertTime(timeOf(c.end), page.items[0].validity.end, c.name);
        }
    }
    ttlock::CredentialPage page;
    TEST_ASSERT_TRUE(ttlock::parseCardPage(toBytes(k3::kCardPageData), page));
    TEST_ASSERT_EQUAL_UINT16(k3::kCardPageSequence, page.next);
    TEST_ASSERT_EQUAL_UINT(k3::kCardPageCount, page.items.size());
    TEST_ASSERT_EQUAL_STRING(k3::kCardPageNumber, std::to_string(page.items[0].id).c_str());
    TEST_ASSERT_EQUAL_STRING(k3::kCardPageStart, minutes(page.items[0].validity.start).c_str());
    TEST_ASSERT_EQUAL_STRING(k3::kCardPageEnd, minutes(page.items[0].validity.end).c_str());
    TEST_ASSERT_FALSE(ttlock::parseCardPage(Bytes{0x55, 0x01, 0x00, 0x01, 0x11, 0x22}, page));
    TEST_ASSERT_FALSE(ttlock::parseCardPage(Bytes{0x55, 0x06, 0xFF, 0xFF}, page));
}

static void test_card_enroll_replies_match_kind3r() {
    ttlock::EnrollReply reply;
    TEST_ASSERT_TRUE(ttlock::parseCardEnrollReply(toBytes(k3::kCardAdded4Data), reply));
    TEST_ASSERT_EQUAL_INT(k3::kCardAdded4Status, static_cast<int>(reply.status));
    TEST_ASSERT_EQUAL_STRING(k3::kCardAdded4Number, std::to_string(reply.id).c_str());
    TEST_ASSERT_TRUE(ttlock::parseCardEnrollReply(toBytes(k3::kCardAdded8Data), reply));
    TEST_ASSERT_EQUAL_INT(k3::kCardAdded8Status, static_cast<int>(reply.status));
    TEST_ASSERT_EQUAL_STRING(k3::kCardAdded8Number, std::to_string(reply.id).c_str());
    const Bytes paddedShortId{0x55, 0x02, 0x01, 0x12, 0x34, 0x56, 0x78, 0xFF, 0xFF, 0xFF, 0xFF};
    TEST_ASSERT_TRUE(ttlock::parseCardEnrollReply(paddedShortId, reply));
    TEST_ASSERT_EQUAL_UINT64(305419896ULL, reply.id);
    TEST_ASSERT_FALSE(ttlock::parseCardEnrollReply(Bytes{0x55, 0x02, 0x01, 0x12, 0x34}, reply));
}

static void test_kind3r_card_capture_decodes_to_enter_add_mode() {
    ttlock::AesKey key{};
    std::copy(std::begin(k3::kCardCaptureKey), std::end(k3::kCardCaptureKey), key.begin());
    ttlock::DecodedFrame frame;
    TEST_ASSERT_EQUAL(ttlock::Status::Ok, ttlock::decodeFrame(toBytes(k3::kCardCaptureFrame), key, frame));
    TEST_ASSERT_TRUE(frame.crcOk);
    assertBytes(k3::kCardCapturePlain, frame.payload, "capture plaintext");
    ttlock::Reply reply;
    TEST_ASSERT_TRUE(ttlock::parseReply(frame.payload, reply));
    TEST_ASSERT_EQUAL_HEX8(ttlock::command::kManageIcCard, reply.command);
    TEST_ASSERT_EQUAL_INT(k3::kCardCaptureResponse, reply.status);
    ttlock::EnrollReply enroll;
    TEST_ASSERT_TRUE(ttlock::parseCardEnrollReply(reply.data, enroll));
    TEST_ASSERT_EQUAL_INT(k3::kCardCaptureStatus, static_cast<int>(enroll.status));
    TEST_ASSERT_EQUAL_INT(k3::kCardCaptureBattery, reply.data[0]);
}

static const ttlock::WeeklyCycle kOfficeHours{3, 8 * 60 + 30, 17 * 60 + 45};

static void test_cyclic_commands_match_kind3r() {
    assertBytes(k3::kCyclicCardAdd4, ttlock::buildCardCycleAdd(305419896ULL, kOfficeHours), "card add 4");
    assertBytes(k3::kCyclicCardAdd8,
                ttlock::buildCardCycleAdd(1234605616436508552ULL, ttlock::WeeklyCycle{7, 0, 24 * 60}), "card add 8");
    assertBytes(k3::kCyclicFingerprintAdd,
                ttlock::buildFingerprintCycleAdd(1234567890123ULL, ttlock::WeeklyCycle{1, 2 * 60 + 14, 16 * 60 + 48}),
                "fingerprint add");
    assertBytes(k3::kCyclicCardClear4, ttlock::buildCardCycleClear(305419896ULL), "card clear 4");
    assertBytes(k3::kCyclicCardClear8, ttlock::buildCardCycleClear(1234605616436508552ULL), "card clear 8");
    assertBytes(k3::kCyclicFingerprintClear, ttlock::buildFingerprintCycleClear(1234567890123ULL), "fingerprint clear");
}

static void test_cyclic_card_numbers_from_2_31_go_out_unsigned_where_kind3r_throws() {
    TEST_ASSERT_EQUAL_INT(1, k3::kCyclicCardHighBitKind3rThrows);
    const uint8_t highBitId[] = {0xDE, 0xAD, 0xBE, 0xEF};
    Bytes added = toBytes(k3::kCyclicCardAdd4);
    Bytes cleared = toBytes(k3::kCyclicCardClear4);
    std::copy(std::begin(highBitId), std::end(highBitId), added.begin() + 3);
    std::copy(std::begin(highBitId), std::end(highBitId), cleared.begin() + 3);
    assertBytes(added.data(), added.size(), ttlock::buildCardCycleAdd(0xDEADBEEFULL, kOfficeHours), "high bit add");
    assertBytes(cleared.data(), cleared.size(), ttlock::buildCardCycleClear(0xDEADBEEFULL), "high bit clear");
    TEST_ASSERT_EQUAL_UINT(sizeof(k3::kCyclicCardClear4), ttlock::buildCardCycleClear(0xFFFFFFFFULL).size());
    TEST_ASSERT_EQUAL_UINT(sizeof(k3::kCyclicCardClear8), ttlock::buildCardCycleClear(0x100000000ULL).size());
}

static void test_passage_mode_requests_match_kind3r() {
    assertBytes(k3::kPassageQuery0, ttlock::buildPassageQuery(0), "query");
    const ttlock::PassageMode mode{ttlock::PassageType::Weekly, 5, 0, 8, 0, 17, 30};
    assertBytes(k3::kPassageAdd, ttlock::buildPassageAdd(mode), "add");
    assertBytes(k3::kPassageDelete, ttlock::buildPassageDelete(mode), "delete");
    assertBytes(k3::kPassageClear, ttlock::buildPassageClear(), "clear");
}

static void test_passage_pages_parse_every_seven_byte_entry() {
    ttlock::PassagePage page;
    TEST_ASSERT_TRUE(ttlock::parsePassagePage(toBytes(k3::kPassagePageData), page));
    TEST_ASSERT_EQUAL_INT(k3::kPassagePageSequence, static_cast<int8_t>(page.next));
    TEST_ASSERT_TRUE(page.last);
    TEST_ASSERT_EQUAL_UINT(k3::kPassagePageCount, page.items.size());
    const ttlock::PassageMode& mode = page.items[0];
    TEST_ASSERT_EQUAL_INT(k3::kPassagePageType, static_cast<int>(mode.type));
    TEST_ASSERT_EQUAL_INT(k3::kPassagePageWeekOrDay, mode.weekOrDay);
    TEST_ASSERT_EQUAL_INT(k3::kPassagePageMonth, mode.month);
    char start[8];
    char end[8];
    std::snprintf(start, sizeof(start), "%02u%02u", mode.startHour, mode.startMinute);
    std::snprintf(end, sizeof(end), "%02u%02u", mode.endHour, mode.endMinute);
    TEST_ASSERT_EQUAL_STRING(k3::kPassagePageStart, start);
    TEST_ASSERT_EQUAL_STRING(k3::kPassagePageEnd, end);
    const Bytes twoEntries{0x5A, 0x01, 0x02, 0x01, 0x01, 0x00, 0x07, 0x00, 0x09, 0x00,
                           0x02, 0x0F, 0x00, 0x00, 0x00, 0x00, 0x00};
    TEST_ASSERT_TRUE(ttlock::parsePassagePage(twoEntries, page));
    TEST_ASSERT_EQUAL_UINT(2, page.items.size());
    TEST_ASSERT_EQUAL_UINT8(2, page.next);
    TEST_ASSERT_FALSE(page.last);
    TEST_ASSERT_EQUAL_INT(static_cast<int>(ttlock::PassageType::Monthly), static_cast<int>(page.items[1].type));
    TEST_ASSERT_EQUAL_UINT8(15, page.items[1].weekOrDay);
    TEST_ASSERT_FALSE(ttlock::parsePassagePage(Bytes{0x5A, 0x01, 0xFF, 0x01, 0x05}, page));
    TEST_ASSERT_FALSE(ttlock::parsePassagePage(Bytes{0x5A, 0x02, 0xFF}, page));
}

static void test_sound_commands_match_kind3r_and_ttlock_ble() {
    assertBytes(k3::kSoundQuery, ttlock::buildSoundQuery(), "kind3r query");
    assertBytes(tb::kSoundQuery, ttlock::buildSoundQuery(), "ttlock-ble query");
    assertBytes(k3::kSoundOn, ttlock::buildSoundSet(true), "kind3r on");
    assertBytes(tb::kSoundOn, ttlock::buildSoundSet(true), "ttlock-ble on");
    assertBytes(k3::kSoundOff, ttlock::buildSoundSet(false), "kind3r off");
    assertBytes(tb::kSoundOff, ttlock::buildSoundSet(false), "ttlock-ble off");
    assertBytes(tb::kSoundVolume3, ttlock::buildSoundVolumeSet(3), "volume");
    ttlock::SoundSetting sound;
    TEST_ASSERT_TRUE(ttlock::parseSound(toBytes(tb::kSoundReplyWithVolume), sound));
    TEST_ASSERT_EQUAL(tb::kSoundReplyWithVolumeEnabled, sound.enabled);
    TEST_ASSERT_EQUAL_UINT8(tb::kSoundReplyWithVolumeVolume, sound.volume);
    TEST_ASSERT_TRUE(ttlock::parseSound(toBytes(tb::kSoundReplyWithoutVolume), sound));
    TEST_ASSERT_EQUAL(tb::kSoundReplyWithoutVolumeEnabled, sound.enabled);
    TEST_ASSERT_EQUAL_UINT8(tb::kSoundReplyWithoutVolumeVolume, sound.volume);
    TEST_ASSERT_TRUE(ttlock::parseSound(toBytes(k3::kSoundReplyData), sound));
    TEST_ASSERT_EQUAL(k3::kSoundReplyValue == 1, sound.enabled);
    TEST_ASSERT_FALSE(ttlock::parseSound(Bytes{0x5A, 0x02, 0x01}, sound));
    TEST_ASSERT_FALSE(ttlock::parseSound(Bytes{0x5A, 0x01}, sound));
}

static void test_auto_lock_commands_match_kind3r_and_ttlock_ble() {
    assertBytes(k3::kAutoLockQuery, ttlock::buildAutoLockQuery(), "kind3r query");
    assertBytes(tb::kAutoLockQuery, ttlock::buildAutoLockQuery(), "ttlock-ble query");
    assertBytes(k3::kAutoLockSet300, ttlock::buildAutoLockSet(300), "kind3r set");
    assertBytes(tb::kAutoLockSet300, ttlock::buildAutoLockSet(300), "ttlock-ble set");
    ttlock::AutoLockSetting setting;
    TEST_ASSERT_TRUE(ttlock::parseAutoLock(toBytes(tb::kAutoLockReply), setting));
    TEST_ASSERT_EQUAL_UINT16(tb::kAutoLockSeconds, setting.seconds);
    TEST_ASSERT_EQUAL_UINT16(tb::kAutoLockMin, setting.minSeconds);
    TEST_ASSERT_EQUAL_UINT16(tb::kAutoLockMax, setting.maxSeconds);
    TEST_ASSERT_TRUE(ttlock::parseAutoLock(toBytes(k3::kAutoLockReplyData), setting));
    TEST_ASSERT_EQUAL_UINT16(k3::kAutoLockReplySeconds, setting.seconds);
    TEST_ASSERT_TRUE(ttlock::parseAutoLock(Bytes{0x5A, 0x01, 0x00, 0x0A}, setting));
    TEST_ASSERT_EQUAL_UINT16(10, setting.seconds);
    TEST_ASSERT_EQUAL_UINT16(0, setting.minSeconds);
    TEST_ASSERT_EQUAL_UINT16(0, setting.maxSeconds);
    TEST_ASSERT_FALSE(ttlock::parseAutoLock(Bytes{0x5A, 0x01, 0x00}, setting));
    TEST_ASSERT_FALSE(ttlock::parseAutoLock(Bytes{0x5A, 0x02, 0x00, 0x0A}, setting));
}

static void test_remote_unlock_and_screen_passcode_match_kind3r() {
    assertBytes(k3::kRemoteUnlockQuery, ttlock::buildRemoteUnlockQuery(), "query");
    assertBytes(k3::kRemoteUnlockOn, ttlock::buildRemoteUnlockSet(true), "on");
    assertBytes(k3::kRemoteUnlockOff, ttlock::buildRemoteUnlockSet(false), "off");
    bool enabled = false;
    TEST_ASSERT_TRUE(ttlock::parseRemoteUnlock(toBytes(k3::kRemoteUnlockReplyData), enabled));
    TEST_ASSERT_EQUAL(k3::kRemoteUnlockReplyValue == 1, enabled);
    TEST_ASSERT_FALSE(ttlock::parseRemoteUnlock(Bytes{0x5A, 0x01}, enabled));
    assertBytes(k3::kScreenPasscodeQuery, ttlock::buildScreenPasscodeQuery(), "screen passcode");
}

static void test_screen_passcode_set_and_reply_match_kind3r() {
    assertBytes(k3::kScreenPasscodeShow, ttlock::buildScreenPasscodeSet(true), "show");
    assertBytes(k3::kScreenPasscodeHide, ttlock::buildScreenPasscodeSet(false), "hide");
    bool visible = false;
    TEST_ASSERT_TRUE(ttlock::parseScreenPasscode(toBytes(k3::kScreenPasscodeReplyShownData), visible));
    TEST_ASSERT_EQUAL(k3::kScreenPasscodeReplyShownValue == 1, visible);
    TEST_ASSERT_TRUE(ttlock::parseScreenPasscode(toBytes(k3::kScreenPasscodeReplyHiddenData), visible));
    TEST_ASSERT_EQUAL(k3::kScreenPasscodeReplyHiddenValue == 1, visible);
    TEST_ASSERT_FALSE(ttlock::parseScreenPasscode(Bytes{0x01}, visible));
    TEST_ASSERT_FALSE(ttlock::parseScreenPasscode(Bytes{0x02, 0x01}, visible));
}

static void test_switch_commands_carry_the_item_mask_twice_when_enabling() {
    const Bytes query = ttlock::buildSwitchQuery();
    TEST_ASSERT_EQUAL_UINT(1, query.size());
    TEST_ASSERT_EQUAL_HEX8(0x01, query[0]);
    const Bytes enable{0x02, 0x00, 0x00, 0x00, 0x02, 0x00, 0x00, 0x00, 0x02};
    assertBytes(enable.data(), enable.size(), ttlock::buildSwitchSet(ttlock::kSwitchResetButton, true), "enable");
    const Bytes disable{0x02, 0x00, 0x00, 0x00, 0x02, 0x00, 0x00, 0x00, 0x00};
    assertBytes(disable.data(), disable.size(), ttlock::buildSwitchSet(ttlock::kSwitchResetButton, false), "disable");
    uint32_t value = 0;
    TEST_ASSERT_TRUE(ttlock::parseSwitchState(Bytes{0x5A, 0x01, 0x00, 0x00, 0x00, 0x06}, value));
    TEST_ASSERT_EQUAL_HEX32(0x06, value);
    TEST_ASSERT_FALSE(ttlock::parseSwitchState(Bytes{0x5A, 0x01, 0x00, 0x00, 0x06}, value));
}

static void test_log_requests_match_kind3r_and_ttlock_ble() {
    assertBytes(k3::kLogRequestNew, ttlock::buildOperateLogRequest(ttlock::kLogSinceLastRead), "kind3r new");
    assertBytes(tb::kLogRequestNew, ttlock::buildOperateLogRequest(ttlock::kLogSinceLastRead), "ttlock-ble new");
    assertBytes(k3::kLogRequest5, ttlock::buildOperateLogRequest(5), "kind3r 5");
    assertBytes(tb::kLogRequest5, ttlock::buildOperateLogRequest(5), "ttlock-ble 5");
}

static void test_log_records_match_ttlock_ble() {
    ttlock::LogPage page;
    TEST_ASSERT_TRUE(ttlock::parseLogPage(toBytes(tb::kLogPage), page));
    TEST_ASSERT_EQUAL_UINT16(tb::kLogPageSequence, page.sequence);
    TEST_ASSERT_EQUAL_UINT(sizeof(tb::kLogCases) / sizeof(tb::kLogCases[0]), page.entries.size());
    for (size_t i = 0; i < page.entries.size(); ++i) {
        const auto& c = tb::kLogCases[i];
        const ttlock::LogEntry& entry = page.entries[i];
        TEST_ASSERT_EQUAL_UINT16_MESSAGE(c.recordNumber, entry.recordNumber, c.name);
        TEST_ASSERT_EQUAL_UINT8_MESSAGE(c.type, entry.type, c.name);
        assertTime(timeOf(c.time), entry.time, c.name);
        TEST_ASSERT_EQUAL_UINT8_MESSAGE(c.battery, entry.battery, c.name);
        TEST_ASSERT_EQUAL_UINT32_MESSAGE(c.uid, entry.uid, c.name);
        TEST_ASSERT_EQUAL_UINT32_MESSAGE(c.recordId, entry.recordId, c.name);
        TEST_ASSERT_EQUAL_STRING_MESSAGE(c.credential, entry.credential.c_str(), c.name);
        TEST_ASSERT_EQUAL_STRING_MESSAGE(c.newCredential, entry.newCredential.c_str(), c.name);
        TEST_ASSERT_EQUAL_INT_MESSAGE(c.keyId, entry.keyId, c.name);
        TEST_ASSERT_EQUAL_INT_MESSAGE(c.accessoryBattery, entry.accessoryBattery, c.name);
    }
}

static void test_log_page_matches_kind3r_and_tolerates_a_truncated_record() {
    ttlock::LogPage page;
    TEST_ASSERT_TRUE(ttlock::parseLogPage(toBytes(k3::kLogPageData), page));
    TEST_ASSERT_EQUAL_UINT16(k3::kLogPageSequence, page.sequence);
    TEST_ASSERT_EQUAL_UINT(k3::kLogPageCount, page.entries.size());
    const ttlock::LogEntry& entry = page.entries[0];
    TEST_ASSERT_EQUAL_INT(k3::kLogPageRecordNumber, entry.recordNumber);
    TEST_ASSERT_EQUAL_INT(k3::kLogPageRecordType, entry.type);
    TEST_ASSERT_EQUAL_STRING(k3::kLogPageOperateDate + 2, seconds(entry.time).c_str());
    TEST_ASSERT_EQUAL_INT(k3::kLogPageBattery, entry.battery);
    TEST_ASSERT_EQUAL_UINT32(k3::kLogPageUid, entry.uid);
    TEST_ASSERT_EQUAL_UINT32(k3::kLogPageRecordId, entry.recordId);
    ttlock::LogPage truncated;
    TEST_ASSERT_TRUE(ttlock::parseLogPage(toBytes(tb::kLogPageTruncated), truncated));
    TEST_ASSERT_TRUE(truncated.entries.empty());
    TEST_ASSERT_EQUAL_UINT16(1, truncated.sequence);
    ttlock::LogPage empty;
    TEST_ASSERT_TRUE(ttlock::parseLogPage(Bytes{0x00, 0x00}, empty));
    TEST_ASSERT_TRUE(empty.entries.empty());
    TEST_ASSERT_EQUAL_UINT16(0, empty.sequence);
    TEST_ASSERT_FALSE(ttlock::parseLogPage(Bytes{0x00}, empty));
}

static void test_push_events_match_ttlock_ble() {
    ttlock::Reply statePush{ttlock::command::kSearchStatus, 0x01, toBytes(tb::kStatePush)};
    const ttlock::LockEvent state = ttlock::parseLockEvent(statePush);
    TEST_ASSERT_EQUAL_HEX8(ttlock::command::kSearchStatus, state.command);
    TEST_ASSERT_EQUAL_INT(tb::kStatePushBattery, state.battery);
    TEST_ASSERT_EQUAL_INT(tb::kStatePushState, static_cast<int>(state.state));
    TEST_ASSERT_FALSE(state.hasRecord);
    TEST_ASSERT_FALSE(ttlock::isLogPush(statePush));
    ttlock::Reply logPush{ttlock::command::kSearchStatus, 0x01, toBytes(tb::kLogPush)};
    const ttlock::LockEvent record = ttlock::parseLockEvent(logPush);
    TEST_ASSERT_TRUE(record.hasRecord);
    TEST_ASSERT_EQUAL_UINT32(tb::kLogPushUid, record.uid);
    TEST_ASSERT_EQUAL_UINT32(tb::kLogPushRecordId, record.recordId);
    assertTime(timeOf(tb::kLogPushTime), record.time, "log push time");
    TEST_ASSERT_EQUAL(ttlock::LockState::Unknown, record.state);
    TEST_ASSERT_TRUE(ttlock::isLogPush(logPush));
    ttlock::Reply other{0x62, 0x01, Bytes{0x5A}};
    const ttlock::LockEvent unknown = ttlock::parseLockEvent(other);
    TEST_ASSERT_EQUAL_HEX8(0x62, unknown.command);
    TEST_ASSERT_EQUAL_INT(-1, unknown.battery);
    TEST_ASSERT_EQUAL_UINT(1, unknown.data.size());
}

static void test_lock_error_codes_have_names() {
    TEST_ASSERT_EQUAL_STRING("no_permission", ttlock::lockErrorName(0x02));
    TEST_ASSERT_EQUAL_STRING("wrong_id_or_password", ttlock::lockErrorName(0x03));
    TEST_ASSERT_EQUAL_STRING("no_power", ttlock::lockErrorName(0x0A));
    TEST_ASSERT_EQUAL_STRING("key_flag_invalid", ttlock::lockErrorName(0x0D));
    TEST_ASSERT_EQUAL_STRING("credential_not_found", ttlock::lockErrorName(0x1A));
    TEST_ASSERT_EQUAL_STRING("unknown", ttlock::lockErrorName(0x00));
    TEST_ASSERT_EQUAL_STRING("unknown", ttlock::lockErrorName(0x7E));
}

static void test_features_cover_kind3r_names_with_distinct_bits() {
    std::set<std::string> names;
    std::set<int> bits;
    for (ttlock::Feature feature : ttlock::kAllFeatures) {
        const char* name = ttlock::toString(feature);
        TEST_ASSERT_NOT_NULL(name);
        TEST_ASSERT_NOT_EQUAL(0, std::strcmp(name, "unknown"));
        names.insert(name);
        bits.insert(static_cast<int>(feature));
        TEST_ASSERT_TRUE(ttlock::hasFeature(ttlock::featureBit(feature), feature));
    }
    TEST_ASSERT_EQUAL_UINT(37, names.size());
    TEST_ASSERT_EQUAL_UINT(37, bits.size());
    TEST_ASSERT_EQUAL_STRING("reset_button", ttlock::toString(ttlock::Feature::ResetButton));
    TEST_ASSERT_EQUAL_HEX64(1ULL << 42, ttlock::featureBit(ttlock::Feature::AccessoryBattery));
    TEST_ASSERT_FALSE(ttlock::hasFeature(0, ttlock::Feature::Passcode));
}

int main() {
    UNITY_BEGIN();
    RUN_TEST(test_reply_splits_echo_status_and_data);
    RUN_TEST(test_aes_key_request_is_sciener_like_kind3r_not_the_ttlock_ble_vendor_token);
    RUN_TEST(test_aes_key_reply_needs_exactly_16_bytes);
    RUN_TEST(test_add_admin_matches_kind3r);
    RUN_TEST(test_add_admin_is_accepted_only_when_the_lock_echoes_sciener);
    RUN_TEST(test_check_admin_matches_kind3r_and_ttlock_ble);
    RUN_TEST(test_check_random_sums_modulo_2_32);
    RUN_TEST(test_check_user_time_matches_kind3r_and_ttlock_ble);
    RUN_TEST(test_ps_from_lock_is_the_first_four_bytes_big_endian);
    RUN_TEST(test_unlock_and_lock_payloads_match_kind3r_and_ttlock_ble);
    RUN_TEST(test_operation_result_matches_kind3r_unlock_reply);
    RUN_TEST(test_operation_result_with_battery_only_or_nothing);
    RUN_TEST(test_calibrate_time_is_six_decimal_bytes);
    RUN_TEST(test_epoch_seconds_become_civil_time);
    RUN_TEST(test_status_request_and_reply);
    RUN_TEST(test_features_stitch_words_low_word_first);
    RUN_TEST(test_device_info_requests_and_strings);
    RUN_TEST(test_admin_passcode_digits_are_raw_values_like_kind3r);
    RUN_TEST(test_admin_code_parses_like_kind3r_where_kind3r_is_consistent);
    RUN_TEST(test_admin_code_takes_the_declared_length_where_kind3r_drops_two_digits);
    RUN_TEST(test_admin_code_refuses_short_or_non_digit_replies);
    RUN_TEST(test_init_passwords_matches_kind3r);
    RUN_TEST(test_empty_payload_commands_match_kind3r);
    RUN_TEST(test_passcode_add_follows_ttlock_ble);
    RUN_TEST(test_passcode_update_delete_clear_and_list_requests);
    RUN_TEST(test_passcode_pages_match_ttlock_ble);
    RUN_TEST(test_passcode_page_matches_kind3r_capture);
    RUN_TEST(test_passcode_page_with_two_items_and_an_unknown_type);
    RUN_TEST(test_malformed_passcode_pages_are_rejected);
    RUN_TEST(test_fingerprint_requests_match_kind3r_and_ttlock_ble);
    RUN_TEST(test_fingerprint_pages_match_ttlock_ble_and_kind3r);
    RUN_TEST(test_fingerprint_enroll_replies_match_kind3r);
    RUN_TEST(test_card_requests_match_kind3r_and_ttlock_ble);
    RUN_TEST(test_eight_byte_card_delete_uses_the_long_id_kind3r_drops);
    RUN_TEST(test_card_pages_match_ttlock_ble_and_kind3r);
    RUN_TEST(test_card_enroll_replies_match_kind3r);
    RUN_TEST(test_kind3r_card_capture_decodes_to_enter_add_mode);
    RUN_TEST(test_cyclic_commands_match_kind3r);
    RUN_TEST(test_cyclic_card_numbers_from_2_31_go_out_unsigned_where_kind3r_throws);
    RUN_TEST(test_passage_mode_requests_match_kind3r);
    RUN_TEST(test_passage_pages_parse_every_seven_byte_entry);
    RUN_TEST(test_sound_commands_match_kind3r_and_ttlock_ble);
    RUN_TEST(test_auto_lock_commands_match_kind3r_and_ttlock_ble);
    RUN_TEST(test_remote_unlock_and_screen_passcode_match_kind3r);
    RUN_TEST(test_screen_passcode_set_and_reply_match_kind3r);
    RUN_TEST(test_switch_commands_carry_the_item_mask_twice_when_enabling);
    RUN_TEST(test_log_requests_match_kind3r_and_ttlock_ble);
    RUN_TEST(test_log_records_match_ttlock_ble);
    RUN_TEST(test_log_page_matches_kind3r_and_tolerates_a_truncated_record);
    RUN_TEST(test_push_events_match_ttlock_ble);
    RUN_TEST(test_lock_error_codes_have_names);
    RUN_TEST(test_features_cover_kind3r_names_with_distinct_bits);
    return UNITY_END();
}
