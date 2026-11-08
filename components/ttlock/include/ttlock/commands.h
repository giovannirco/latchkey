// SPDX-License-Identifier: GPL-3.0-or-later
#pragma once

#include <array>
#include <cstddef>
#include <cstdint>
#include <string>
#include <vector>

#include "ttlock/bytes.h"
#include "ttlock/types.h"

namespace ttlock {

namespace command {

inline constexpr uint8_t kSearchDeviceFeature = 0x01;
inline constexpr uint8_t kManageKeyboardPassword = 0x03;
inline constexpr uint8_t kManageIcCard = 0x05;
inline constexpr uint8_t kManageFingerprint = 0x06;
inline constexpr uint8_t kPasscodeList = 0x07;
inline constexpr uint8_t kSearchStatus = 0x14;
inline constexpr uint8_t kGetAesKey = 0x19;
inline constexpr uint8_t kGetOperateLog = 0x25;
inline constexpr uint8_t kCheckRandom = 0x30;
inline constexpr uint8_t kInitPasswords = 0x31;
inline constexpr uint8_t kAutoLockManage = 0x36;
inline constexpr uint8_t kControlRemoteUnlock = 0x37;
inline constexpr uint8_t kCheckAdmin = 0x41;
inline constexpr uint8_t kTimeCalibrate = 0x43;
inline constexpr uint8_t kInitialization = 0x45;
inline constexpr uint8_t kUnlock = 0x47;
inline constexpr uint8_t kResetLock = 0x52;
inline constexpr uint8_t kSetAdminKeyboardPassword = 0x53;
inline constexpr uint8_t kResponse = 0x54;
inline constexpr uint8_t kCheckUserTime = 0x55;
inline constexpr uint8_t kAddAdmin = 0x56;
inline constexpr uint8_t kOperateFinished = 0x57;
inline constexpr uint8_t kLock = 0x58;
inline constexpr uint8_t kShowPassword = 0x59;
inline constexpr uint8_t kAudioManage = 0x62;
inline constexpr uint8_t kGetAdminCode = 0x65;
inline constexpr uint8_t kConfigurePassageMode = 0x66;
inline constexpr uint8_t kSwitch = 0x68;
inline constexpr uint8_t kCyclic = 0x70;
inline constexpr uint8_t kReadDeviceInfo = 0x90;

}

inline constexpr uint8_t kReplySuccess = 0x01;
inline constexpr uint16_t kLogSinceLastRead = 0xFFFF;
inline constexpr size_t kCodeSecretCount = 10;
inline constexpr uint32_t kSwitchTamperAlert = 0x01;
inline constexpr uint32_t kSwitchResetButton = 0x02;
inline constexpr uint32_t kSwitchPrivacyLock = 0x04;

struct Reply {
    uint8_t command = 0;
    uint8_t status = 0;
    Bytes data;
};

bool parseReply(const Bytes& plain, Reply& out);

LockTime lockTimeFromEpoch(int64_t seconds);

Bytes buildGetAesKey();
bool parseAesKey(const Bytes& data, AesKey& out);
Bytes buildAddAdmin(uint32_t adminPs, uint32_t unlockKey);
bool isAddAdminAccepted(const Bytes& data);
Bytes buildCalibrateTime(const LockTime& localTime);
Bytes buildCheckAdmin(uint32_t adminPs, uint32_t lockFlagPos, uint32_t uid);
Bytes buildCheckRandom(uint32_t psFromLock, uint32_t unlockKey);
Bytes buildCheckUserTime(uint32_t lockFlagPos, uint32_t uid);
bool parsePsFromLock(const Bytes& data, uint32_t& out);
Bytes buildLockControl(uint32_t psFromLock, uint32_t unlockKey, uint32_t utcSeconds);
OperationResult parseOperationResult(const Bytes& data);
Bytes buildSearchStatus();
bool parseLockStatus(const Bytes& data, LockStatus& out);
bool parseFeatures(const Bytes& data, uint64_t& out);

enum class DeviceInfoItem : uint8_t {
    Model = 1,
    Hardware = 2,
    Firmware = 3,
    ManufactureDate = 4,
};

Bytes buildReadDeviceInfo(DeviceInfoItem item);
std::string parseDeviceInfoString(const Bytes& data);
Bytes buildSetAdminPasscode(const std::string& digits);

struct CodeSecret {
    uint16_t code = 0;
    uint64_t secret = 0;
};

Bytes buildInitPasswords(uint8_t yearOfCentury, const std::array<CodeSecret, kCodeSecretCount>& seeds);

Bytes buildPasscodeAdd(const Passcode& passcode);
Bytes buildPasscodeUpdate(const std::string& oldCode, const Passcode& passcode);
Bytes buildPasscodeDelete(PasscodeType type, const std::string& code);
Bytes buildPasscodeClear();
Bytes buildPasscodeListRequest(uint16_t sequence);

struct PasscodePage {
    std::vector<Passcode> items;
    uint16_t next = 0;
    bool last = true;
};

bool parsePasscodePage(const Bytes& data, PasscodePage& out);

Bytes buildFingerprintListRequest(uint16_t sequence);
Bytes buildFingerprintEnrollStart();
Bytes buildFingerprintSetValidity(uint64_t id, const Validity& validity);
Bytes buildFingerprintDelete(uint64_t id);
Bytes buildFingerprintClear();

Bytes buildCardListRequest(uint16_t sequence);
Bytes buildCardEnrollStart();
Bytes buildCardSetValidity(uint64_t number, const Validity& validity);
Bytes buildCardDelete(uint64_t number);
Bytes buildCardClear();

struct CredentialPage {
    std::vector<Credential> items;
    uint16_t next = 0;
    bool last = true;
};

bool parseFingerprintPage(const Bytes& data, CredentialPage& out);
bool parseCardPage(const Bytes& data, CredentialPage& out);

enum class EnrollStatus : uint8_t {
    Added = 0x01,
    Waiting = 0x02,
    Progress = 0x03,
    ReceiveTemplate = 0x04,
};

struct EnrollReply {
    EnrollStatus status = EnrollStatus::Waiting;
    uint64_t id = 0;
};

bool parseFingerprintEnrollReply(const Bytes& data, EnrollReply& out);
bool parseCardEnrollReply(const Bytes& data, EnrollReply& out);

Bytes buildCardCycleAdd(uint64_t number, const WeeklyCycle& cycle);
Bytes buildCardCycleClear(uint64_t number);
Bytes buildFingerprintCycleAdd(uint64_t id, const WeeklyCycle& cycle);
Bytes buildFingerprintCycleClear(uint64_t id);

Bytes buildAutoLockQuery();
Bytes buildAutoLockSet(uint16_t seconds);
bool parseAutoLock(const Bytes& data, AutoLockSetting& out);

Bytes buildPassageQuery(uint8_t sequence);
Bytes buildPassageAdd(const PassageMode& mode);
Bytes buildPassageDelete(const PassageMode& mode);
Bytes buildPassageClear();

struct PassagePage {
    std::vector<PassageMode> items;
    uint8_t next = 0;
    bool last = true;
};

bool parsePassagePage(const Bytes& data, PassagePage& out);

Bytes buildSoundQuery();
Bytes buildSoundSet(bool enabled);
Bytes buildSoundVolumeSet(uint8_t level);
bool parseSound(const Bytes& data, SoundSetting& out);

Bytes buildSwitchQuery();
Bytes buildSwitchSet(uint32_t item, bool enabled);
bool parseSwitchState(const Bytes& data, uint32_t& out);

Bytes buildRemoteUnlockQuery();
Bytes buildRemoteUnlockSet(bool enabled);
bool parseRemoteUnlock(const Bytes& data, bool& out);

Bytes buildScreenPasscodeQuery();
Bytes buildScreenPasscodeSet(bool visible);
bool parseScreenPasscode(const Bytes& data, bool& visible);

Bytes buildOperateLogRequest(uint16_t sequence);

struct LogPage {
    std::vector<LogEntry> entries;
    uint16_t sequence = 0;
};

bool parseLogPage(const Bytes& data, LogPage& out);
LockEvent parseLockEvent(const Reply& reply);
bool isLogPush(const Reply& reply);

}
