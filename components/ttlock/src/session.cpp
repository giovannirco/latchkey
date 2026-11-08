// SPDX-License-Identifier: GPL-3.0-or-later
// Ported from kind3r/ttlock-sdk-js (GPL-3.0) src/device/TTLock.ts and src/device/TTLockApi.ts: the pairing
// sequence of initLock, the admin login of macro_adminLogin and the operation flows. Matching replies on the
// echoed opcode, the admin handshake per call and the operation-log paging follow roquerodrigo/ttlock-ble (MIT)
// client.py and ble/transport.py.
#include "ttlock/session.h"

#include <array>
#include <set>
#include <utility>

#include "ttlock/aes.h"
#include "ttlock/commands.h"

namespace ttlock {
namespace {

constexpr uint32_t kSecretBound = 999999999;
constexpr uint32_t kCodeBound = 1071;
constexpr uint32_t kDigitBound = 10;
constexpr size_t kSecretDigits = 10;
constexpr size_t kMinPasscodeDigits = 4;
constexpr size_t kMaxPasscodeDigits = 9;
constexpr uint8_t kMinVolume = 1;
constexpr uint8_t kMaxVolume = 5;
constexpr uint8_t kFirstV3ProtocolType = 5;
constexpr uint16_t kFirstYear = 2000;
constexpr uint16_t kLastYear = 2099;
constexpr uint8_t kLastWeekday = 7;
constexpr uint8_t kLastMonthDay = 31;

bool usesV3Frames(const LockVersion& version) {
    return version.protocolType >= kFirstV3ProtocolType;
}

bool isDigits(const std::string& code, size_t minimum, size_t maximum) {
    if (code.size() < minimum || code.size() > maximum) {
        return false;
    }
    for (char digit : code) {
        if (digit < '0' || digit > '9') {
            return false;
        }
    }
    return true;
}

bool isPasscode(const std::string& code) {
    return isDigits(code, kMinPasscodeDigits, kMaxPasscodeDigits);
}

bool isKnownPasscodeType(PasscodeType type) {
    switch (type) {
        case PasscodeType::Permanent:
        case PasscodeType::Count:
        case PasscodeType::Period:
        case PasscodeType::Cyclic:
            return true;
    }
    return false;
}

bool isLeapYear(uint16_t year) {
    return (year % 4 == 0 && year % 100 != 0) || year % 400 == 0;
}

uint8_t daysInMonth(uint16_t year, uint8_t month) {
    constexpr uint8_t kDays[] = {31, 28, 31, 30, 31, 30, 31, 31, 30, 31, 30, 31};
    return month == 2 && isLeapYear(year) ? 29 : kDays[month - 1];
}

bool isValidTime(const LockTime& time) {
    return time.year >= kFirstYear && time.year <= kLastYear && time.month >= 1 && time.month <= 12 &&
           time.day >= 1 && time.day <= daysInMonth(time.year, time.month) && time.hour <= 23 && time.minute <= 59 &&
           time.second <= 59;
}

uint64_t ordinal(const LockTime& time) {
    return (((uint64_t{time.year} * 13 + time.month) * 32 + time.day) * 24 + time.hour) * 60 + time.minute;
}

bool isValidValidity(const Validity& validity) {
    return isValidTime(validity.start) && isValidTime(validity.end) && ordinal(validity.start) <= ordinal(validity.end);
}

bool isValidPassage(const PassageMode& mode) {
    const bool weekly = mode.type == PassageType::Weekly && mode.weekOrDay <= kLastWeekday;
    const bool monthly = mode.type == PassageType::Monthly && mode.weekOrDay >= 1 && mode.weekOrDay <= kLastMonthDay;
    return (weekly || monthly) && mode.startHour <= 23 && mode.endHour <= 23 && mode.startMinute <= 59 &&
           mode.endMinute <= 59;
}

Status checkWritablePasscode(const Passcode& passcode) {
    if (!isKnownPasscodeType(passcode.type) || !isPasscode(passcode.code) || !isValidValidity(passcode.validity)) {
        return Status::InvalidArgument;
    }
    return passcode.type == PasscodeType::Cyclic ? Status::Unsupported : Status::Ok;
}

Bytes noPayload() {
    return Bytes{};
}

struct OptionalRead {
    uint64_t features;
    uint8_t command;
    Bytes (*payload)();
};

const OptionalRead kPairingReads[] = {
    {featureBit(Feature::ResetButton) | featureBit(Feature::TamperAlert) | featureBit(Feature::PrivacyLock),
     command::kSwitch, buildSwitchQuery},
    {featureBit(Feature::AudioManagement), command::kAudioManage, buildSoundQuery},
    {featureBit(Feature::PasswordDisplayOrHide), command::kShowPassword, buildScreenPasscodeQuery},
    {featureBit(Feature::AutoLock), command::kAutoLockManage, buildAutoLockQuery},
    {featureBit(Feature::GetAdminCode), command::kGetAdminCode, noPayload},
};

template <typename Page, typename Item, typename Fetch>
Status collectPages(Fetch&& fetch, std::vector<Item>& out) {
    std::vector<Item> items;
    uint16_t sequence = 0;
    for (size_t pages = 0; pages < kMaxListPages; ++pages) {
        Page page;
        const Status status = fetch(sequence, page);
        if (status != Status::Ok) {
            return status;
        }
        items.insert(items.end(), page.items.begin(), page.items.end());
        if (page.last) {
            out = std::move(items);
            return Status::Ok;
        }
        if (page.next == sequence) {
            return Status::BadResponse;
        }
        sequence = page.next;
    }
    return Status::BadResponse;
}

}

Session::Session(Transport& transport, Clock& clock, Random& random)
    : transport_(transport), clock_(clock), random_(random) {}

void Session::setEventSink(EventSink sink) {
    sink_ = std::move(sink);
}

const LockKeys& Session::keys() const {
    return keys_;
}

uint8_t Session::lockErrorCode() const {
    return lockErrorCode_;
}

Status Session::attach(const LockKeys& keys) {
    attached_ = false;
    lockErrorCode_ = 0;
    if (!usesV3Frames(keys.version)) {
        return Status::Unsupported;
    }
    keys_ = keys;
    attached_ = true;
    return Status::Ok;
}

Status Session::requireKeys() const {
    return attached_ ? Status::Ok : Status::NotPaired;
}

Status Session::requireFeature(Feature feature) const {
    const Status status = requireKeys();
    if (status != Status::Ok) {
        return status;
    }
    return hasFeature(keys_.features, feature) ? Status::Ok : Status::Unsupported;
}

bool Session::timeUsable() {
    return clock_.synced() && clock_.utcSeconds() >= kEarliestUsableUtc;
}

LockTime Session::localNow() {
    return lockTimeFromEpoch(clock_.utcSeconds() + clock_.utcOffsetSeconds());
}

uint32_t Session::uniformBelow(uint32_t bound) {
    const uint64_t range = uint64_t{1} << 32;
    const uint64_t limit = range - range % bound;
    while (true) {
        uint8_t bytes[4];
        random_.fill(bytes, sizeof(bytes));
        const uint64_t value = uint64_t{bytes[0]} << 24 | uint64_t{bytes[1]} << 16 | uint64_t{bytes[2]} << 8 | bytes[3];
        if (value < limit) {
            return static_cast<uint32_t>(value % bound);
        }
    }
}

uint32_t Session::randomSecret() {
    return 1 + uniformBelow(kSecretBound);
}

std::string Session::randomDigits(size_t count) {
    std::string digits;
    digits.reserve(count);
    for (size_t i = 0; i < count; ++i) {
        digits.push_back(static_cast<char>('0' + uniformBelow(kDigitBound)));
    }
    return digits;
}

Status Session::sendCommand(uint8_t command, const Bytes& payload) {
    lockErrorCode_ = 0;
    const Bytes frame = encodeFrame(keys_.version, command, payload, keys_.aesKey);
    if (frame.empty()) {
        return Status::InvalidArgument;
    }
    return transport_.send(frame);
}

void Session::deliver(const Reply& reply) {
    if (sink_) {
        sink_(parseLockEvent(reply));
    }
}

Status Session::awaitPlain(uint8_t command, uint32_t timeoutMs, Bytes& plain) {
    for (size_t frames = 0; frames < kMaxFramesPerReply; ++frames) {
        Bytes raw;
        const Status received = transport_.receive(raw, timeoutMs);
        if (received != Status::Ok) {
            return received;
        }
        DecodedFrame frame;
        const Status decoded = decodeFrame(raw, keys_.aesKey, frame);
        if (decoded != Status::Ok) {
            return decoded;
        }
        Reply reply;
        if (!frame.payload.empty()) {
            if (!parseReply(frame.payload, reply)) {
                return Status::BadResponse;
            }
            const bool pushed = command == command::kSearchStatus && isLogPush(reply);
            if (reply.command != command || pushed) {
                if (frame.crcOk) {
                    deliver(reply);
                }
                continue;
            }
        }
        if (!frame.crcOk) {
            return Status::BadCrc;
        }
        plain = std::move(frame.payload);
        return Status::Ok;
    }
    return Status::Timeout;
}

Status Session::awaitData(uint8_t command, uint32_t timeoutMs, Bytes& data) {
    Bytes plain;
    const Status status = awaitPlain(command, timeoutMs, plain);
    if (status != Status::Ok) {
        return status;
    }
    Reply reply;
    if (!parseReply(plain, reply)) {
        return Status::BadResponse;
    }
    if (reply.status != kReplySuccess) {
        lockErrorCode_ = reply.data.empty() ? 0 : reply.data[0];
        return Status::LockError;
    }
    data = std::move(reply.data);
    return Status::Ok;
}

Status Session::request(uint8_t command, const Bytes& payload, Bytes& data) {
    const Status sent = sendCommand(command, payload);
    if (sent != Status::Ok) {
        return sent;
    }
    return awaitData(command, kCommandTimeoutMs, data);
}

Status Session::optionalRead(uint8_t command, const Bytes& payload) {
    Bytes data;
    const Status status = request(command, payload, data);
    return status == Status::LockError ? Status::Ok : status;
}

Status Session::adminLogin() {
    Bytes data;
    Status status = request(command::kCheckAdmin, buildCheckAdmin(keys_.adminPs, keys_.lockFlagPos, 0), data);
    if (status != Status::Ok) {
        return status;
    }
    uint32_t psFromLock = 0;
    if (!parsePsFromLock(data, psFromLock)) {
        return Status::BadResponse;
    }
    return request(command::kCheckRandom, buildCheckRandom(psFromLock, keys_.unlockKey), data);
}

Status Session::beginAdmin() {
    const Status status = requireKeys();
    return status == Status::Ok ? adminLogin() : status;
}

Status Session::beginAdmin(Feature feature) {
    const Status status = requireFeature(feature);
    return status == Status::Ok ? adminLogin() : status;
}

Status Session::adminRequest(Feature feature, uint8_t command, const Bytes& payload, Bytes& data) {
    const Status status = beginAdmin(feature);
    return status == Status::Ok ? request(command, payload, data) : status;
}

Status Session::pair(const LockVersion& version, LockKeys& out, PersistCallback persistEarly) {
    if (!usesV3Frames(version)) {
        return Status::Unsupported;
    }
    if (!timeUsable()) {
        return Status::TimeUnsynced;
    }
    attached_ = false;
    LockKeys fresh;
    fresh.mac = out.mac;
    fresh.version = version;
    fresh.aesKey = kDefaultAesKey;
    keys_ = std::move(fresh);
    Status status = initialize();
    if (status != Status::Ok) {
        return status;
    }
    status = fetchAesKey();
    if (status != Status::Ok) {
        return status;
    }
    keys_.adminPs = randomSecret();
    keys_.unlockKey = randomSecret();
    status = addAdmin();
    if (status == Status::LockError) {
        return status;
    }
    attached_ = true;
    out = keys_;
    if (persistEarly) {
        persistEarly(keys_);
    }
    if (status != Status::Ok) {
        return Status::PairIncomplete;
    }
    status = finishPairing();
    out = keys_;
    if (status != Status::Ok) {
        return Status::PairIncomplete;
    }
    if (persistEarly) {
        persistEarly(keys_);
    }
    return Status::Ok;
}

Status Session::initialize() {
    const Status sent = sendCommand(command::kInitialization, noPayload());
    if (sent != Status::Ok) {
        return sent;
    }
    Bytes raw;
    const Status received = transport_.receive(raw, kCommandTimeoutMs);
    if (received != Status::Ok) {
        return received;
    }
    DecodedFrame frame;
    const Status decoded = decodeFrame(raw, keys_.aesKey, frame);
    if (decoded != Status::Ok) {
        return decoded;
    }
    return frame.crcOk ? Status::Ok : Status::BadCrc;
}

Status Session::fetchAesKey() {
    Bytes data;
    const Status status = request(command::kGetAesKey, buildGetAesKey(), data);
    if (status != Status::Ok) {
        return status;
    }
    AesKey key{};
    if (!parseAesKey(data, key)) {
        return Status::BadResponse;
    }
    keys_.aesKey = key;
    return Status::Ok;
}

Status Session::addAdmin() {
    Bytes data;
    const Status status = request(command::kAddAdmin, buildAddAdmin(keys_.adminPs, keys_.unlockKey), data);
    if (status != Status::Ok) {
        return status;
    }
    return isAddAdminAccepted(data) ? Status::Ok : Status::BadResponse;
}

Status Session::finishPairing() {
    Status status = optionalRead(command::kTimeCalibrate, buildCalibrateTime(localNow()));
    if (status != Status::Ok) {
        return status;
    }
    Bytes data;
    status = request(command::kSearchDeviceFeature, noPayload(), data);
    if (status != Status::Ok) {
        return status;
    }
    if (!parseFeatures(data, keys_.features)) {
        return Status::BadResponse;
    }
    for (const OptionalRead& read : kPairingReads) {
        if ((keys_.features & read.features) == 0) {
            continue;
        }
        status = optionalRead(read.command, read.payload());
        if (status != Status::Ok) {
            return status;
        }
    }
    const std::string adminPasscode = randomDigits(kAdminPasscodeDigits);
    status = request(command::kSetAdminKeyboardPassword, buildSetAdminPasscode(adminPasscode), data);
    if (status != Status::Ok) {
        return status;
    }
    keys_.adminPasscode = adminPasscode;
    status = initPasswords();
    if (status != Status::Ok) {
        return status;
    }
    if (hasFeature(keys_.features, Feature::ConfigGatewayUnlock)) {
        status = optionalRead(command::kControlRemoteUnlock, buildRemoteUnlockQuery());
        if (status != Status::Ok) {
            return status;
        }
    }
    return request(command::kOperateFinished, noPayload(), data);
}

Status Session::initPasswords() {
    const LockTime now = localNow();
    const bool newYearsDay = now.month == 1 && now.day == 1;
    const uint16_t year = newYearsDay ? static_cast<uint16_t>(now.year - 1) : now.year;
    std::array<CodeSecret, kCodeSecretCount> seeds{};
    for (CodeSecret& seed : seeds) {
        seed.code = static_cast<uint16_t>(uniformBelow(kCodeBound));
        for (size_t i = 0; i < kSecretDigits; ++i) {
            seed.secret = seed.secret * kDigitBound + uniformBelow(kDigitBound);
        }
    }
    Bytes data;
    return request(command::kInitPasswords, buildInitPasswords(static_cast<uint8_t>(year % 100), seeds), data);
}

Status Session::unlock(OperationResult& out) {
    return controlLock(command::kUnlock, out);
}

Status Session::lock(OperationResult& out) {
    return controlLock(command::kLock, out);
}

Status Session::controlLock(uint8_t command, OperationResult& out) {
    Status status = requireKeys();
    if (status != Status::Ok) {
        return status;
    }
    if (!timeUsable()) {
        return Status::TimeUnsynced;
    }
    Bytes data;
    status = request(command::kCheckUserTime, buildCheckUserTime(keys_.lockFlagPos, 0), data);
    if (status != Status::Ok) {
        return status;
    }
    uint32_t psFromLock = 0;
    if (!parsePsFromLock(data, psFromLock)) {
        return Status::BadResponse;
    }
    const auto utcSeconds = static_cast<uint32_t>(clock_.utcSeconds());
    status = request(command, buildLockControl(psFromLock, keys_.unlockKey, utcSeconds), data);
    if (status != Status::Ok) {
        return status;
    }
    out = parseOperationResult(data);
    return Status::Ok;
}

Status Session::status(LockStatus& out) {
    Status result = requireKeys();
    if (result != Status::Ok) {
        return result;
    }
    Bytes data;
    result = request(command::kSearchStatus, buildSearchStatus(), data);
    if (result != Status::Ok) {
        return result;
    }
    return parseLockStatus(data, out) ? Status::Ok : Status::BadResponse;
}

Status Session::deviceInfo(DeviceInfo& out) {
    Status status = beginAdmin();
    if (status != Status::Ok) {
        return status;
    }
    DeviceInfo info;
    const std::pair<DeviceInfoItem, std::string*> items[] = {
        {DeviceInfoItem::Model, &info.model},
        {DeviceInfoItem::Hardware, &info.hardware},
        {DeviceInfoItem::Firmware, &info.firmware},
        {DeviceInfoItem::ManufactureDate, &info.manufactureDate},
    };
    for (const auto& [item, field] : items) {
        Bytes data;
        status = request(command::kReadDeviceInfo, buildReadDeviceInfo(item), data);
        if (status != Status::Ok) {
            return status;
        }
        *field = parseDeviceInfoString(data);
    }
    out = std::move(info);
    return Status::Ok;
}

Status Session::features(uint64_t& out) {
    Status status = beginAdmin();
    if (status != Status::Ok) {
        return status;
    }
    Bytes data;
    status = request(command::kSearchDeviceFeature, noPayload(), data);
    if (status != Status::Ok) {
        return status;
    }
    uint64_t mask = 0;
    if (!parseFeatures(data, mask)) {
        return Status::BadResponse;
    }
    keys_.features = mask;
    out = mask;
    return Status::Ok;
}

Status Session::syncTime() {
    Status status = requireKeys();
    if (status != Status::Ok) {
        return status;
    }
    if (!timeUsable()) {
        return Status::TimeUnsynced;
    }
    status = adminLogin();
    if (status != Status::Ok) {
        return status;
    }
    Bytes data;
    return request(command::kTimeCalibrate, buildCalibrateTime(localNow()), data);
}

Status Session::autolockGet(AutoLockSetting& out) {
    Bytes data;
    const Status status = adminRequest(Feature::AutoLock, command::kAutoLockManage, buildAutoLockQuery(), data);
    if (status != Status::Ok) {
        return status;
    }
    return parseAutoLock(data, out) ? Status::Ok : Status::BadResponse;
}

Status Session::autolockSet(uint16_t seconds) {
    Bytes data;
    return adminRequest(Feature::AutoLock, command::kAutoLockManage, buildAutoLockSet(seconds), data);
}

Status Session::passageList(std::vector<PassageMode>& out) {
    const Status status = beginAdmin(Feature::PassageMode);
    if (status != Status::Ok) {
        return status;
    }
    return collectPages<PassagePage>(
        [this](uint16_t sequence, PassagePage& page) {
            Bytes data;
            const Status fetched =
                request(command::kConfigurePassageMode, buildPassageQuery(static_cast<uint8_t>(sequence)), data);
            if (fetched != Status::Ok) {
                return fetched;
            }
            return parsePassagePage(data, page) ? Status::Ok : Status::BadResponse;
        },
        out);
}

Status Session::passageAdd(const PassageMode& mode) {
    const Status status = requireFeature(Feature::PassageMode);
    if (status != Status::Ok) {
        return status;
    }
    if (!isValidPassage(mode)) {
        return Status::InvalidArgument;
    }
    Bytes data;
    return adminRequest(Feature::PassageMode, command::kConfigurePassageMode, buildPassageAdd(mode), data);
}

Status Session::passageDelete(const PassageMode& mode) {
    const Status status = requireFeature(Feature::PassageMode);
    if (status != Status::Ok) {
        return status;
    }
    if (!isValidPassage(mode)) {
        return Status::InvalidArgument;
    }
    Bytes data;
    return adminRequest(Feature::PassageMode, command::kConfigurePassageMode, buildPassageDelete(mode), data);
}

Status Session::passageClear() {
    Bytes data;
    return adminRequest(Feature::PassageMode, command::kConfigurePassageMode, buildPassageClear(), data);
}

Status Session::passcodeList(std::vector<Passcode>& out) {
    const Status status = beginAdmin(Feature::Passcode);
    if (status != Status::Ok) {
        return status;
    }
    return collectPages<PasscodePage>(
        [this](uint16_t sequence, PasscodePage& page) {
            Bytes data;
            const Status fetched = request(command::kPasscodeList, buildPasscodeListRequest(sequence), data);
            if (fetched != Status::Ok) {
                return fetched;
            }
            return parsePasscodePage(data, page) ? Status::Ok : Status::BadResponse;
        },
        out);
}

Status Session::passcodeAdd(const Passcode& passcode) {
    Status status = requireFeature(Feature::Passcode);
    if (status != Status::Ok) {
        return status;
    }
    status = checkWritablePasscode(passcode);
    if (status != Status::Ok) {
        return status;
    }
    Bytes data;
    return adminRequest(Feature::Passcode, command::kManageKeyboardPassword, buildPasscodeAdd(passcode), data);
}

Status Session::passcodeUpdate(const std::string& oldCode, const Passcode& passcode) {
    Status status = requireFeature(Feature::Passcode);
    if (status != Status::Ok) {
        return status;
    }
    if (!isPasscode(oldCode)) {
        return Status::InvalidArgument;
    }
    status = checkWritablePasscode(passcode);
    if (status != Status::Ok) {
        return status;
    }
    Bytes data;
    return adminRequest(Feature::Passcode, command::kManageKeyboardPassword, buildPasscodeUpdate(oldCode, passcode),
                        data);
}

Status Session::passcodeDelete(PasscodeType type, const std::string& code) {
    const Status status = requireFeature(Feature::Passcode);
    if (status != Status::Ok) {
        return status;
    }
    if (!isKnownPasscodeType(type) || !isPasscode(code)) {
        return Status::InvalidArgument;
    }
    Bytes data;
    return adminRequest(Feature::Passcode, command::kManageKeyboardPassword, buildPasscodeDelete(type, code), data);
}

Status Session::passcodeClear() {
    Bytes data;
    return adminRequest(Feature::Passcode, command::kManageKeyboardPassword, buildPasscodeClear(), data);
}

Status Session::setAdminPasscode(const std::string& code) {
    Status status = requireFeature(Feature::Passcode);
    if (status != Status::Ok) {
        return status;
    }
    if (!isPasscode(code)) {
        return Status::InvalidArgument;
    }
    Bytes data;
    status = adminRequest(Feature::Passcode, command::kSetAdminKeyboardPassword, buildSetAdminPasscode(code), data);
    if (status == Status::Ok) {
        keys_.adminPasscode = code;
    }
    return status;
}

Status Session::fingerprintList(std::vector<Credential>& out) {
    const Status status = beginAdmin(Feature::FingerPrint);
    if (status != Status::Ok) {
        return status;
    }
    return collectPages<CredentialPage>(
        [this](uint16_t sequence, CredentialPage& page) {
            Bytes data;
            const Status fetched = request(command::kManageFingerprint, buildFingerprintListRequest(sequence), data);
            if (fetched != Status::Ok) {
                return fetched;
            }
            return parseFingerprintPage(data, page) ? Status::Ok : Status::BadResponse;
        },
        out);
}

Status Session::fingerprintEnroll(const Validity& validity, const EnrollCallback& progress, uint64_t& id) {
    const Status status = requireFeature(Feature::FingerPrint);
    if (status != Status::Ok) {
        return status;
    }
    if (!isValidValidity(validity)) {
        return Status::InvalidArgument;
    }
    const Status login = adminLogin();
    return login == Status::Ok ? enroll(true, validity, progress, id) : login;
}

Status Session::fingerprintDelete(uint64_t id) {
    Bytes data;
    return adminRequest(Feature::FingerPrint, command::kManageFingerprint, buildFingerprintDelete(id), data);
}

Status Session::fingerprintClear() {
    Bytes data;
    return adminRequest(Feature::FingerPrint, command::kManageFingerprint, buildFingerprintClear(), data);
}

Status Session::fingerprintSetValidity(uint64_t id, const Validity& validity) {
    const Status status = requireFeature(Feature::FingerPrint);
    if (status != Status::Ok) {
        return status;
    }
    if (!isValidValidity(validity)) {
        return Status::InvalidArgument;
    }
    Bytes data;
    return adminRequest(Feature::FingerPrint, command::kManageFingerprint, buildFingerprintSetValidity(id, validity),
                        data);
}

Status Session::cardList(std::vector<Credential>& out) {
    const Status status = beginAdmin(Feature::Ic);
    if (status != Status::Ok) {
        return status;
    }
    return collectPages<CredentialPage>(
        [this](uint16_t sequence, CredentialPage& page) {
            Bytes data;
            const Status fetched = request(command::kManageIcCard, buildCardListRequest(sequence), data);
            if (fetched != Status::Ok) {
                return fetched;
            }
            return parseCardPage(data, page) ? Status::Ok : Status::BadResponse;
        },
        out);
}

Status Session::cardEnroll(const Validity& validity, const EnrollCallback& progress, uint64_t& number) {
    const Status status = requireFeature(Feature::Ic);
    if (status != Status::Ok) {
        return status;
    }
    if (!isValidValidity(validity)) {
        return Status::InvalidArgument;
    }
    const Status login = adminLogin();
    return login == Status::Ok ? enroll(false, validity, progress, number) : login;
}

Status Session::cardDelete(uint64_t number) {
    Bytes data;
    return adminRequest(Feature::Ic, command::kManageIcCard, buildCardDelete(number), data);
}

Status Session::cardClear() {
    Bytes data;
    return adminRequest(Feature::Ic, command::kManageIcCard, buildCardClear(), data);
}

Status Session::cardSetValidity(uint64_t number, const Validity& validity) {
    const Status status = requireFeature(Feature::Ic);
    if (status != Status::Ok) {
        return status;
    }
    if (!isValidValidity(validity)) {
        return Status::InvalidArgument;
    }
    Bytes data;
    return adminRequest(Feature::Ic, command::kManageIcCard, buildCardSetValidity(number, validity), data);
}

Status Session::enroll(bool fingerprint, const Validity& validity, const EnrollCallback& progress, uint64_t& id) {
    const uint8_t command = fingerprint ? command::kManageFingerprint : command::kManageIcCard;
    const auto parse = fingerprint ? parseFingerprintEnrollReply : parseCardEnrollReply;
    Bytes data;
    Status status = request(command, fingerprint ? buildFingerprintEnrollStart() : buildCardEnrollStart(), data);
    uint8_t scans = 0;
    while (status == Status::Ok) {
        EnrollReply reply;
        if (!parse(data, reply)) {
            return Status::BadResponse;
        }
        if (reply.status == EnrollStatus::Added) {
            id = reply.id;
            const Bytes frame = fingerprint ? buildFingerprintSetValidity(id, validity)
                                            : buildCardSetValidity(id, validity);
            return request(command, frame, data);
        }
        if (reply.status == EnrollStatus::ReceiveTemplate) {
            return Status::BadResponse;
        }
        const bool scanned = reply.status == EnrollStatus::Progress;
        if (scanned) {
            ++scans;
        }
        if (progress) {
            progress(EnrollProgress{scanned ? EnrollStage::Scanned : EnrollStage::Waiting, scans});
        }
        status = awaitData(command, kEnrollStepTimeoutMs, data);
    }
    return status;
}

Status Session::fetchLog(uint16_t fromSequence, std::vector<LogEntry>& out) {
    const Status status = requireKeys();
    if (status != Status::Ok) {
        return status;
    }
    std::vector<LogEntry> entries;
    std::set<uint16_t> seen;
    uint16_t next = fromSequence;
    for (size_t pages = 0; pages < kMaxListPages; ++pages) {
        Bytes data;
        const Status fetched = request(command::kGetOperateLog, buildOperateLogRequest(next), data);
        if (fetched != Status::Ok) {
            return fetched;
        }
        LogPage page;
        if (!parseLogPage(data, page)) {
            return Status::BadResponse;
        }
        size_t fresh = 0;
        for (LogEntry& entry : page.entries) {
            if (seen.insert(entry.recordNumber).second) {
                entries.push_back(std::move(entry));
                ++fresh;
            }
        }
        if (fresh == 0 || page.sequence == 0 || page.sequence == next) {
            break;
        }
        next = page.sequence;
    }
    out = std::move(entries);
    return Status::Ok;
}

Status Session::soundGet(SoundSetting& out) {
    Bytes data;
    const Status status = adminRequest(Feature::AudioManagement, command::kAudioManage, buildSoundQuery(), data);
    if (status != Status::Ok) {
        return status;
    }
    return parseSound(data, out) ? Status::Ok : Status::BadResponse;
}

Status Session::soundSet(bool enabled) {
    Bytes data;
    return adminRequest(Feature::AudioManagement, command::kAudioManage, buildSoundSet(enabled), data);
}

Status Session::soundVolumeSet(uint8_t level) {
    const Status status = requireFeature(Feature::AudioManagement);
    if (status != Status::Ok) {
        return status;
    }
    if (level < kMinVolume || level > kMaxVolume) {
        return Status::InvalidArgument;
    }
    Bytes data;
    return adminRequest(Feature::AudioManagement, command::kAudioManage, buildSoundVolumeSet(level), data);
}

Status Session::switchGet(Feature feature, uint32_t item, bool& enabled) {
    Bytes data;
    const Status status = adminRequest(feature, command::kSwitch, buildSwitchQuery(), data);
    if (status != Status::Ok) {
        return status;
    }
    uint32_t value = 0;
    if (!parseSwitchState(data, value)) {
        return Status::BadResponse;
    }
    enabled = (value & item) != 0;
    return Status::Ok;
}

Status Session::switchSet(Feature feature, uint32_t item, bool enabled) {
    Bytes data;
    return adminRequest(feature, command::kSwitch, buildSwitchSet(item, enabled), data);
}

Status Session::resetButtonGet(bool& enabled) {
    return switchGet(Feature::ResetButton, kSwitchResetButton, enabled);
}

Status Session::resetButtonSet(bool enabled) {
    return switchSet(Feature::ResetButton, kSwitchResetButton, enabled);
}

Status Session::remoteUnlockGet(bool& enabled) {
    Bytes data;
    const Status status =
        adminRequest(Feature::ConfigGatewayUnlock, command::kControlRemoteUnlock, buildRemoteUnlockQuery(), data);
    if (status != Status::Ok) {
        return status;
    }
    return parseRemoteUnlock(data, enabled) ? Status::Ok : Status::BadResponse;
}

Status Session::remoteUnlockSet(bool enabled) {
    Bytes data;
    return adminRequest(Feature::ConfigGatewayUnlock, command::kControlRemoteUnlock, buildRemoteUnlockSet(enabled),
                        data);
}

Status Session::factoryReset() {
    Status status = beginAdmin();
    if (status != Status::Ok) {
        return status;
    }
    status = sendCommand(command::kResetLock, noPayload());
    if (status != Status::Ok) {
        return status;
    }
    Bytes plain;
    status = awaitPlain(command::kResetLock, kCommandTimeoutMs, plain);
    if (status != Status::Ok) {
        return status;
    }
    if (!plain.empty()) {
        Reply reply;
        if (!parseReply(plain, reply)) {
            return Status::BadResponse;
        }
        if (reply.status != kReplySuccess) {
            lockErrorCode_ = reply.data.empty() ? 0 : reply.data[0];
            return Status::LockError;
        }
    }
    attached_ = false;
    keys_ = LockKeys{};
    return Status::Ok;
}

Status Session::receiveEvent(uint32_t timeoutMs) {
    Status status = requireKeys();
    if (status != Status::Ok) {
        return status;
    }
    Bytes raw;
    status = transport_.receive(raw, timeoutMs);
    if (status != Status::Ok) {
        return status;
    }
    DecodedFrame frame;
    status = decodeFrame(raw, keys_.aesKey, frame);
    if (status != Status::Ok) {
        return status;
    }
    if (!frame.crcOk) {
        return Status::BadCrc;
    }
    Reply reply;
    if (!parseReply(frame.payload, reply)) {
        return Status::BadResponse;
    }
    deliver(reply);
    return Status::Ok;
}

}
