// SPDX-License-Identifier: GPL-3.0-or-later
// Ported from kind3r/ttlock-sdk-js (GPL-3.0) src/device/TTLock.ts and src/device/TTLockApi.ts: the passcode,
// fingerprint and IC card flows. The weekly-cycle limits follow src/api/ValidityInfo.ts isValidCycle.
#include "ttlock/session.h"

#include <string>
#include <vector>

#include "session_internal.h"
#include "ttlock/commands.h"

namespace ttlock {
namespace {

constexpr uint16_t kFirstYear = 2000;
constexpr uint16_t kLastYear = 2099;
constexpr uint8_t kFirstWeekDay = 1;
constexpr uint8_t kLastWeekDay = 7;
constexpr uint16_t kMinutesPerDay = 24 * 60;

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

Status checkWritablePasscode(const Passcode& passcode) {
    if (!isKnownPasscodeType(passcode.type) || !isPasscode(passcode.code) || !isValidValidity(passcode.validity)) {
        return Status::InvalidArgument;
    }
    return passcode.type == PasscodeType::Cyclic ? Status::Unsupported : Status::Ok;
}

bool isValidCycle(const WeeklyCycle& cycle) {
    return cycle.weekDay >= kFirstWeekDay && cycle.weekDay <= kLastWeekDay &&
           cycle.startMinuteOfDay <= kMinutesPerDay && cycle.endMinuteOfDay <= kMinutesPerDay;
}

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

Status Session::adminPasscodeGet(std::string& out) {
    Bytes data;
    const Status status = adminRequest(Feature::GetAdminCode, command::kGetAdminCode, noPayload(), data);
    if (status != Status::Ok) {
        return status;
    }
    return parseAdminCode(data, out) ? Status::Ok : Status::BadResponse;
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

Status Session::requireCyclic(Feature credential) const {
    const Status status = requireFeature(credential);
    return status == Status::Ok ? requireFeature(Feature::CyclicIcOrFingerPrint) : status;
}

Status Session::cardAddCycle(uint64_t number, const WeeklyCycle& cycle) {
    const Status status = requireCyclic(Feature::Ic);
    if (status != Status::Ok) {
        return status;
    }
    if (!isValidCycle(cycle)) {
        return Status::InvalidArgument;
    }
    Bytes data;
    return adminRequest(Feature::CyclicIcOrFingerPrint, command::kCyclic, buildCardCycleAdd(number, cycle), data);
}

Status Session::cardClearCycles(uint64_t number) {
    const Status status = requireCyclic(Feature::Ic);
    if (status != Status::Ok) {
        return status;
    }
    Bytes data;
    return adminRequest(Feature::CyclicIcOrFingerPrint, command::kCyclic, buildCardCycleClear(number), data);
}

Status Session::fingerprintAddCycle(uint64_t id, const WeeklyCycle& cycle) {
    const Status status = requireCyclic(Feature::FingerPrint);
    if (status != Status::Ok) {
        return status;
    }
    if (!isValidCycle(cycle)) {
        return Status::InvalidArgument;
    }
    Bytes data;
    return adminRequest(Feature::CyclicIcOrFingerPrint, command::kCyclic, buildFingerprintCycleAdd(id, cycle), data);
}

Status Session::fingerprintClearCycles(uint64_t id) {
    const Status status = requireCyclic(Feature::FingerPrint);
    if (status != Status::Ok) {
        return status;
    }
    Bytes data;
    return adminRequest(Feature::CyclicIcOrFingerPrint, command::kCyclic, buildFingerprintCycleClear(id), data);
}

}
