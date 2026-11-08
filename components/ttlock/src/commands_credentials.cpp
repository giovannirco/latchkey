// SPDX-License-Identifier: GPL-3.0-or-later
// Ported from kind3r/ttlock-sdk-js (GPL-3.0) src/api/Commands: ManageKeyboardPassword, GetKeyboardPasswords,
// ManageIC, ManageFR and CyclicDate. Passcode ADD, the passcode trailer lengths and the 8-byte card listing follow
// roquerodrigo/ttlock-ble (MIT), which confirmed them on hardware.
#include <utility>

#include "ttlock/commands.h"
#include "wire_format.h"

namespace ttlock {
namespace {

constexpr uint8_t kPasscodeClear = 1;
constexpr uint8_t kPasscodeAdd = 2;
constexpr uint8_t kPasscodeRemove = 3;
constexpr uint8_t kPasscodeModify = 5;
constexpr uint8_t kCardSearch = 1;
constexpr uint8_t kCredentialAdd = 2;
constexpr uint8_t kCredentialDelete = 3;
constexpr uint8_t kCredentialClear = 4;
constexpr uint8_t kCredentialModify = 5;
constexpr uint8_t kFingerprintSearch = 6;
constexpr uint16_t kEndOfList = 0xFFFF;
constexpr size_t kPageHeaderSize = 4;
constexpr size_t kFingerprintIdSize = 6;
constexpr size_t kFingerprintRecordSize = kFingerprintIdSize + 2 * wire::kDateSize;
constexpr size_t kShortCardIdSize = 4;
constexpr size_t kLongCardIdSize = 8;
constexpr size_t kShortCardRecordSize = kShortCardIdSize + 2 * wire::kDateSize;
constexpr size_t kLongCardPageSize = kPageHeaderSize + kLongCardIdSize + 2 * wire::kDateSize;
constexpr size_t kEnrollHeaderSize = 3;
constexpr uint32_t kCardPadding = 0xFFFFFFFF;
constexpr uint8_t kCycleAdd = 2;
constexpr uint8_t kCycleClear = 4;
constexpr uint8_t kCycleFingerprint = 1;
constexpr uint8_t kCycleCard = 2;
constexpr uint8_t kWeeklyCycle = 1;
constexpr uint8_t kNoMonth = 0;
constexpr size_t kCycleZeroTail = 4;
constexpr uint16_t kMinutesPerHour = 60;

void appendCode(Bytes& out, const std::string& code) {
    out.push_back(static_cast<uint8_t>(code.size()));
    out.insert(out.end(), code.begin(), code.end());
}

size_t cardIdSize(uint64_t number) {
    return number > 0xFFFFFFFFULL ? kLongCardIdSize : kShortCardIdSize;
}

bool lastPage(uint16_t sequence) {
    return sequence == 0 || sequence == kEndOfList;
}

bool readPasscodeDates(PasscodeType type, const uint8_t* trailer, size_t size, Validity& out) {
    switch (type) {
        case PasscodeType::Permanent:
        case PasscodeType::Cyclic:
            if (size < wire::kDateSize) {
                return false;
            }
            out.start = wire::readTime(trailer, false);
            return true;
        case PasscodeType::Period:
            if (size < 2 * wire::kDateSize) {
                return false;
            }
            out = wire::readValidity(trailer);
            return true;
        case PasscodeType::Count:
            if (size >= 2 * wire::kDateSize) {
                out = wire::readValidity(trailer);
            }
            return true;
    }
    return true;
}

bool parsePasscodeItem(const uint8_t* item, size_t size, Passcode& out) {
    if (size < 3) {
        return false;
    }
    size_t offset = 0;
    out.type = static_cast<PasscodeType>(item[offset++]);
    const size_t codeSize = item[offset++];
    if (offset + codeSize >= size) {
        return false;
    }
    out.code.assign(item + offset, item + offset + codeSize);
    offset += codeSize;
    const size_t originalSize = item[offset++];
    if (offset + originalSize > size) {
        return false;
    }
    offset += originalSize;
    return readPasscodeDates(out.type, item + offset, size - offset, out.validity);
}

bool parseEnrollHeader(const Bytes& data, EnrollReply& out) {
    if (data.size() < kEnrollHeaderSize || data[1] != kCredentialAdd) {
        return false;
    }
    const uint8_t status = data[2];
    if (status < static_cast<uint8_t>(EnrollStatus::Added) || status > static_cast<uint8_t>(EnrollStatus::ReceiveTemplate)) {
        return false;
    }
    out.status = static_cast<EnrollStatus>(status);
    out.id = 0;
    return true;
}

Bytes cycleFrame(uint8_t operation, uint8_t user, uint64_t id, size_t idSize) {
    Bytes out{operation, user, static_cast<uint8_t>(idSize)};
    wire::appendBe(out, id, idSize);
    return out;
}

void appendHourMinute(Bytes& out, uint16_t minuteOfDay) {
    out.push_back(static_cast<uint8_t>(minuteOfDay / kMinutesPerHour));
    out.push_back(static_cast<uint8_t>(minuteOfDay % kMinutesPerHour));
}

Bytes cycleAdd(uint8_t user, uint64_t id, size_t idSize, const WeeklyCycle& cycle) {
    Bytes out = cycleFrame(kCycleAdd, user, id, idSize);
    out.push_back(kWeeklyCycle);
    out.push_back(cycle.weekDay);
    out.push_back(kNoMonth);
    appendHourMinute(out, cycle.startMinuteOfDay);
    appendHourMinute(out, cycle.endMinuteOfDay);
    out.insert(out.end(), kCycleZeroTail, uint8_t{0});
    return out;
}

}

Bytes buildPasscodeAdd(const Passcode& passcode) {
    Bytes out{kPasscodeAdd, static_cast<uint8_t>(passcode.type)};
    appendCode(out, passcode.code);
    wire::appendTime(out, passcode.validity.start, false);
    if (passcode.type != PasscodeType::Permanent) {
        wire::appendTime(out, passcode.validity.end, false);
    }
    return out;
}

Bytes buildPasscodeUpdate(const std::string& oldCode, const Passcode& passcode) {
    Bytes out{kPasscodeModify, static_cast<uint8_t>(passcode.type)};
    appendCode(out, oldCode);
    appendCode(out, passcode.code);
    wire::appendValidity(out, passcode.validity);
    return out;
}

Bytes buildPasscodeDelete(PasscodeType type, const std::string& code) {
    Bytes out{kPasscodeRemove, static_cast<uint8_t>(type)};
    appendCode(out, code);
    return out;
}

Bytes buildPasscodeClear() {
    return Bytes{kPasscodeClear};
}

Bytes buildPasscodeListRequest(uint16_t sequence) {
    Bytes out;
    wire::appendBe(out, sequence, 2);
    return out;
}

bool parsePasscodePage(const Bytes& data, PasscodePage& out) {
    if (data.size() < 2) {
        return false;
    }
    PasscodePage page;
    if (wire::readBe16(data.data()) == 0) {
        out = std::move(page);
        return true;
    }
    if (data.size() < kPageHeaderSize) {
        return false;
    }
    page.next = wire::readBe16(data.data() + 2);
    page.last = lastPage(page.next);
    size_t offset = kPageHeaderSize;
    while (offset < data.size()) {
        const size_t itemSize = data[offset];
        const size_t itemStart = offset + 1;
        if (itemStart + itemSize > data.size()) {
            return false;
        }
        Passcode item;
        if (!parsePasscodeItem(data.data() + itemStart, itemSize, item)) {
            return false;
        }
        page.items.push_back(std::move(item));
        offset = itemStart + itemSize;
    }
    out = std::move(page);
    return true;
}

Bytes buildFingerprintListRequest(uint16_t sequence) {
    Bytes out{kFingerprintSearch};
    wire::appendBe(out, sequence, 2);
    return out;
}

Bytes buildFingerprintEnrollStart() {
    return Bytes{kCredentialAdd};
}

Bytes buildFingerprintSetValidity(uint64_t id, const Validity& validity) {
    Bytes out{kCredentialModify};
    wire::appendBe(out, id, kFingerprintIdSize);
    wire::appendValidity(out, validity);
    return out;
}

Bytes buildFingerprintDelete(uint64_t id) {
    Bytes out{kCredentialDelete};
    wire::appendBe(out, id, kFingerprintIdSize);
    return out;
}

Bytes buildFingerprintClear() {
    return Bytes{kCredentialClear};
}

Bytes buildCardListRequest(uint16_t sequence) {
    Bytes out{kCardSearch};
    wire::appendBe(out, sequence, 2);
    return out;
}

Bytes buildCardEnrollStart() {
    return Bytes{kCredentialAdd};
}

Bytes buildCardSetValidity(uint64_t number, const Validity& validity) {
    Bytes out{kCredentialModify};
    wire::appendBe(out, number, cardIdSize(number));
    wire::appendValidity(out, validity);
    return out;
}

Bytes buildCardDelete(uint64_t number) {
    Bytes out{kCredentialDelete};
    wire::appendBe(out, number, cardIdSize(number));
    return out;
}

Bytes buildCardClear() {
    return Bytes{kCredentialClear};
}

bool parseFingerprintPage(const Bytes& data, CredentialPage& out) {
    if (data.size() < kPageHeaderSize || data[1] != kFingerprintSearch ||
        (data.size() - kPageHeaderSize) % kFingerprintRecordSize != 0) {
        return false;
    }
    CredentialPage page;
    page.next = wire::readBe16(data.data() + 2);
    page.last = lastPage(page.next);
    for (size_t offset = kPageHeaderSize; offset < data.size(); offset += kFingerprintRecordSize) {
        const uint8_t* record = data.data() + offset;
        page.items.push_back(Credential{wire::readBe(record, kFingerprintIdSize),
                                        wire::readValidity(record + kFingerprintIdSize)});
    }
    out = std::move(page);
    return true;
}

bool parseCardPage(const Bytes& data, CredentialPage& out) {
    if (data.size() < kPageHeaderSize || data[1] != kCardSearch) {
        return false;
    }
    const bool longId = data.size() == kLongCardPageSize;
    const size_t idSize = longId ? kLongCardIdSize : kShortCardIdSize;
    const size_t recordSize = idSize + 2 * wire::kDateSize;
    if (!longId && (data.size() - kPageHeaderSize) % kShortCardRecordSize != 0) {
        return false;
    }
    CredentialPage page;
    page.next = wire::readBe16(data.data() + 2);
    page.last = lastPage(page.next);
    for (size_t offset = kPageHeaderSize; offset < data.size(); offset += recordSize) {
        const uint8_t* record = data.data() + offset;
        page.items.push_back(Credential{wire::readBe(record, idSize), wire::readValidity(record + idSize)});
    }
    out = std::move(page);
    return true;
}

bool parseFingerprintEnrollReply(const Bytes& data, EnrollReply& out) {
    EnrollReply reply;
    if (!parseEnrollHeader(data, reply)) {
        return false;
    }
    if (reply.status == EnrollStatus::Added) {
        if (data.size() < kEnrollHeaderSize + kFingerprintIdSize) {
            return false;
        }
        reply.id = wire::readBe(data.data() + kEnrollHeaderSize, kFingerprintIdSize);
    }
    out = reply;
    return true;
}

bool parseCardEnrollReply(const Bytes& data, EnrollReply& out) {
    EnrollReply reply;
    if (!parseEnrollHeader(data, reply)) {
        return false;
    }
    if (reply.status == EnrollStatus::Added) {
        const uint8_t* number = data.data() + kEnrollHeaderSize;
        const size_t size = data.size() - kEnrollHeaderSize;
        if (size == kShortCardIdSize) {
            reply.id = wire::readBe32(number);
        } else if (size == kLongCardIdSize) {
            const bool padded = wire::readBe32(number + kShortCardIdSize) == kCardPadding;
            reply.id = padded ? wire::readBe32(number) : wire::readBe(number, kLongCardIdSize);
        } else {
            return false;
        }
    }
    out = reply;
    return true;
}

Bytes buildCardCycleAdd(uint64_t number, const WeeklyCycle& cycle) {
    return cycleAdd(kCycleCard, number, cardIdSize(number), cycle);
}

Bytes buildCardCycleClear(uint64_t number) {
    return cycleFrame(kCycleClear, kCycleCard, number, cardIdSize(number));
}

Bytes buildFingerprintCycleAdd(uint64_t id, const WeeklyCycle& cycle) {
    return cycleAdd(kCycleFingerprint, id, kFingerprintIdSize, cycle);
}

Bytes buildFingerprintCycleClear(uint64_t id) {
    return cycleFrame(kCycleClear, kCycleFingerprint, id, kFingerprintIdSize);
}

}
