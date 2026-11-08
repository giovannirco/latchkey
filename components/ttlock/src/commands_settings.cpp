// SPDX-License-Identifier: GPL-3.0-or-later
// Ported from kind3r/ttlock-sdk-js (GPL-3.0) src/api/Commands: AutoLockManage, PassageMode, AudioManage,
// ControlRemoteUnlock and ScreenPasscodeManage. The auto-lock limits and the volume write follow
// roquerodrigo/ttlock-ble (MIT).
#include <utility>

#include "ttlock/commands.h"
#include "wire_format.h"

namespace ttlock {
namespace {

constexpr uint8_t kQuery = 1;
constexpr uint8_t kModify = 2;
constexpr uint8_t kPassageDelete = 3;
constexpr uint8_t kPassageClear = 4;
constexpr uint8_t kVolumeSelector = 1;
constexpr uint8_t kVolumeTrailer = 0;
constexpr uint8_t kLowestVolume = 1;
constexpr uint8_t kHighestVolume = 5;
constexpr uint8_t kRemoteUnlockOpen = 1;
constexpr uint8_t kScreenPasscodeVisible = 1;
constexpr uint8_t kPassageEnd = 0xFF;
constexpr size_t kPassageHeaderSize = 3;
constexpr size_t kPassageEntrySize = 7;

Bytes passageFrame(uint8_t operation, const PassageMode& mode) {
    return Bytes{operation,      static_cast<uint8_t>(mode.type), mode.weekOrDay, mode.month,
                 mode.startHour, mode.startMinute,                mode.endHour,   mode.endMinute};
}

bool isQueryReply(const Bytes& data, size_t minimumSize) {
    return data.size() >= minimumSize && data[1] == kQuery;
}

}

Bytes buildAutoLockQuery() {
    return Bytes{kQuery};
}

Bytes buildAutoLockSet(uint16_t seconds) {
    Bytes out{kModify};
    wire::appendBe(out, seconds, 2);
    return out;
}

bool parseAutoLock(const Bytes& data, AutoLockSetting& out) {
    if (!isQueryReply(data, 4)) {
        return false;
    }
    AutoLockSetting setting;
    setting.seconds = wire::readBe16(data.data() + 2);
    if (data.size() >= 8) {
        setting.minSeconds = wire::readBe16(data.data() + 4);
        setting.maxSeconds = wire::readBe16(data.data() + 6);
    }
    out = setting;
    return true;
}

Bytes buildPassageQuery(uint8_t sequence) {
    return Bytes{kQuery, sequence};
}

Bytes buildPassageAdd(const PassageMode& mode) {
    return passageFrame(kModify, mode);
}

Bytes buildPassageDelete(const PassageMode& mode) {
    return passageFrame(kPassageDelete, mode);
}

Bytes buildPassageClear() {
    return Bytes{kPassageClear};
}

bool parsePassagePage(const Bytes& data, PassagePage& out) {
    if (!isQueryReply(data, kPassageHeaderSize) || (data.size() - kPassageHeaderSize) % kPassageEntrySize != 0) {
        return false;
    }
    PassagePage page;
    page.next = data[2];
    page.last = page.next == 0 || page.next == kPassageEnd;
    for (size_t offset = kPassageHeaderSize; offset < data.size(); offset += kPassageEntrySize) {
        const uint8_t* entry = data.data() + offset;
        page.items.push_back(PassageMode{static_cast<PassageType>(entry[0]), entry[1], entry[2], entry[3], entry[4],
                                         entry[5], entry[6]});
    }
    out = std::move(page);
    return true;
}

Bytes buildSoundQuery() {
    return Bytes{kQuery};
}

Bytes buildSoundSet(bool enabled) {
    return Bytes{kModify, static_cast<uint8_t>(enabled ? 1 : 0)};
}

Bytes buildSoundVolumeSet(uint8_t level) {
    return Bytes{kModify, kVolumeSelector, level, kVolumeTrailer};
}

bool parseSound(const Bytes& data, SoundSetting& out) {
    if (!isQueryReply(data, 3)) {
        return false;
    }
    SoundSetting setting;
    setting.enabled = data[2] != 0;
    if (data.size() >= 4 && data[3] >= kLowestVolume && data[3] <= kHighestVolume) {
        setting.volume = data[3];
    }
    out = setting;
    return true;
}

Bytes buildSwitchQuery() {
    return Bytes{kQuery};
}

Bytes buildSwitchSet(uint32_t item, bool enabled) {
    Bytes out{kModify};
    wire::appendBe(out, item, 4);
    wire::appendBe(out, enabled ? item : 0, 4);
    return out;
}

bool parseSwitchState(const Bytes& data, uint32_t& out) {
    if (data.size() < 6) {
        return false;
    }
    out = wire::readBe32(data.data() + 2);
    return true;
}

Bytes buildRemoteUnlockQuery() {
    return Bytes{kQuery};
}

Bytes buildRemoteUnlockSet(bool enabled) {
    return Bytes{kModify, static_cast<uint8_t>(enabled ? 1 : 0)};
}

bool parseRemoteUnlock(const Bytes& data, bool& out) {
    if (!isQueryReply(data, 3)) {
        return false;
    }
    out = data[2] == kRemoteUnlockOpen;
    return true;
}

Bytes buildScreenPasscodeQuery() {
    return Bytes{kQuery};
}

Bytes buildScreenPasscodeSet(bool visible) {
    return Bytes{kModify, static_cast<uint8_t>(visible ? 1 : 0)};
}

bool parseScreenPasscode(const Bytes& data, bool& visible) {
    if (data.size() < 2 || data[0] != kQuery) {
        return false;
    }
    visible = data[1] == kScreenPasscodeVisible;
    return true;
}

}
