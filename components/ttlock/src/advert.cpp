// SPDX-License-Identifier: GPL-3.0-or-later
// Ported from kind3r/ttlock-sdk-js (GPL-3.0) TTBluetoothDevice.parseManufacturerData; dormant bit per
// roquerodrigo/ttlock-ble (MIT) LockAdvertisement.
#include "ttlock/advert.h"

#include <cstddef>
#include <utility>

namespace ttlock {
namespace {

constexpr size_t kMinAdvertSize = 15;
constexpr size_t kMacSize = 6;
constexpr size_t kCompactSceneIndex = 2;
constexpr size_t kOffsetTypeIndex = 4;
constexpr size_t kOffsetSceneIndex = 7;
constexpr uint8_t kV3ProtocolType = 5;
constexpr uint8_t kV3ProtocolVersion = 3;
constexpr uint8_t kV2sProtocolVersion = 1;
constexpr uint8_t kFlagUnlocked = 0x01;
constexpr uint8_t kFlagSettingMode = 0x04;
constexpr uint8_t kFlagDormant = 0x10;

bool isDfuMode(uint8_t protocolType, uint8_t protocolVersion) {
    return (protocolType == 18 && protocolVersion == 25) || (protocolType == 0xFF && protocolVersion == 0xFF);
}

bool carriesState(const LockVersion& version) {
    const bool isV2s = version.protocolType == kV3ProtocolType && version.protocolVersion == kV2sProtocolVersion;
    return version.protocolType >= kV3ProtocolType && !isV2s;
}

std::string formatMac(const uint8_t* reversedMac) {
    static constexpr char kHexDigits[] = "0123456789ABCDEF";
    std::string mac;
    mac.reserve(3 * kMacSize - 1);
    for (size_t i = 0; i < kMacSize; ++i) {
        const uint8_t byte = reversedMac[kMacSize - 1 - i];
        if (i > 0) {
            mac.push_back(':');
        }
        mac.push_back(kHexDigits[byte >> 4]);
        mac.push_back(kHexDigits[byte & 0x0F]);
    }
    return mac;
}

}

bool parseAdvert(const Bytes& manufacturerData, Advert& out) {
    const Bytes& data = manufacturerData;
    if (data.size() < kMinAdvertSize || isDfuMode(data[0], data[1])) {
        return false;
    }
    const bool compact = data[0] == kV3ProtocolType && data[1] == kV3ProtocolVersion;
    const size_t typeIndex = compact ? 0 : kOffsetTypeIndex;
    const size_t sceneIndex = compact ? kCompactSceneIndex : kOffsetSceneIndex;
    LockVersion version;
    version.protocolType = data[typeIndex];
    version.protocolVersion = data[typeIndex + 1];
    version.scene = data[sceneIndex];
    if (!carriesState(version)) {
        return false;
    }
    const uint8_t flags = data[sceneIndex + 1];
    Advert advert;
    advert.version = version;
    advert.paired = (flags & kFlagSettingMode) == 0;
    advert.hasLockState = (flags & kFlagDormant) == 0;
    advert.locked = advert.hasLockState && (flags & kFlagUnlocked) == 0;
    advert.battery = data[sceneIndex + 2];
    advert.mac = formatMac(data.data() + data.size() - kMacSize);
    out = std::move(advert);
    return true;
}

}
