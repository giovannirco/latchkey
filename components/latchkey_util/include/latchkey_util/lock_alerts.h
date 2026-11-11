// SPDX-License-Identifier: GPL-3.0-or-later
#pragma once

#include <array>
#include <cstddef>
#include <cstdint>
#include <span>

#include "latchkey_util/unlock_alert.h"

namespace latchkey_util {

inline constexpr size_t kMaxLockAlerts = 8;
inline constexpr size_t kLockAlertsBytes = 7 + 14 * kMaxLockAlerts;

enum class LockAlertKind : uint8_t {
    UnexpectedUnlock = 1,
    WatchStateUnreadable = 2,
    AlertsUnreadable = 3,
    LowBattery = 4,
};

struct LockAlert {
    uint32_t id = 0;
    uint32_t time = 0;
    uint16_t seq = 0;
    uint8_t type = 0;
    int battery = -1;
    LockAlertKind kind = LockAlertKind::UnexpectedUnlock;
    UnlockMethod method = UnlockMethod::None;
};

class LockAlerts {
public:
    std::span<const LockAlert> entries() const;
    bool add(LockAlert alert);
    bool acknowledge(uint32_t through);
    bool observeBattery(int level, uint32_t time);
    std::array<uint8_t, kLockAlertsBytes> encode() const;
    static bool decode(const uint8_t* data, size_t size, LockAlerts& out);
    static LockAlerts lost();

private:
    std::array<LockAlert, kMaxLockAlerts> entries_{};
    size_t count_ = 0;
    uint32_t next_ = 1;
    bool batteryLow_ = false;
};

}
