// SPDX-License-Identifier: GPL-3.0-or-later
#include "latchkey_util/lock_alerts.h"

#include <algorithm>
#include <limits>

#include "big_endian.h"

namespace latchkey_util {

namespace {

constexpr uint8_t kVersion = 2;
constexpr size_t kHeaderBytes = 7;
constexpr size_t kEntryBytes = 14;

bool valid(const LockAlert& alert) {
    if (alert.kind == LockAlertKind::LowBattery) {
        return alert.method == UnlockMethod::None && alert.type == 0 && alert.seq == 0 &&
               alert.battery >= 0 && alert.battery < 40;
    }
    if (alert.battery != -1) return false;
    if (alert.kind == LockAlertKind::WatchStateUnreadable || alert.kind == LockAlertKind::AlertsUnreadable) {
        return alert.method == UnlockMethod::None && alert.type == 0 && alert.seq == 0;
    }
    return alert.kind == LockAlertKind::UnexpectedUnlock && unlockMethodOf(alert.type) == alert.method &&
           (alert.method == UnlockMethod::App || alert.method == UnlockMethod::Remote ||
            alert.method == UnlockMethod::Forced);
}

bool same(const LockAlert& left, const LockAlert& right) {
    return left.kind == right.kind && left.time == right.time && left.seq == right.seq && left.type == right.type &&
           left.method == right.method && left.battery == right.battery;
}

}

std::span<const LockAlert> LockAlerts::entries() const { return {entries_.data(), count_}; }

bool LockAlerts::add(LockAlert alert) {
    if (!valid(alert)) {
        return false;
    }
    for (const LockAlert& held : entries()) {
        if (same(held, alert)) {
            return true;
        }
    }
    if (next_ == std::numeric_limits<uint32_t>::max()) {
        return false;
    }
    if (count_ == entries_.size()) {
        const auto oldest = std::find_if(entries_.begin(), entries_.end(), [](const auto& held) {
            return held.kind != LockAlertKind::LowBattery;
        });
        if (oldest == entries_.end()) return false;
        std::move(oldest + 1, entries_.end(), oldest);
        --count_;
    }
    alert.id = next_++;
    entries_[count_++] = alert;
    if (alert.kind == LockAlertKind::LowBattery) batteryLow_ = true;
    return true;
}

bool LockAlerts::acknowledge(uint32_t through) {
    if (through >= next_) {
        return false;
    }
    size_t kept = 0;
    for (const LockAlert& alert : entries()) {
        if (alert.id > through) {
            entries_[kept++] = alert;
        }
    }
    count_ = kept;
    return true;
}

bool LockAlerts::observeBattery(int level, uint32_t time) {
    if (level < 0 || level > 100) return false;
    if (level < 40) {
        if (batteryLow_) return true;
        LockAlert alert;
        alert.kind = LockAlertKind::LowBattery;
        alert.time = time;
        alert.battery = level;
        if (!add(alert)) return false;
        batteryLow_ = true;
        return true;
    }
    batteryLow_ = false;
    size_t kept = 0;
    for (const auto& alert : entries()) {
        if (alert.kind != LockAlertKind::LowBattery) entries_[kept++] = alert;
    }
    count_ = kept;
    return true;
}

std::array<uint8_t, kLockAlertsBytes> LockAlerts::encode() const {
    std::array<uint8_t, kLockAlertsBytes> bytes{};
    bytes[0] = kVersion;
    big_endian::write(bytes.data() + 1, next_, 4);
    bytes[5] = static_cast<uint8_t>(count_);
    bytes[6] = batteryLow_ ? 1 : 0;
    for (size_t i = 0; i < count_; ++i) {
        const LockAlert& alert = entries_[i];
        uint8_t* entry = bytes.data() + kHeaderBytes + i * kEntryBytes;
        big_endian::write(entry, alert.id, 4);
        big_endian::write(entry + 4, alert.time, 4);
        big_endian::write(entry + 8, alert.seq, 2);
        entry[10] = alert.type;
        entry[11] = static_cast<uint8_t>(alert.kind);
        entry[12] = static_cast<uint8_t>(alert.method);
        entry[13] = alert.battery < 0 ? 0xFF : static_cast<uint8_t>(alert.battery);
    }
    return bytes;
}

bool LockAlerts::decode(const uint8_t* data, size_t size, LockAlerts& out) {
    if (data == nullptr || size < 6) return false;
    const bool legacy = data[0] == 1;
    const size_t header = legacy ? 6 : kHeaderBytes;
    const size_t stride = legacy ? 13 : kEntryBytes;
    if ((!legacy && data[0] != kVersion) || size != header + stride * kMaxLockAlerts ||
        data[5] > kMaxLockAlerts || (!legacy && data[6] > 1)) return false;
    LockAlerts alerts;
    alerts.batteryLow_ = !legacy && data[6] != 0;
    alerts.next_ = static_cast<uint32_t>(big_endian::read(data + 1, 4));
    alerts.count_ = data[5];
    if (alerts.next_ == 0) {
        return false;
    }
    uint32_t previous = 0;
    for (size_t i = 0; i < alerts.count_; ++i) {
        const uint8_t* entry = data + header + i * stride;
        LockAlert& alert = alerts.entries_[i];
        alert.id = static_cast<uint32_t>(big_endian::read(entry, 4));
        alert.time = static_cast<uint32_t>(big_endian::read(entry + 4, 4));
        alert.seq = static_cast<uint16_t>(big_endian::read(entry + 8, 2));
        alert.type = entry[10];
        alert.kind = static_cast<LockAlertKind>(entry[11]);
        alert.method = static_cast<UnlockMethod>(entry[12]);
        alert.battery = legacy || entry[13] == 0xFF ? -1 : entry[13];
        if (alert.kind == LockAlertKind::LowBattery && !alerts.batteryLow_) return false;
        if (!valid(alert) || alert.id <= previous || alert.id >= alerts.next_) {
            return false;
        }
        previous = alert.id;
    }
    const uint8_t* unused = data + header + alerts.count_ * stride;
    if (std::any_of(unused, data + size, [](uint8_t byte) { return byte != 0; })) {
        return false;
    }
    out = alerts;
    return true;
}

LockAlerts LockAlerts::lost() {
    LockAlerts alerts;
    LockAlert warning;
    warning.kind = LockAlertKind::AlertsUnreadable;
    alerts.add(warning);
    return alerts;
}

}
