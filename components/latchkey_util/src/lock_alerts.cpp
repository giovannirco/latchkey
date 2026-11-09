// SPDX-License-Identifier: GPL-3.0-or-later
#include "latchkey_util/lock_alerts.h"

#include <algorithm>
#include <limits>

#include "big_endian.h"

namespace latchkey_util {

namespace {

constexpr uint8_t kVersion = 1;
constexpr size_t kHeaderBytes = 6;
constexpr size_t kEntryBytes = 13;

bool valid(const LockAlert& alert) {
    if (alert.kind == LockAlertKind::WatchStateUnreadable || alert.kind == LockAlertKind::AlertsUnreadable) {
        return alert.method == UnlockMethod::None && alert.type == 0 && alert.seq == 0;
    }
    return alert.kind == LockAlertKind::UnexpectedUnlock && unlockMethodOf(alert.type) == alert.method &&
           (alert.method == UnlockMethod::App || alert.method == UnlockMethod::Remote ||
            alert.method == UnlockMethod::Forced);
}

bool same(const LockAlert& left, const LockAlert& right) {
    return left.kind == right.kind && left.time == right.time && left.seq == right.seq && left.type == right.type &&
           left.method == right.method;
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
        std::move(entries_.begin() + 1, entries_.end(), entries_.begin());
        --count_;
    }
    alert.id = next_++;
    entries_[count_++] = alert;
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

std::array<uint8_t, kLockAlertsBytes> LockAlerts::encode() const {
    std::array<uint8_t, kLockAlertsBytes> bytes{};
    bytes[0] = kVersion;
    big_endian::write(bytes.data() + 1, next_, 4);
    bytes[5] = static_cast<uint8_t>(count_);
    for (size_t i = 0; i < count_; ++i) {
        const LockAlert& alert = entries_[i];
        uint8_t* entry = bytes.data() + kHeaderBytes + i * kEntryBytes;
        big_endian::write(entry, alert.id, 4);
        big_endian::write(entry + 4, alert.time, 4);
        big_endian::write(entry + 8, alert.seq, 2);
        entry[10] = alert.type;
        entry[11] = static_cast<uint8_t>(alert.kind);
        entry[12] = static_cast<uint8_t>(alert.method);
    }
    return bytes;
}

bool LockAlerts::decode(const uint8_t* data, size_t size, LockAlerts& out) {
    if (data == nullptr || size != kLockAlertsBytes || data[0] != kVersion || data[5] > kMaxLockAlerts) {
        return false;
    }
    LockAlerts alerts;
    alerts.next_ = static_cast<uint32_t>(big_endian::read(data + 1, 4));
    alerts.count_ = data[5];
    if (alerts.next_ == 0) {
        return false;
    }
    uint32_t previous = 0;
    for (size_t i = 0; i < alerts.count_; ++i) {
        const uint8_t* entry = data + kHeaderBytes + i * kEntryBytes;
        LockAlert& alert = alerts.entries_[i];
        alert.id = static_cast<uint32_t>(big_endian::read(entry, 4));
        alert.time = static_cast<uint32_t>(big_endian::read(entry + 4, 4));
        alert.seq = static_cast<uint16_t>(big_endian::read(entry + 8, 2));
        alert.type = entry[10];
        alert.kind = static_cast<LockAlertKind>(entry[11]);
        alert.method = static_cast<UnlockMethod>(entry[12]);
        if (!valid(alert) || alert.id <= previous || alert.id >= alerts.next_) {
            return false;
        }
        previous = alert.id;
    }
    const uint8_t* unused = data + kHeaderBytes + alerts.count_ * kEntryBytes;
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
