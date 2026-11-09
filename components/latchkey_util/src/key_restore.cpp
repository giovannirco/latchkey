// SPDX-License-Identifier: GPL-3.0-or-later
#include "latchkey_util/key_restore.h"

#include <algorithm>
#include <cstring>

#include "latchkey_util/storage_budget.h"
#include "ttlock/types.h"

namespace latchkey_util {
namespace {

bool validIdentity(std::string_view mac) {
    if (mac.size() != 17) return false;
    for (size_t i = 0; i < mac.size(); ++i) {
        const char value = mac[i];
        if (i % 3 == 2) {
            if (value != ':') return false;
        } else if (!((value >= '0' && value <= '9') || (value >= 'A' && value <= 'F'))) {
            return false;
        }
    }
    return true;
}

bool validJournal(const RestoreJournal& journal) {
    if (journal.count == 0 || journal.count > kMaxBackupLocks) return false;
    for (size_t i = 0; i < journal.count; ++i) {
        const auto& identity = journal.identities[i];
        if (identity[17] != '\0' || !validIdentity({identity.data(), 17})) return false;
        for (size_t j = 0; j < i; ++j) if (identity == journal.identities[j]) return false;
    }
    return true;
}

RestoreStatus cleanJournal(RestoreStorage& storage, const RestoreJournal& journal) {
    if (!validJournal(journal)) return RestoreStatus::RecoveryRequired;
    for (size_t i = 0; i < journal.count; ++i) {
        for (const auto part : kRestoreParts) {
            if (!storage.erasePart({journal.identities[i].data(), 17}, part)) return RestoreStatus::RecoveryRequired;
        }
    }
    return storage.clearJournal() ? RestoreStatus::Ok : RestoreStatus::RecoveryRequired;
}

RestoreStatus rollback(RestoreStorage& storage, bool missingAllowed) {
    RestoreJournal journal;
    bool present = false;
    if (!storage.readJournal(journal, present)) return RestoreStatus::RecoveryRequired;
    if (!present) return missingAllowed ? RestoreStatus::WriteFailed : RestoreStatus::RecoveryRequired;
    return cleanJournal(storage, journal) == RestoreStatus::Ok ? RestoreStatus::WriteFailed
                                                              : RestoreStatus::RecoveryRequired;
}

size_t entriesNeeded(std::span<const BackupLock> locks, size_t recordBytes) {
    size_t needed = 5 + nvsBlobEntries(2 + 17 * locks.size());
    for (const auto& lock : locks) {
        needed += nvsBlobEntries(recordBytes) + nvsBlobEntries(kLockMetadataBytes);
        for (const auto labels : lock.labels) needed += nvsBlobEntries(labels.size());
        if (!lock.seeds.empty()) needed += nvsBlobEntries(lock.seeds.size());
    }
    return needed;
}

}

LockMetadata::~LockMetadata() {
    auto* bytes = static_cast<volatile char*>(pendingAdminPasscode.data());
    for (size_t i = 0; i < pendingAdminPasscode.size(); ++i) bytes[i] = 0;
}

bool encodeRestoreJournal(const RestoreJournal& journal, std::span<uint8_t> bytes, size_t& size) {
    const size_t needed = 2 + 17 * journal.count;
    if (!validJournal(journal) || bytes.size() < needed) return false;
    bytes[0] = 1;
    bytes[1] = static_cast<uint8_t>(journal.count);
    for (size_t i = 0; i < journal.count; ++i) std::memcpy(bytes.data() + 2 + 17 * i, journal.identities[i].data(), 17);
    size = needed;
    return true;
}

bool decodeRestoreJournal(std::span<const uint8_t> bytes, RestoreJournal& out) {
    if (bytes.size() < 2 || bytes[0] != 1 || bytes[1] > kMaxBackupLocks || bytes.size() != 2 + 17U * bytes[1]) {
        return false;
    }
    RestoreJournal journal;
    journal.count = bytes[1];
    for (size_t i = 0; i < journal.count; ++i) std::memcpy(journal.identities[i].data(), bytes.data() + 2 + 17 * i, 17);
    if (!validJournal(journal)) return false;
    out = journal;
    return true;
}

bool encodeLockMetadata(const LockMetadata& metadata, std::span<uint8_t, kLockMetadataBytes> bytes) {
    const size_t length = strnlen(metadata.pendingAdminPasscode.data(), metadata.pendingAdminPasscode.size());
    const auto code = std::string_view(metadata.pendingAdminPasscode.data(), length);
    if ((metadata.lifecycle & ~7) != 0 || metadata.provenance > AdminProvenance::HardeningGenerated ||
        metadata.pendingProvenance > AdminProvenance::HardeningGenerated ||
        (!code.empty() && !ttlock::isPasscode(code)) ||
        (code.empty() && metadata.pendingProvenance != AdminProvenance::LegacyUnknown)) return false;
    std::fill(bytes.begin(), bytes.end(), 0);
    bytes[0] = 1;
    bytes[1] = metadata.lifecycle;
    bytes[2] = static_cast<uint8_t>(metadata.provenance);
    bytes[3] = static_cast<uint8_t>(metadata.pendingProvenance);
    bytes[4] = static_cast<uint8_t>(length);
    std::memcpy(bytes.data() + 5, code.data(), code.size());
    return true;
}

bool decodeLockMetadata(std::span<const uint8_t> bytes, LockMetadata& out) {
    if (bytes.size() != kLockMetadataBytes || bytes[0] != 1 || bytes[4] > 9) return false;
    LockMetadata metadata;
    metadata.lifecycle = bytes[1];
    metadata.provenance = static_cast<AdminProvenance>(bytes[2]);
    metadata.pendingProvenance = static_cast<AdminProvenance>(bytes[3]);
    std::memcpy(metadata.pendingAdminPasscode.data(), bytes.data() + 5, bytes[4]);
    std::array<uint8_t, kLockMetadataBytes> canonical{};
    const bool valid = encodeLockMetadata(metadata, canonical) && std::equal(bytes.begin(), bytes.end(), canonical.begin());
    auto* secret = static_cast<volatile uint8_t*>(canonical.data());
    for (size_t i = 0; i < canonical.size(); ++i) secret[i] = 0;
    if (!valid) return false;
    out = metadata;
    return true;
}

namespace {

RestoreStatus restorePrepared(const DecodedBackup& backup, RestoreStorage& storage, RestorePublication& publication) {
    const auto locks = backup.locks();
    if (locks.empty() || locks.size() > kMaxBackupLocks) return RestoreStatus::Invalid;
    RestoreJournal journal;
    bool present = false;
    if (!storage.readJournal(journal, present)) return RestoreStatus::ReadFailed;
    if (present) return RestoreStatus::RecoveryRequired;
    size_t count = 0;
    if (!storage.countRecords(count)) return RestoreStatus::ReadFailed;
    if (count > kMaxBackupLocks || locks.size() > kMaxBackupLocks - count) return RestoreStatus::Capacity;
    for (const auto& lock : locks) {
        bool occupied = false;
        if (!storage.containsIdentity(lock.mac, occupied)) return RestoreStatus::ReadFailed;
        if (occupied) return RestoreStatus::Conflict;
    }
    size_t available = 0;
    size_t reserve = 0;
    if (!storage.capacity(available, reserve)) return RestoreStatus::ReadFailed;
    const size_t needed = entriesNeeded(locks, storage.recordBytes());
    if (needed > available || reserve > available - needed) return RestoreStatus::Capacity;
    if (!publication.prepare(locks)) {
        publication.discard();
        return RestoreStatus::NoMemory;
    }
    journal.count = locks.size();
    for (size_t i = 0; i < locks.size(); ++i) std::memcpy(journal.identities[i].data(), locks[i].mac.data(), 17);
    if (!storage.writeJournal(journal)) {
        publication.discard();
        return rollback(storage, true);
    }
    for (const auto& lock : locks) {
        for (const auto part : kRestoreParts) {
            if (!storage.writePart(lock, part)) {
                publication.discard();
                return rollback(storage, false);
            }
        }
    }
    if (!storage.clearJournal()) {
        publication.discard();
        return rollback(storage, false);
    }
    publication.publish();
    return RestoreStatus::Ok;
}

}

bool RestoreStorage::recoveryRequired() const { return recoveryRequired_; }

RestoreStatus restoreKeys(const DecodedBackup& backup, RestoreStorage& storage, RestorePublication& publication) {
    if (storage.recoveryRequired_) return RestoreStatus::RecoveryRequired;
    const auto status = restorePrepared(backup, storage, publication);
    if (status == RestoreStatus::RecoveryRequired) storage.recoveryRequired_ = true;
    return status;
}

RestoreStatus recoverKeys(RestoreStorage& storage) {
    RestoreJournal journal;
    bool present = false;
    if (!storage.readJournal(journal, present)) return RestoreStatus::RecoveryRequired;
    return present ? cleanJournal(storage, journal) : RestoreStatus::Ok;
}

}
