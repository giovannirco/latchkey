// SPDX-License-Identifier: GPL-3.0-or-later
#pragma once

#include <array>
#include <span>
#include <string_view>

#include "latchkey_util/key_backup.h"

namespace latchkey_util {

inline constexpr size_t kRestoreJournalBytes = 2 + 17 * kMaxBackupLocks;
inline constexpr size_t kLockMetadataBytes = 14;

enum class RestoreStatus { Ok, Invalid, Conflict, Capacity, ReadFailed, WriteFailed, RecoveryRequired, NoMemory };
enum class RestorePart { Record, Passcodes, Fingerprints, Cards, Seeds, Metadata };

inline constexpr std::array kRestoreParts{RestorePart::Record, RestorePart::Passcodes, RestorePart::Fingerprints,
                                        RestorePart::Cards, RestorePart::Seeds, RestorePart::Metadata};

struct RestoreJournal {
    std::array<std::array<char, 18>, kMaxBackupLocks> identities{};
    size_t count = 0;
};

struct LockMetadata {
    ~LockMetadata();
    uint8_t lifecycle = 0;
    AdminProvenance provenance = AdminProvenance::LegacyUnknown;
    AdminProvenance pendingProvenance = AdminProvenance::LegacyUnknown;
    std::array<char, 10> pendingAdminPasscode{};
};

bool encodeRestoreJournal(const RestoreJournal& journal, std::span<uint8_t> bytes, size_t& size);
bool decodeRestoreJournal(std::span<const uint8_t> bytes, RestoreJournal& out);
bool encodeLockMetadata(const LockMetadata& metadata, std::span<uint8_t, kLockMetadataBytes> bytes);
bool decodeLockMetadata(std::span<const uint8_t> bytes, LockMetadata& out);

class RestorePublication;

class RestoreStorage {
public:
    virtual ~RestoreStorage() = default;
    bool recoveryRequired() const;
    virtual bool readJournal(RestoreJournal& out, bool& present) = 0;
    virtual bool countRecords(size_t& out) = 0;
    virtual bool containsIdentity(std::string_view mac, bool& out) = 0;
    virtual bool capacity(size_t& availableEntries, size_t& reservedEntries) = 0;
    virtual size_t recordBytes() const = 0;
    virtual bool writeJournal(const RestoreJournal& journal) = 0;
    virtual bool writePart(const BackupLock& lock, RestorePart part) = 0;
    virtual bool erasePart(std::string_view mac, RestorePart part) = 0;
    virtual bool clearJournal() = 0;

private:
    friend RestoreStatus restoreKeys(const DecodedBackup&, RestoreStorage&, RestorePublication&);
    bool recoveryRequired_ = false;
};

class RestorePublication {
public:
    virtual ~RestorePublication() = default;
    virtual bool prepare(std::span<const BackupLock> locks) = 0;
    virtual void publish() noexcept = 0;
    virtual void discard() noexcept = 0;
};

RestoreStatus restoreKeys(const DecodedBackup& backup, RestoreStorage& storage, RestorePublication& publication);
RestoreStatus recoverKeys(RestoreStorage& storage);

}
