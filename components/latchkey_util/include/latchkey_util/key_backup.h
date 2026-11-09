// SPDX-License-Identifier: GPL-3.0-or-later
#pragma once

#include <array>
#include <cstddef>
#include <cstdint>
#include <memory>
#include <span>
#include <string_view>

#include "ttlock/frame.h"

namespace latchkey_util {

inline constexpr size_t kMaxBackupPlaintext = 8192;
inline constexpr size_t kBackupHeaderSize = 38;
inline constexpr size_t kBackupTagSize = 16;
inline constexpr size_t kMaxBackupEnvelope = kBackupHeaderSize + kMaxBackupPlaintext + kBackupTagSize;
inline constexpr size_t kMaxBackupLocks = 8;
inline constexpr uint32_t kBackupIterations = 100000;
inline constexpr uint8_t kBackupPairComplete = 0x01;
inline constexpr uint8_t kBackupAdminPasscodeConfirmed = 0x02;
inline constexpr uint8_t kBackupTimeCalibrated = 0x04;
inline constexpr uint8_t kBackupBackedUp = 0x01;
inline constexpr uint8_t kBackupHardened = 0x02;
inline constexpr uint8_t kBackupResetButtonOff = 0x04;

enum class BackupStatus { Ok, Invalid, Duplicate, TooLarge, NoMemory, CryptoFailed };
enum class AdminProvenance : uint8_t { LegacyUnknown, Owner, PairingGenerated };

class SensitiveBuffer {
public:
    SensitiveBuffer() = default;
    ~SensitiveBuffer();
    SensitiveBuffer(const SensitiveBuffer&) = delete;
    SensitiveBuffer& operator=(const SensitiveBuffer&) = delete;
    SensitiveBuffer(SensitiveBuffer&& other) noexcept;
    SensitiveBuffer& operator=(SensitiveBuffer&& other) noexcept;
    bool allocate(size_t size, size_t capacity = 0);
    bool resize(size_t size);
    void clear();
    uint8_t* data();
    const uint8_t* data() const;
    size_t size() const;
    size_t capacity() const;

private:
    uint8_t* data_ = nullptr;
    size_t size_ = 0;
    size_t capacity_ = 0;
};

struct BackupLock {
    ~BackupLock();
    uint8_t flags = 0;
    uint8_t lifecycle = 0;
    uint8_t addressType = 0;
    AdminProvenance provenance = AdminProvenance::LegacyUnknown;
    AdminProvenance pendingProvenance = AdminProvenance::LegacyUnknown;
    std::array<uint8_t, 6> address{};
    std::string_view mac;
    ttlock::LockVersion protocol;
    std::span<const uint8_t> aesKey;
    uint32_t adminPs = 0;
    uint32_t unlockKey = 0;
    uint32_t lockFlagPos = 0;
    uint64_t features = 0;
    std::string_view name;
    std::string_view adminPasscode;
    std::string_view pendingAdminPasscode;
    std::string_view model;
    std::string_view hardware;
    std::string_view firmware;
    std::string_view manufactureDate;
    std::array<std::span<const uint8_t>, 3> labels;
    std::span<const uint8_t> seeds;
};

class DecodedBackup {
public:
    DecodedBackup() = default;
    DecodedBackup(const DecodedBackup&) = delete;
    DecodedBackup& operator=(const DecodedBackup&) = delete;
    DecodedBackup(DecodedBackup&& other) noexcept;
    DecodedBackup& operator=(DecodedBackup&& other) noexcept;
    std::span<const BackupLock> locks() const;

private:
    friend BackupStatus decodeBackup(SensitiveBuffer plaintext, DecodedBackup& out);
    SensitiveBuffer plaintext_;
    std::unique_ptr<BackupLock[]> locks_;
    size_t count_ = 0;
};

BackupStatus encodeBackup(std::span<const BackupLock> locks, SensitiveBuffer& out);
BackupStatus decodeBackup(SensitiveBuffer plaintext, DecodedBackup& out);
bool isBackupPassphrase(std::string_view password);

struct BackupHeader {
    std::array<uint8_t, 16> salt{};
    std::array<uint8_t, 12> nonce{};
};

std::array<uint8_t, kBackupHeaderSize> encodeBackupHeader(const BackupHeader& header);
bool parseBackupHeader(std::span<const uint8_t> bytes, BackupHeader& out);

class BackupCrypto {
public:
    virtual ~BackupCrypto() = default;
    virtual bool random(std::span<uint8_t> bytes) = 0;
    virtual bool deriveKey(std::string_view password, std::span<const uint8_t, 16> salt,
                            std::span<uint8_t, 32> key) = 0;
    virtual bool seal(std::span<const uint8_t, 32> key, std::span<const uint8_t, 12> nonce,
                       std::span<const uint8_t> aad, std::span<uint8_t> plaintextAndTag) = 0;
    virtual bool open(std::span<const uint8_t, 32> key, std::span<const uint8_t, 12> nonce,
                       std::span<const uint8_t> aad, std::span<uint8_t> ciphertextAndTag) = 0;
};

BackupStatus sealBackup(SensitiveBuffer plaintext, std::string_view password, BackupCrypto& crypto,
                         SensitiveBuffer& out);
BackupStatus openBackup(SensitiveBuffer envelope, std::string_view password, BackupCrypto& crypto,
                         SensitiveBuffer& out);

}
