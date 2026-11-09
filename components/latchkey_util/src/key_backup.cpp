// SPDX-License-Identifier: GPL-3.0-or-later
#include "latchkey_util/key_backup.h"

#include <algorithm>
#include <cstdlib>
#include <cstring>
#include <new>
#include <utility>

#include "latchkey_util/label_table.h"
#include "latchkey_util/seed_table.h"

namespace latchkey_util {
namespace {

void wipe(void* data, size_t size) {
    auto* bytes = static_cast<volatile uint8_t*>(data);
    while (size-- > 0) *bytes++ = 0;
}

struct BackupKey {
    std::array<uint8_t, 32> bytes{};
    ~BackupKey() { wipe(bytes.data(), bytes.size()); }
};

bool validText(std::string_view text, size_t maxBytes, size_t maxPoints = SIZE_MAX) {
    if (text.size() > maxBytes) return false;
    size_t points = 0;
    for (size_t at = 0; at < text.size(); ++points) {
        const auto first = static_cast<uint8_t>(text[at++]);
        if (first < 0x80) {
            if (first < 0x20 || first == 0x7F) return false;
            continue;
        }
        uint32_t value = 0;
        size_t continuation = 0;
        uint32_t minimum = 0;
        if (first >= 0xC2 && first <= 0xDF) {
            value = first & 0x1F;
            continuation = 1;
            minimum = 0x80;
        } else if (first >= 0xE0 && first <= 0xEF) {
            value = first & 0x0F;
            continuation = 2;
            minimum = 0x800;
        } else if (first >= 0xF0 && first <= 0xF4) {
            value = first & 7;
            continuation = 3;
            minimum = 0x10000;
        } else {
            return false;
        }
        if (text.size() - at < continuation) return false;
        while (continuation-- > 0) {
            const auto next = static_cast<uint8_t>(text[at++]);
            if ((next & 0xC0) != 0x80) return false;
            value = (value << 6) | (next & 0x3F);
        }
        if (value < minimum || value > 0x10FFFF || (value >= 0xD800 && value <= 0xDFFF)) return false;
    }
    return points <= maxPoints;
}

class Reader {
public:
    explicit Reader(std::span<const uint8_t> bytes) : bytes_(bytes) {}

    bool take(size_t size, std::span<const uint8_t>& out) {
        if (size > bytes_.size()) return false;
        out = bytes_.first(size);
        bytes_ = bytes_.subspan(size);
        return true;
    }

    template <typename T>
    bool number(T& out, size_t size = sizeof(T)) {
        std::span<const uint8_t> field;
        if (!take(size, field)) return false;
        uint64_t value = 0;
        for (const uint8_t byte : field) value = (value << 8) | byte;
        out = static_cast<T>(value);
        return true;
    }

    bool text(std::string_view& out) {
        uint8_t size = 0;
        std::span<const uint8_t> field;
        if (!number(size) || !take(size, field)) return false;
        out = {reinterpret_cast<const char*>(field.data()), field.size()};
        return true;
    }

    bool blob(std::span<const uint8_t>& out) {
        uint16_t size = 0;
        return number(size) && take(size, out);
    }

    bool done() const { return bytes_.empty(); }

private:
    std::span<const uint8_t> bytes_;
};

class Writer {
public:
    explicit Writer(uint8_t* data = nullptr) : data_(data) {}

    void bytes(std::span<const uint8_t> bytes) {
        if (data_ != nullptr && !bytes.empty()) std::memcpy(data_ + size_, bytes.data(), bytes.size());
        size_ += bytes.size();
    }

    void number(uint64_t value, size_t size = 1) {
        if (data_ != nullptr) {
            for (size_t i = 0; i < size; ++i) {
                data_[size_ + i] = static_cast<uint8_t>(value >> (8 * (size - 1 - i)));
            }
        }
        size_ += size;
    }

    void text(std::string_view text) {
        number(text.size());
        bytes({reinterpret_cast<const uint8_t*>(text.data()), text.size()});
    }

    void blob(std::span<const uint8_t> blob) {
        number(blob.size(), 2);
        bytes(blob);
    }

    size_t size() const { return size_; }

private:
    uint8_t* data_;
    size_t size_ = 0;
};

bool validLabels(std::span<const uint8_t> bytes) {
    Reader reader(bytes);
    uint8_t version = 0;
    uint8_t count = 0;
    if (!reader.number(version) || version != 1 || !reader.number(count) || count > kMaxLabels) return false;
    std::array<uint64_t, kMaxLabels> ids{};
    for (size_t i = 0; i < count; ++i) {
        uint8_t flags = 0;
        std::string_view name;
        if (!reader.number(ids[i]) || !reader.number(flags) || (flags & ~3) != 0 || !reader.text(name) ||
            !validText(name, kMaxLabelNameBytes, kMaxLabelNameCodePoints) || (flags == 0 && name.empty())) {
            return false;
        }
        for (size_t j = 0; j < i; ++j) if (ids[i] == ids[j]) return false;
        if ((flags & 2) != 0) {
            WeeklyWindow window;
            if (!reader.number(window.days) || !reader.number(window.startMinute) ||
                !reader.number(window.endMinute) || !isWeeklyWindow(window)) return false;
        }
    }
    return reader.done();
}

bool validSeeds(std::span<const uint8_t> bytes) {
    if (bytes.empty()) return true;
    if (bytes.size() != kSeedTableSize || bytes[0] != 1 || bytes[1] > 1) return false;
    const uint16_t year = static_cast<uint16_t>((bytes[2] << 8) | bytes[3]);
    return year >= 2000 && year <= 2099;
}

bool validMac(const BackupLock& lock) {
    if (lock.mac.size() != 17) return false;
    for (size_t i = 0; i < lock.mac.size(); ++i) {
        const char value = lock.mac[i];
        if (i % 3 == 2) {
            if (value != ':') return false;
        } else if (!((value >= '0' && value <= '9') || (value >= 'A' && value <= 'F'))) {
            return false;
        }
    }
    return true;
}

bool validLock(const BackupLock& lock) {
    constexpr uint8_t recordFlags = kBackupPairComplete | kBackupAdminPasscodeConfirmed | kBackupTimeCalibrated;
    constexpr uint8_t lifecycleFlags = kBackupBackedUp | kBackupHardened | kBackupResetButtonOff;
    if ((lock.flags & ~recordFlags) != 0 || (lock.lifecycle & ~lifecycleFlags) != 0 || lock.addressType > 3 ||
        lock.provenance > AdminProvenance::PairingGenerated ||
        lock.pendingProvenance > AdminProvenance::PairingGenerated || !validMac(lock) || lock.aesKey.size() != 16 ||
        lock.protocol.protocolType != 5 || lock.protocol.protocolVersion != 3 || lock.protocol.scene != 1 ||
        lock.protocol.groupId == 0 || lock.protocol.orgId == 0) return false;
    if (!validText(lock.name, 99) || !validText(lock.model, 31) || !validText(lock.hardware, 31) ||
        !validText(lock.firmware, 31) || !validText(lock.manufactureDate, 15)) return false;
    if ((!lock.adminPasscode.empty() && !ttlock::isPasscode(lock.adminPasscode)) ||
        ((lock.flags & kBackupAdminPasscodeConfirmed) != 0 && lock.adminPasscode.empty()) ||
        (!lock.pendingAdminPasscode.empty() && (!ttlock::isPasscode(lock.pendingAdminPasscode) ||
                                               lock.pendingAdminPasscode == lock.adminPasscode)) ||
        (lock.pendingAdminPasscode.empty() && lock.pendingProvenance != AdminProvenance::LegacyUnknown)) return false;
    for (const auto labels : lock.labels) if (!validLabels(labels)) return false;
    return validSeeds(lock.seeds);
}

void writeLock(const BackupLock& lock, Writer& writer) {
    writer.number(lock.flags);
    writer.number(lock.lifecycle);
    writer.number(lock.addressType);
    writer.number(static_cast<uint8_t>(lock.provenance));
    writer.number(static_cast<uint8_t>(lock.pendingProvenance));
    writer.bytes(lock.address);
    writer.bytes({reinterpret_cast<const uint8_t*>(lock.mac.data()), lock.mac.size()});
    writer.number(lock.protocol.protocolType);
    writer.number(lock.protocol.protocolVersion);
    writer.number(lock.protocol.scene);
    writer.number(lock.protocol.groupId, 2);
    writer.number(lock.protocol.orgId, 2);
    writer.bytes(lock.aesKey);
    writer.number(lock.adminPs, 4);
    writer.number(lock.unlockKey, 4);
    writer.number(lock.lockFlagPos, 4);
    writer.number(lock.features, 8);
    writer.text(lock.name);
    writer.text(lock.adminPasscode);
    writer.text(lock.pendingAdminPasscode);
    writer.text(lock.model);
    writer.text(lock.hardware);
    writer.text(lock.firmware);
    writer.text(lock.manufactureDate);
    for (const auto labels : lock.labels) writer.blob(labels);
    writer.blob(lock.seeds);
}

bool readLock(Reader& reader, BackupLock& lock) {
    std::span<const uint8_t> record;
    if (!reader.blob(record)) return false;
    Reader fields(record);
    std::span<const uint8_t> address;
    std::span<const uint8_t> mac;
    if (!fields.number(lock.flags) || !fields.number(lock.lifecycle) || !fields.number(lock.addressType) ||
        !fields.number(lock.provenance, 1) || !fields.number(lock.pendingProvenance, 1) ||
        !fields.take(6, address) || !fields.take(17, mac)) return false;
    std::copy(address.begin(), address.end(), lock.address.begin());
    lock.mac = {reinterpret_cast<const char*>(mac.data()), mac.size()};
    if (!fields.number(lock.protocol.protocolType) || !fields.number(lock.protocol.protocolVersion) ||
        !fields.number(lock.protocol.scene) || !fields.number(lock.protocol.groupId) ||
        !fields.number(lock.protocol.orgId) || !fields.take(16, lock.aesKey) || !fields.number(lock.adminPs) ||
        !fields.number(lock.unlockKey) || !fields.number(lock.lockFlagPos) || !fields.number(lock.features) ||
        !fields.text(lock.name) || !fields.text(lock.adminPasscode) || !fields.text(lock.pendingAdminPasscode) ||
        !fields.text(lock.model) || !fields.text(lock.hardware) || !fields.text(lock.firmware) ||
        !fields.text(lock.manufactureDate)) return false;
    for (auto& labels : lock.labels) if (!fields.blob(labels)) return false;
    return fields.blob(lock.seeds) && fields.done() && validLock(lock);
}

}

SensitiveBuffer::~SensitiveBuffer() { clear(); }

BackupLock::~BackupLock() {
    wipe(&adminPs, sizeof(adminPs));
    wipe(&unlockKey, sizeof(unlockKey));
    wipe(&lockFlagPos, sizeof(lockFlagPos));
}

SensitiveBuffer::SensitiveBuffer(SensitiveBuffer&& other) noexcept { *this = std::move(other); }

SensitiveBuffer& SensitiveBuffer::operator=(SensitiveBuffer&& other) noexcept {
    if (this == &other) return *this;
    clear();
    data_ = std::exchange(other.data_, nullptr);
    size_ = std::exchange(other.size_, 0);
    capacity_ = std::exchange(other.capacity_, 0);
    return *this;
}

bool SensitiveBuffer::allocate(size_t size, size_t capacity) {
    if (capacity == 0) capacity = size;
    if (size > capacity || capacity > kMaxBackupEnvelope) return false;
    uint8_t* data = capacity == 0 ? nullptr : static_cast<uint8_t*>(std::calloc(capacity, 1));
    if (capacity != 0 && data == nullptr) return false;
    clear();
    data_ = data;
    size_ = size;
    capacity_ = capacity;
    return true;
}

bool SensitiveBuffer::resize(size_t size) {
    if (size > capacity_) return false;
    if (size < size_) wipe(data_ + size, size_ - size);
    size_ = size;
    return true;
}

void SensitiveBuffer::clear() {
    wipe(data_, capacity_);
    std::free(data_);
    data_ = nullptr;
    size_ = capacity_ = 0;
}

uint8_t* SensitiveBuffer::data() { return data_; }
const uint8_t* SensitiveBuffer::data() const { return data_; }
size_t SensitiveBuffer::size() const { return size_; }
size_t SensitiveBuffer::capacity() const { return capacity_; }

DecodedBackup::DecodedBackup(DecodedBackup&& other) noexcept { *this = std::move(other); }

DecodedBackup& DecodedBackup::operator=(DecodedBackup&& other) noexcept {
    if (this == &other) return *this;
    plaintext_ = std::move(other.plaintext_);
    locks_ = std::move(other.locks_);
    count_ = std::exchange(other.count_, 0);
    return *this;
}

std::span<const BackupLock> DecodedBackup::locks() const { return {locks_.get(), count_}; }

BackupStatus encodeBackup(std::span<const BackupLock> locks, SensitiveBuffer& out) {
    if (locks.empty()) return BackupStatus::Invalid;
    if (locks.size() > kMaxBackupLocks) return BackupStatus::TooLarge;
    size_t size = 2;
    for (size_t i = 0; i < locks.size(); ++i) {
        if (!validLock(locks[i])) return BackupStatus::Invalid;
        for (size_t j = 0; j < i; ++j) if (locks[i].mac == locks[j].mac) return BackupStatus::Duplicate;
        Writer measure;
        writeLock(locks[i], measure);
        size += 2 + measure.size();
        if (size > kMaxBackupPlaintext) return BackupStatus::TooLarge;
    }
    SensitiveBuffer encoded;
    if (!encoded.allocate(size, size + kBackupHeaderSize + kBackupTagSize)) return BackupStatus::NoMemory;
    Writer writer(encoded.data());
    writer.number(1);
    writer.number(locks.size());
    for (const auto& lock : locks) {
        Writer measure;
        writeLock(lock, measure);
        writer.number(measure.size(), 2);
        writeLock(lock, writer);
    }
    out = std::move(encoded);
    return BackupStatus::Ok;
}

BackupStatus decodeBackup(SensitiveBuffer plaintext, DecodedBackup& out) {
    if (plaintext.size() < 2 || plaintext.size() > kMaxBackupPlaintext || plaintext.data()[0] != 1 ||
        plaintext.data()[1] == 0 || plaintext.data()[1] > kMaxBackupLocks) return BackupStatus::Invalid;
    const size_t count = plaintext.data()[1];
    std::array<std::string_view, kMaxBackupLocks> identities{};
    Reader verify({plaintext.data() + 2, plaintext.size() - 2});
    for (size_t i = 0; i < count; ++i) {
        BackupLock lock;
        if (!readLock(verify, lock)) return BackupStatus::Invalid;
        for (size_t j = 0; j < i; ++j) if (lock.mac == identities[j]) return BackupStatus::Duplicate;
        identities[i] = lock.mac;
    }
    if (!verify.done()) return BackupStatus::Invalid;
    DecodedBackup decoded;
    decoded.locks_.reset(new (std::nothrow) BackupLock[count]);
    if (decoded.locks_ == nullptr) return BackupStatus::NoMemory;
    Reader reader({plaintext.data() + 2, plaintext.size() - 2});
    for (size_t i = 0; i < count; ++i) {
        if (!readLock(reader, decoded.locks_[i])) return BackupStatus::Invalid;
    }
    decoded.count_ = count;
    decoded.plaintext_ = std::move(plaintext);
    out = std::move(decoded);
    return BackupStatus::Ok;
}

std::array<uint8_t, kBackupHeaderSize> encodeBackupHeader(const BackupHeader& header) {
    std::array<uint8_t, kBackupHeaderSize> bytes{};
    Writer writer(bytes.data());
    const uint8_t prefix[] = {'L', 'K', 'B', '2', 1, 1};
    writer.bytes(prefix);
    writer.number(kBackupIterations, 4);
    writer.bytes(header.salt);
    writer.bytes(header.nonce);
    return bytes;
}

bool parseBackupHeader(std::span<const uint8_t> bytes, BackupHeader& out) {
    const uint8_t prefix[] = {'L', 'K', 'B', '2', 1, 1};
    if (bytes.size() != kBackupHeaderSize || !std::equal(std::begin(prefix), std::end(prefix), bytes.begin())) {
        return false;
    }
    Reader reader(bytes.subspan(sizeof(prefix)));
    uint32_t iterations = 0;
    if (!reader.number(iterations) || iterations != kBackupIterations) return false;
    BackupHeader header;
    std::copy_n(bytes.begin() + 10, header.salt.size(), header.salt.begin());
    std::copy_n(bytes.begin() + 26, header.nonce.size(), header.nonce.begin());
    out = header;
    return true;
}

BackupStatus sealBackup(SensitiveBuffer plaintext, std::string_view password, BackupCrypto& crypto,
                         SensitiveBuffer& out) {
    if (plaintext.size() < 2 || password.size() < 12 || !validText(password, 128)) return BackupStatus::Invalid;
    if (plaintext.size() > kMaxBackupPlaintext) return BackupStatus::TooLarge;
    const size_t plainSize = plaintext.size();
    const size_t envelopeSize = kBackupHeaderSize + plainSize + kBackupTagSize;
    if (plaintext.capacity() < envelopeSize) {
        SensitiveBuffer expanded;
        if (!expanded.allocate(plainSize, envelopeSize)) return BackupStatus::NoMemory;
        std::memcpy(expanded.data(), plaintext.data(), plainSize);
        plaintext = std::move(expanded);
    }
    BackupHeader header;
    if (!crypto.random(header.salt) || !crypto.random(header.nonce)) return BackupStatus::CryptoFailed;
    BackupKey key;
    if (!crypto.deriveKey(password, header.salt, key.bytes)) return BackupStatus::CryptoFailed;
    const auto aad = encodeBackupHeader(header);
    plaintext.resize(envelopeSize);
    std::memmove(plaintext.data() + kBackupHeaderSize, plaintext.data(), plainSize);
    std::copy(aad.begin(), aad.end(), plaintext.data());
    if (!crypto.seal(key.bytes, header.nonce, {plaintext.data(), kBackupHeaderSize},
                     {plaintext.data() + kBackupHeaderSize, plainSize + kBackupTagSize})) {
        return BackupStatus::CryptoFailed;
    }
    out = std::move(plaintext);
    return BackupStatus::Ok;
}

BackupStatus openBackup(SensitiveBuffer envelope, std::string_view password, BackupCrypto& crypto,
                         SensitiveBuffer& out) {
    if (envelope.size() < kBackupHeaderSize + kBackupTagSize + 2 || envelope.size() > kMaxBackupEnvelope ||
        password.size() < 12 || !validText(password, 128)) return BackupStatus::Invalid;
    BackupHeader header;
    if (!parseBackupHeader({envelope.data(), kBackupHeaderSize}, header)) return BackupStatus::Invalid;
    BackupKey key;
    if (!crypto.deriveKey(password, header.salt, key.bytes)) return BackupStatus::CryptoFailed;
    if (!crypto.open(key.bytes, header.nonce, {envelope.data(), kBackupHeaderSize},
                     {envelope.data() + kBackupHeaderSize, envelope.size() - kBackupHeaderSize})) {
        return BackupStatus::CryptoFailed;
    }
    const size_t plainSize = envelope.size() - kBackupHeaderSize - kBackupTagSize;
    std::memmove(envelope.data(), envelope.data() + kBackupHeaderSize, plainSize);
    envelope.resize(plainSize);
    out = std::move(envelope);
    return BackupStatus::Ok;
}

}
