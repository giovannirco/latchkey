// SPDX-License-Identifier: GPL-3.0-or-later
#include "key_store.h"

#include <algorithm>
#include <cstring>

#include "mbedtls/platform_util.h"
#include "nvs.h"

namespace key_store {
namespace {

using latchkey_util::RestorePart;
constexpr const char* kMetadataNamespace = "lockmeta";
constexpr const char* kJournalNamespace = "restore";
constexpr const char* kJournalKey = "pending";

class Handle {
public:
    Handle(const char* name, nvs_open_mode_t mode) : error_(nvs_open(name, mode, &handle_)) {}
    ~Handle() { if (error_ == ESP_OK) nvs_close(handle_); }
    Handle(const Handle&) = delete;
    Handle& operator=(const Handle&) = delete;
    esp_err_t error() const { return error_; }
    nvs_handle_t get() const { return handle_; }

private:
    nvs_handle_t handle_ = 0;
    esp_err_t error_;
};

bool identityKey(std::string_view mac, char (&key)[14]) {
    if (mac.size() != 17) return false;
    size_t at = 0;
    for (size_t i = 0; i < mac.size(); ++i) {
        const char value = mac[i];
        if (i % 3 == 2) {
            if (value != ':') return false;
        } else {
            if (!((value >= '0' && value <= '9') || (value >= 'A' && value <= 'F'))) return false;
            key[at++] = value;
        }
    }
    key[at] = '\0';
    return true;
}

const char* partKey(std::string_view mac, RestorePart part, char (&key)[14]) {
    if (!identityKey(mac, key)) return nullptr;
    switch (part) {
        case RestorePart::Record: return "locks";
        case RestorePart::Seeds: return "seeds";
        case RestorePart::Metadata: return kMetadataNamespace;
        case RestorePart::Passcodes: key[12] = 'p'; break;
        case RestorePart::Fingerprints: key[12] = 'f'; break;
        case RestorePart::Cards: key[12] = 'c'; break;
        default: return nullptr;
    }
    key[13] = '\0';
    return "labels";
}

esp_err_t readBlob(const char* name, const char* key, void* out, size_t& length) {
    Handle handle(name, NVS_READONLY);
    if (handle.error() != ESP_OK) return handle.error();
    return nvs_get_blob(handle.get(), key, out, &length);
}

esp_err_t writeBlob(const char* name, const char* key, const void* value, size_t length) {
    Handle handle(name, NVS_READWRITE);
    if (handle.error() != ESP_OK) return handle.error();
    const auto error = nvs_set_blob(handle.get(), key, value, length);
    return error == ESP_OK ? nvs_commit(handle.get()) : error;
}

esp_err_t contains(const char* name, const char* key, bool& out) {
    Handle handle(name, NVS_READONLY);
    esp_err_t error = handle.error();
    if (error == ESP_OK) {
        nvs_type_t type;
        error = nvs_find_key(handle.get(), key, &type);
    }
    if (error != ESP_OK && error != ESP_ERR_NVS_NOT_FOUND) return error;
    out = error == ESP_OK;
    return ESP_OK;
}

esp_err_t eraseBlob(const char* name, const char* key) {
    bool present = false;
    const auto found = contains(name, key, present);
    if (found != ESP_OK || !present) return found;
    Handle handle(name, NVS_READWRITE);
    if (handle.error() != ESP_OK) return handle.error();
    const auto error = nvs_erase_key(handle.get(), key);
    return error == ESP_OK ? nvs_commit(handle.get()) : error;
}

template <size_t N>
bool copyText(char (&out)[N], std::string_view text) {
    if (text.size() >= N || text.find('\0') != std::string_view::npos) return false;
    std::memcpy(out, text.data(), text.size());
    std::memset(out + text.size(), 0, N - text.size());
    return true;
}

bool makeRecord(const latchkey_util::BackupLock& lock, store::locks::Record& record) {
    std::memset(static_cast<void*>(&record), 0, sizeof(record));
    record.version = store::locks::kRecordVersion;
    if (lock.aesKey.size() != sizeof(record.aesKey) || !copyText(record.mac, lock.mac) ||
        !copyText(record.name, lock.name) || !copyText(record.adminPasscode, lock.adminPasscode) ||
        !copyText(record.model, lock.model) || !copyText(record.hardware, lock.hardware) ||
        !copyText(record.firmware, lock.firmware) || !copyText(record.manufactureDate, lock.manufactureDate)) return false;
    record.flags = lock.flags;
    record.addressType = lock.addressType;
    std::copy(lock.address.begin(), lock.address.end(), record.address);
    record.protocolType = lock.protocol.protocolType;
    record.protocolVersion = lock.protocol.protocolVersion;
    record.scene = lock.protocol.scene;
    record.groupId = lock.protocol.groupId;
    record.orgId = lock.protocol.orgId;
    std::copy(lock.aesKey.begin(), lock.aesKey.end(), record.aesKey);
    record.adminPs = lock.adminPs;
    record.unlockKey = lock.unlockKey;
    record.lockFlagPos = lock.lockFlagPos;
    record.features = lock.features;
    return true;
}

template <size_t N>
bool terminated(const char (&field)[N]) { return std::memchr(field, '\0', N) != nullptr; }

}

bool Restore::readJournal(latchkey_util::RestoreJournal& out, bool& present) {
    std::array<uint8_t, latchkey_util::kRestoreJournalBytes> bytes{};
    size_t length = bytes.size();
    const auto error = readBlob(kJournalNamespace, kJournalKey, bytes.data(), length);
    if (error == ESP_ERR_NVS_NOT_FOUND) {
        present = false;
        return true;
    }
    if (error != ESP_OK || !latchkey_util::decodeRestoreJournal({bytes.data(), length}, out)) return false;
    present = true;
    return true;
}

bool Restore::countRecords(size_t& out) {
    Handle handle("locks", NVS_READONLY);
    if (handle.error() == ESP_ERR_NVS_NOT_FOUND) {
        out = 0;
        return true;
    }
    if (handle.error() != ESP_OK) return false;
    size_t count = 0;
    nvs_iterator_t entry = nullptr;
    auto error = nvs_entry_find_in_handle(handle.get(), NVS_TYPE_ANY, &entry);
    while (error == ESP_OK) {
        ++count;
        error = nvs_entry_next(&entry);
    }
    nvs_release_iterator(entry);
    if (error != ESP_ERR_NVS_NOT_FOUND) return false;
    out = count;
    return true;
}

bool Restore::containsIdentity(std::string_view mac, bool& out) {
    for (const auto part : latchkey_util::kRestoreParts) {
        char key[14];
        const auto* name = partKey(mac, part, key);
        bool present = false;
        if (name == nullptr || contains(name, key, present) != ESP_OK) return false;
        if (present) {
            out = true;
            return true;
        }
    }
    char key[14];
    if (!identityKey(mac, key)) return false;
    for (const auto* name : {"watch", "alerts"}) {
        bool present = false;
        if (contains(name, key, present) != ESP_OK) return false;
        if (present) {
            out = true;
            return true;
        }
    }
    out = false;
    return true;
}

bool Restore::capacity(size_t& availableEntries, size_t& reservedEntries) {
    store::Usage usage;
    if (store::usage(usage) != ESP_OK) return false;
    Handle audit("audit", NVS_READONLY);
    uint32_t sequence = 1;
    auto error = audit.error();
    if (error == ESP_OK) error = nvs_get_u32(audit.get(), "next", &sequence);
    if (error != ESP_OK && error != ESP_ERR_NVS_NOT_FOUND) return false;
    availableEntries = usage.availableEntries;
    reservedEntries = store::reservedEntries(sequence);
    return true;
}

size_t Restore::recordBytes() const { return sizeof(store::locks::Record); }

bool Restore::writeJournal(const latchkey_util::RestoreJournal& journal) {
    std::array<uint8_t, latchkey_util::kRestoreJournalBytes> bytes{};
    size_t length = 0;
    if (!latchkey_util::encodeRestoreJournal(journal, bytes, length)) return false;
    return writeBlob(kJournalNamespace, kJournalKey, bytes.data(), length) == ESP_OK;
}

bool Restore::writePart(const latchkey_util::BackupLock& lock, RestorePart part) {
    char key[14];
    const auto* name = partKey(lock.mac, part, key);
    if (name == nullptr) return false;
    if (part == RestorePart::Record) {
        store::locks::Record record;
        const auto error = makeRecord(lock, record) ? writeBlob(name, key, &record, sizeof(record)) : ESP_ERR_INVALID_ARG;
        mbedtls_platform_zeroize(&record, sizeof(record));
        return error == ESP_OK;
    }
    if (part == RestorePart::Metadata) {
        latchkey_util::LockMetadata metadata;
        metadata.lifecycle = lock.lifecycle;
        metadata.provenance = lock.provenance;
        metadata.pendingProvenance = lock.pendingProvenance;
        if (lock.pendingAdminPasscode.size() >= metadata.pendingAdminPasscode.size()) return false;
        std::copy(lock.pendingAdminPasscode.begin(), lock.pendingAdminPasscode.end(), metadata.pendingAdminPasscode.begin());
        return saveMetadata(lock.mac, metadata) == ESP_OK;
    }
    std::span<const uint8_t> bytes;
    switch (part) {
        case RestorePart::Passcodes: bytes = lock.labels[0]; break;
        case RestorePart::Fingerprints: bytes = lock.labels[1]; break;
        case RestorePart::Cards: bytes = lock.labels[2]; break;
        case RestorePart::Seeds: bytes = lock.seeds; break;
        default: return false;
    }
    return bytes.empty() || writeBlob(name, key, bytes.data(), bytes.size()) == ESP_OK;
}

bool Restore::erasePart(std::string_view mac, RestorePart part) {
    char key[14];
    const auto* name = partKey(mac, part, key);
    return name != nullptr && eraseBlob(name, key) == ESP_OK;
}

bool Restore::clearJournal() { return eraseBlob(kJournalNamespace, kJournalKey) == ESP_OK; }

esp_err_t recover() {
    Restore storage;
    return latchkey_util::recoverKeys(storage) == latchkey_util::RestoreStatus::Ok ? ESP_OK : ESP_ERR_INVALID_STATE;
}

esp_err_t loadRecord(std::string_view mac, store::locks::Record& out) {
    char key[14];
    if (!identityKey(mac, key)) return ESP_ERR_INVALID_ARG;
    store::locks::Record record;
    size_t length = sizeof(record);
    auto error = readBlob("locks", key, &record, length);
    if (error == ESP_OK &&
        (length != sizeof(record) || record.version != store::locks::kRecordVersion || !terminated(record.mac) ||
         mac != record.mac || !terminated(record.name) || !terminated(record.adminPasscode) || !terminated(record.model) ||
         !terminated(record.hardware) || !terminated(record.firmware) || !terminated(record.manufactureDate))) {
        error = ESP_ERR_INVALID_CRC;
    }
    if (error == ESP_OK) out = record;
    mbedtls_platform_zeroize(&record, sizeof(record));
    return error;
}

esp_err_t loadMetadata(std::string_view mac, latchkey_util::LockMetadata& out) {
    char key[14];
    if (!identityKey(mac, key)) return ESP_ERR_INVALID_ARG;
    std::array<uint8_t, latchkey_util::kLockMetadataBytes> bytes{};
    size_t length = bytes.size();
    auto error = readBlob(kMetadataNamespace, key, bytes.data(), length);
    if (error == ESP_ERR_NVS_NOT_FOUND) {
        out = latchkey_util::LockMetadata{};
        error = ESP_OK;
    } else if (error == ESP_OK && !latchkey_util::decodeLockMetadata({bytes.data(), length}, out)) {
        error = ESP_ERR_INVALID_CRC;
    }
    mbedtls_platform_zeroize(bytes.data(), bytes.size());
    return error;
}

esp_err_t saveMetadata(std::string_view mac, const latchkey_util::LockMetadata& metadata) {
    char key[14];
    if (!identityKey(mac, key)) return ESP_ERR_INVALID_ARG;
    std::array<uint8_t, latchkey_util::kLockMetadataBytes> bytes{};
    const auto error = latchkey_util::encodeLockMetadata(metadata, bytes)
                           ? writeBlob(kMetadataNamespace, key, bytes.data(), bytes.size()) : ESP_ERR_INVALID_ARG;
    mbedtls_platform_zeroize(bytes.data(), bytes.size());
    return error;
}

esp_err_t eraseMetadata(std::string_view mac) {
    char key[14];
    if (!identityKey(mac, key)) return ESP_ERR_INVALID_ARG;
    return eraseBlob(kMetadataNamespace, key);
}

esp_err_t loadSeeds(std::string_view mac, latchkey_util::SeedTable& out, bool& present) {
    char key[14];
    if (!identityKey(mac, key)) return ESP_ERR_INVALID_ARG;
    std::array<uint8_t, latchkey_util::kSeedTableSize> bytes{};
    size_t length = bytes.size();
    auto error = readBlob("seeds", key, bytes.data(), length);
    if (error == ESP_ERR_NVS_NOT_FOUND) {
        out = latchkey_util::SeedTable{};
        present = false;
        error = ESP_OK;
    } else if (error == ESP_OK) {
        latchkey_util::SeedTable table;
        if (!latchkey_util::decodeSeedTable(bytes.data(), length, table) || table.year < 2000 || table.year > 2099) {
            error = ESP_ERR_INVALID_CRC;
        } else {
            out = table;
            present = true;
        }
        mbedtls_platform_zeroize(&table, sizeof(table));
    }
    mbedtls_platform_zeroize(bytes.data(), bytes.size());
    return error;
}

}
