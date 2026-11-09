// SPDX-License-Identifier: GPL-3.0-or-later
#include "backup.h"

#include <algorithm>
#include <array>
#include <cstring>
#include <string_view>

#include "key_store.h"
#include "latchkey_util/rpc_text.h"

namespace backup {
namespace {

using latchkey_util::BackupStatus;
using latchkey_util::RestoreStatus;
using latchkey_util::SensitiveBuffer;
constexpr size_t kMaxEncodedBytes = ((latchkey_util::kMaxBackupEnvelope + 2) / 3) * 4;
constexpr char kAlphabet[] = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";

rpc::Reply invalid(const char* message) { return rpc::fail("invalid_argument", message); }
rpc::Reply noMemory() { return rpc::fail("internal", "not enough memory for the backup operation"); }

bool isText(const cJSON* item) { return cJSON_IsString(item) && item->valuestring != nullptr; }

bool fields(const cJSON* params, const char* second, bool required) {
    if (!cJSON_IsObject(params)) return false;
    unsigned seen = 0;
    for (const cJSON* item = params->child; item != nullptr; item = item->next) {
        if (item->string == nullptr) return false;
        const unsigned flag = std::strcmp(item->string, "passphrase") == 0 ? 1 :
                              std::strcmp(item->string, second) == 0 ? 2 : 0;
        if (flag == 0 || (seen & flag) != 0) return false;
        seen |= flag;
    }
    const auto* password = cJSON_GetObjectItemCaseSensitive(params, "passphrase");
    return (seen & 1) != 0 && (!required || seen == 3) && isText(password) &&
           latchkey_util::isBackupPassphrase(password->valuestring);
}

bool canonicalMac(std::string_view value) {
    if (value.size() != 17) return false;
    for (size_t i = 0; i < value.size(); ++i) {
        if (i % 3 == 2) {
            if (value[i] != ':') return false;
        } else if (!((value[i] >= '0' && value[i] <= '9') || (value[i] >= 'A' && value[i] <= 'F'))) return false;
    }
    return true;
}

int digit(char value) {
    if (value >= 'A' && value <= 'Z') return value - 'A';
    if (value >= 'a' && value <= 'z') return value - 'a' + 26;
    if (value >= '0' && value <= '9') return value - '0' + 52;
    if (value == '+') return 62;
    if (value == '/') return 63;
    return -1;
}

bool decodedSize(std::string_view encoded, size_t& out) {
    if (encoded.empty() || encoded.size() > kMaxEncodedBytes || encoded.size() % 4 != 0) return false;
    const size_t padding = encoded.back() == '=' ? (encoded[encoded.size() - 2] == '=' ? 2 : 1) : 0;
    const size_t digits = encoded.size() - padding;
    for (size_t i = 0; i < digits; ++i) if (digit(encoded[i]) < 0) return false;
    if (padding == 2 && (digit(encoded[digits - 1]) & 15) != 0) return false;
    if (padding == 1 && (digit(encoded[digits - 1]) & 3) != 0) return false;
    const size_t size = (encoded.size() / 4) * 3 - padding;
    if (size < latchkey_util::kBackupHeaderSize + latchkey_util::kBackupTagSize + 2 ||
        size > latchkey_util::kMaxBackupEnvelope) return false;
    out = size;
    return true;
}

void decodePrefix(std::string_view encoded, std::span<uint8_t> out) {
    size_t written = 0;
    for (size_t at = 0; written < out.size(); at += 4) {
        uint32_t value = 0;
        for (size_t i = 0; i < 4; ++i) value = (value << 6) | (encoded[at + i] == '=' ? 0 : digit(encoded[at + i]));
        for (size_t i = 0; i < 3 && written < out.size(); ++i) out[written++] = value >> (16 - 8 * i);
    }
}

void encodeBase64(std::span<const uint8_t> bytes, char* out) {
    size_t written = 0;
    for (size_t at = 0; at < bytes.size(); at += 3) {
        const size_t count = std::min(size_t{3}, bytes.size() - at);
        uint32_t value = 0;
        for (size_t i = 0; i < 3; ++i) value = (value << 8) | (i < count ? bytes[at + i] : 0);
        out[written++] = kAlphabet[(value >> 18) & 63];
        out[written++] = kAlphabet[(value >> 12) & 63];
        out[written++] = count > 1 ? kAlphabet[(value >> 6) & 63] : '=';
        out[written++] = count > 2 ? kAlphabet[value & 63] : '=';
    }
}

rpc::Json resultWithIds(const char* field, const latchkey_util::RestoreJournal& identities) {
    rpc::Json result(cJSON_CreateObject());
    rpc::Json array(cJSON_CreateArray());
    if (!result || !array || !cJSON_AddItemToObjectCS(result.get(), field, array.get())) return {};
    cJSON* items = array.release();
    for (size_t i = 0; i < identities.count; ++i) {
        rpc::Json item(cJSON_CreateString(identities.identities[i].data()));
        if (!item || !cJSON_AddItemToArray(items, item.get())) return {};
        item.release();
    }
    return result;
}

rpc::Reply restoreFailure(RestoreStatus status) {
    switch (status) {
        case RestoreStatus::Invalid: return invalid("the backup contains invalid lock data");
        case RestoreStatus::Conflict: return rpc::fail("conflict", "the backup contains lock identities already stored on this board");
        case RestoreStatus::Capacity: return rpc::fail("storage_full", "the backup exceeds the available lock slots or reserved storage capacity");
        case RestoreStatus::ReadFailed: return rpc::fail("internal", "cannot read the current lock storage state");
        case RestoreStatus::WriteFailed: return rpc::fail("internal", "the restore failed; newly imported data was removed");
        case RestoreStatus::RecoveryRequired: return rpc::fail("recovery_required", "lock storage requires recovery and a restart before more changes");
        case RestoreStatus::NoMemory: return noMemory();
        case RestoreStatus::Ok: break;
    }
    return rpc::fail("internal", "unexpected restore result");
}

}

rpc::Reply checkExport(cJSON* params, const rpc::Context&) {
    if (!fields(params, "lock", false)) return invalid("passphrase must contain 12 to 128 UTF-8 bytes; only passphrase and lock are accepted");
    const auto* lock = cJSON_GetObjectItemCaseSensitive(params, "lock");
    if (lock != nullptr && (!isText(lock) || !canonicalMac(lock->valuestring))) {
        return invalid("lock must be a canonical uppercase Bluetooth address");
    }
    return rpc::ok();
}

rpc::Reply checkImport(cJSON* params, const rpc::Context&) {
    if (!fields(params, "backup", true)) return invalid("passphrase must contain 12 to 128 UTF-8 bytes and backup is required");
    const auto* encoded = cJSON_GetObjectItemCaseSensitive(params, "backup");
    size_t size = 0;
    if (!isText(encoded) || !decodedSize(encoded->valuestring, size)) return invalid("backup must be bounded canonical base64");
    std::array<uint8_t, latchkey_util::kBackupHeaderSize> bytes{};
    decodePrefix(encoded->valuestring, bytes);
    latchkey_util::BackupHeader header;
    if (!latchkey_util::parseBackupHeader(bytes, header)) return invalid("unsupported or damaged backup header");
    return rpc::ok();
}

rpc::Reply exportKeys(cJSON* params, latchkey_util::BackupCrypto& crypto,
                       lock_manager::StoragePublication& publication) {
    auto checked = checkExport(params, {rpc::Transport::Serial, {}});
    if (!checked.error.empty()) return checked;
    checked.result.reset();
    const auto* lock = cJSON_GetObjectItemCaseSensitive(params, "lock");
    SensitiveBuffer plaintext;
    latchkey_util::RestoreJournal selected;
    const auto snapshot = key_store::snapshot(lock == nullptr ? std::string_view{} : lock->valuestring,
                                              plaintext, selected);
    if (snapshot == ESP_ERR_INVALID_SIZE) return rpc::fail("too_large", "backup exceeds 8 KiB; export individual locks");
    if (snapshot == ESP_ERR_NO_MEM) return noMemory();
    if (snapshot == ESP_ERR_NOT_FOUND) return rpc::fail("not_paired", "no requested lock keys are stored on this board");
    if (snapshot != ESP_OK) return rpc::fail("internal", "cannot export unreadable or invalid stored lock data");
    const auto* password = cJSON_GetObjectItemCaseSensitive(params, "passphrase");
    SensitiveBuffer envelope;
    const auto sealed = latchkey_util::sealBackup(std::move(plaintext), password->valuestring, crypto, envelope);
    cJSON_DeleteItemFromObjectCaseSensitive(params, "passphrase");
    if (sealed == BackupStatus::NoMemory) return noMemory();
    if (sealed != BackupStatus::Ok) return rpc::fail("internal", "cannot encrypt the lock backup");
    latchkey_util::RpcText encoded;
    if (!encoded.resize(((envelope.size() + 2) / 3) * 4)) return noMemory();
    encodeBase64({envelope.data(), envelope.size()}, encoded.data());
    envelope.clear();
    auto result = resultWithIds("locks", selected);
    if (!result || !cJSON_AddStringToObject(result.get(), "backup", encoded.c_str())) return noMemory();
    encoded.clear();
    for (size_t i = 0; i < selected.count; ++i) {
        const std::string_view mac = selected.identities[i].data();
        latchkey_util::LockMetadata metadata;
        if (key_store::loadMetadata(mac, metadata) != ESP_OK) {
            publication.metadataChanged(mac, nullptr);
            return rpc::fail("internal", "cannot read the lock backup state");
        }
        metadata.lifecycle |= latchkey_util::kBackupBackedUp;
        if (key_store::saveMetadata(mac, metadata) != ESP_OK) {
            publication.metadataChanged(mac, nullptr);
            return rpc::fail("internal", "backup was encrypted but its stored status could not be confirmed");
        }
        publication.metadataChanged(mac, &metadata);
    }
    return rpc::ok(result.release());
}

rpc::Reply importKeys(cJSON* params, latchkey_util::BackupCrypto& crypto,
                       latchkey_util::RestoreStorage& storage, lock_manager::StoragePublication& publication) {
    auto checked = checkImport(params, {rpc::Transport::Serial, {}});
    if (!checked.error.empty()) return checked;
    checked.result.reset();
    const auto* encoded = cJSON_GetObjectItemCaseSensitive(params, "backup");
    size_t size = 0;
    if (!decodedSize(encoded->valuestring, size)) return invalid("backup must be bounded canonical base64");
    SensitiveBuffer envelope;
    if (!envelope.allocate(size)) return noMemory();
    decodePrefix(encoded->valuestring, {envelope.data(), envelope.size()});
    cJSON_DeleteItemFromObjectCaseSensitive(params, "backup");
    const auto* password = cJSON_GetObjectItemCaseSensitive(params, "passphrase");
    SensitiveBuffer plaintext;
    const auto opened = latchkey_util::openBackup(std::move(envelope), password->valuestring, crypto, plaintext);
    cJSON_DeleteItemFromObjectCaseSensitive(params, "passphrase");
    if (opened == BackupStatus::NoMemory) return noMemory();
    if (opened != BackupStatus::Ok) return invalid("cannot authenticate the backup with that passphrase");
    latchkey_util::DecodedBackup decoded;
    const auto read = latchkey_util::decodeBackup(std::move(plaintext), decoded);
    if (read == BackupStatus::NoMemory) return noMemory();
    if (read != BackupStatus::Ok) return invalid("the authenticated backup contains invalid or duplicate lock data");
    latchkey_util::RestoreJournal imported;
    imported.count = decoded.locks().size();
    for (size_t i = 0; i < imported.count; ++i) {
        const auto mac = decoded.locks()[i].mac;
        std::copy(mac.begin(), mac.end(), imported.identities[i].begin());
    }
    auto result = resultWithIds("imported", imported);
    if (!result) return noMemory();
    const auto restored = latchkey_util::restoreKeys(decoded, storage, publication);
    if (restored != RestoreStatus::Ok) return restoreFailure(restored);
    return rpc::ok(result.release());
}

}
