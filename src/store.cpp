// SPDX-License-Identifier: GPL-3.0-or-later
#include "store.h"

#include <cstdio>
#include <cstring>
#include <utility>

#include "mbedtls/platform_util.h"
#include "nvs.h"
#include "nvs_flash.h"

#include "latchkey_util/hostname.h"
#include "latchkey_util/storage_budget.h"

namespace store {

namespace {

constexpr const char* kCfgNamespace = "cfg";
constexpr const char* kAuthNamespace = "auth";
constexpr const char* kAuditNamespace = "audit";
constexpr const char* kLocksNamespace = "locks";
constexpr const char* kLabelsNamespace = "labels";
constexpr const char* kSeedsNamespace = "seeds";
constexpr const char* kWatchNamespace = "watch";
constexpr const char* kAlertsNamespace = "alerts";
constexpr const char* kPasswordKey = "password";
constexpr const char* kTotpKey = "totp";
constexpr const char* kTlsKey = "tls";
constexpr const char* kMqttKey = "mqtt";
constexpr uint8_t kMqttRecordVersion = 1;
constexpr size_t kLockKeySize = 13;
constexpr size_t kLabelKeySize = kLockKeySize + 1;
constexpr labels::Kind kLabelKinds[] = {labels::Kind::Passcodes, labels::Kind::Fingerprints, labels::Kind::Cards};
constexpr size_t kSpareEntries = 48;

struct MqttRecord {
    uint8_t version;
    uint8_t enabled;
    uint16_t port;
    char host[latchkey_util::kMaxMqttHost + 1];
    char username[latchkey_util::kMaxMqttUsername + 1];
    char password[latchkey_util::kMaxMqttPassword + 1];
    char prefix[latchkey_util::kMaxHaPrefix + 1];
};

template <size_t N>
bool putText(char (&field)[N], const std::string& value) {
    if (value.size() >= N || value.find('\0') != std::string::npos) {
        return false;
    }
    std::memcpy(field, value.data(), value.size());
    std::memset(field + value.size(), 0, N - value.size());
    return true;
}

template <size_t N>
std::string takeText(const char (&field)[N]) {
    return std::string(field, strnlen(field, N));
}

class Handle {
public:
    Handle(const char* name, nvs_open_mode_t mode) : error_(nvs_open(name, mode, &handle_)) {}

    ~Handle() {
        if (error_ == ESP_OK) {
            nvs_close(handle_);
        }
    }

    Handle(const Handle&) = delete;
    Handle& operator=(const Handle&) = delete;

    bool ok() const { return error_ == ESP_OK; }

    esp_err_t error() const { return error_; }

    nvs_handle_t get() const { return handle_; }

private:
    nvs_handle_t handle_ = 0;
    esp_err_t error_;
};

bool readString(nvs_handle_t handle, const char* key, std::string& out) {
    size_t length = 0;
    if (nvs_get_str(handle, key, nullptr, &length) != ESP_OK || length == 0) {
        return false;
    }
    std::string value(length, '\0');
    if (nvs_get_str(handle, key, value.data(), &length) != ESP_OK) {
        mbedtls_platform_zeroize(value.data(), value.size());
        return false;
    }
    value.resize(length - 1);
    out = value;
    mbedtls_platform_zeroize(value.data(), value.size());
    return true;
}

template <size_t N>
bool readBlob(nvs_handle_t handle, const char* key, std::array<uint8_t, N>& out) {
    size_t length = N;
    return nvs_get_blob(handle, key, out.data(), &length) == ESP_OK && length == N;
}

esp_err_t eraseNamespace(const char* name) {
    Handle handle(name, NVS_READWRITE);
    if (!handle.ok()) {
        return handle.error();
    }
    const esp_err_t error = nvs_erase_all(handle.get());
    return error == ESP_OK ? nvs_commit(handle.get()) : error;
}

void slotKey(uint32_t seq, char (&key)[8]) {
    std::snprintf(key, sizeof(key), "e%03u", static_cast<unsigned>(seq % audit::kCapacity));
}

bool lockKey(const char* mac, char (&key)[kLockKeySize]) {
    size_t length = 0;
    for (const char* c = mac; *c != '\0'; ++c) {
        if (*c == ':') {
            continue;
        }
        if (length + 1 >= sizeof(key)) {
            return false;
        }
        key[length++] = *c;
    }
    key[length] = '\0';
    return length == sizeof(key) - 1;
}

bool labelKey(const char* mac, labels::Kind kind, char (&key)[kLabelKeySize]) {
    char lock[kLockKeySize];
    if (!lockKey(mac, lock)) {
        return false;
    }
    std::memcpy(key, lock, kLockKeySize - 1);
    key[kLockKeySize - 1] = static_cast<char>(kind);
    key[kLockKeySize] = '\0';
    return true;
}

size_t storedBlobSize(const char* name, const char* key) {
    Handle handle(name, NVS_READONLY);
    size_t length = 0;
    if (!handle.ok() || nvs_get_blob(handle.get(), key, nullptr, &length) != ESP_OK) {
        return 0;
    }
    return length;
}

bool roomAboveReserve(size_t blobBytes) {
    nvs_stats_t stats{};
    return nvs_get_stats(nullptr, &stats) == ESP_OK &&
           latchkey_util::fitsAboveReserve(stats.available_entries, blobBytes, reservedEntries());
}

bool growthFits(const char* name, const char* key, size_t blobBytes) {
    return blobBytes <= storedBlobSize(name, key) || roomAboveReserve(blobBytes);
}

constexpr const char* kSyslogKey = "syslog";
constexpr uint8_t kSyslogRecordVersion = 1;

struct SyslogRecord {
    uint8_t version;
    uint8_t enabled;
    uint8_t tcp;
    uint8_t level;
    uint16_t port;
    char host[latchkey_util::kMaxHostname + 1];
    char appName[latchkey_util::kMaxSyslogAppName + 1];
};

template <size_t N>
bool copyText(char (&field)[N], const std::string& value) {
    if (value.size() >= N || value.find('\0') != std::string::npos) {
        return false;
    }
    std::memcpy(field, value.data(), value.size());
    return true;
}

esp_err_t eraseKey(const char* name, const char* key) {
    Handle handle(name, NVS_READWRITE);
    if (!handle.ok()) {
        return handle.error();
    }
    const esp_err_t error = nvs_erase_key(handle.get(), key);
    if (error != ESP_OK && error != ESP_ERR_NVS_NOT_FOUND) {
        return error;
    }
    return nvs_commit(handle.get());
}

}

void init() { ESP_ERROR_CHECK(nvs_flash_init()); }

esp_err_t usage(Usage& out) {
    nvs_stats_t stats{};
    const esp_err_t error = nvs_get_stats(nullptr, &stats);
    if (error == ESP_OK) {
        out = Usage{stats.used_entries, stats.available_entries, stats.total_entries};
    }
    return error;
}

size_t reservedEntries() { return reservedEntries(audit::loadNextSeq()); }

size_t reservedEntries(uint32_t nextAuditSequence) {
    latchkey_util::StorageNeeds needs;
    needs.auditRecordsLeft = latchkey_util::auditRecordsLeft(nextAuditSequence, audit::kCapacity);
    needs.auditRecordBytes = sizeof(audit::Record);
    needs.lockRecordBytes = sizeof(locks::Record);
    needs.seedTableBytes = latchkey_util::kSeedTableSize;
    needs.spareEntries = kSpareEntries + locks::kMaxLocks * latchkey_util::nvsBlobEntries(latchkey_util::kRetiredLabelsBytes);
    needs.watchStateBytes = latchkey_util::kWatchStateSize;
    needs.watchStates = locks::kMaxLocks;
    needs.alertTableBytes = latchkey_util::kLockAlertsBytes;
    needs.alertTables = locks::kMaxLocks;
    return latchkey_util::reservedEntries(needs);
}

namespace cfg {

bool loadWifi(Wifi& out) {
    Handle handle(kCfgNamespace, NVS_READONLY);
    if (!handle.ok()) {
        return false;
    }
    Wifi wifi;
    const nvs_handle_t h = handle.get();
    const bool complete =
        readString(h, "ssid", wifi.ssid) && readString(h, "wifi_pass", wifi.password) &&
        nvs_get_u32(h, "ip", &wifi.ip) == ESP_OK && nvs_get_u32(h, "gateway", &wifi.gateway) == ESP_OK &&
        nvs_get_u32(h, "netmask", &wifi.netmask) == ESP_OK && nvs_get_u32(h, "dns", &wifi.dns) == ESP_OK;
    if (complete) {
        mbedtls_platform_zeroize(out.password.data(), out.password.size());
        out = wifi;
    }
    mbedtls_platform_zeroize(wifi.password.data(), wifi.password.size());
    return complete;
}

esp_err_t saveWifi(const Wifi& wifi) {
    Handle handle(kCfgNamespace, NVS_READWRITE);
    if (!handle.ok()) {
        return handle.error();
    }
    const nvs_handle_t h = handle.get();
    esp_err_t error = nvs_set_str(h, "wifi_pass", wifi.password.c_str());
    if (error == ESP_OK) {
        error = nvs_set_u32(h, "ip", wifi.ip);
    }
    if (error == ESP_OK) {
        error = nvs_set_u32(h, "gateway", wifi.gateway);
    }
    if (error == ESP_OK) {
        error = nvs_set_u32(h, "netmask", wifi.netmask);
    }
    if (error == ESP_OK) {
        error = nvs_set_u32(h, "dns", wifi.dns);
    }
    if (error == ESP_OK) {
        error = nvs_set_str(h, "ssid", wifi.ssid.c_str());
    }
    return error == ESP_OK ? nvs_commit(h) : error;
}

bool loadTimezone(std::string& out) {
    Handle handle(kCfgNamespace, NVS_READONLY);
    return handle.ok() && readString(handle.get(), "tz", out);
}

esp_err_t saveTimezone(const std::string& timezone) {
    Handle handle(kCfgNamespace, NVS_READWRITE);
    if (!handle.ok()) {
        return handle.error();
    }
    const esp_err_t error = nvs_set_str(handle.get(), "tz", timezone.c_str());
    return error == ESP_OK ? nvs_commit(handle.get()) : error;
}

esp_err_t loadSyslog(Syslog& out) {
    Handle handle(kCfgNamespace, NVS_READONLY);
    SyslogRecord record{};
    size_t length = sizeof(record);
    esp_err_t error = handle.ok() ? nvs_get_blob(handle.get(), kSyslogKey, &record, &length) : handle.error();
    if (error == ESP_ERR_NVS_NOT_FOUND) {
        out = Syslog{};
        return ESP_OK;
    }
    const bool known = record.level >= static_cast<uint8_t>(latchkey_util::LogLevel::Error) &&
                       record.level <= static_cast<uint8_t>(latchkey_util::LogLevel::Verbose);
    if (error == ESP_OK && (length != sizeof(record) || record.version != kSyslogRecordVersion || !known)) {
        error = ESP_ERR_INVALID_VERSION;
    }
    if (error != ESP_OK) {
        return error;
    }
    Syslog syslog;
    syslog.enabled = record.enabled != 0;
    syslog.tcp = record.tcp != 0;
    syslog.level = static_cast<latchkey_util::LogLevel>(record.level);
    syslog.port = record.port;
    syslog.host.assign(record.host, strnlen(record.host, sizeof(record.host)));
    syslog.appName.assign(record.appName, strnlen(record.appName, sizeof(record.appName)));
    out = std::move(syslog);
    return ESP_OK;
}

esp_err_t saveSyslog(const Syslog& syslog) {
    SyslogRecord record{};
    record.version = kSyslogRecordVersion;
    record.enabled = syslog.enabled ? 1 : 0;
    record.tcp = syslog.tcp ? 1 : 0;
    record.level = static_cast<uint8_t>(syslog.level);
    record.port = syslog.port;
    if (!copyText(record.host, syslog.host) || !copyText(record.appName, syslog.appName)) {
        return ESP_ERR_INVALID_ARG;
    }
    if (!growthFits(kCfgNamespace, kSyslogKey, sizeof(record))) {
        return ESP_ERR_NVS_NOT_ENOUGH_SPACE;
    }
    Handle handle(kCfgNamespace, NVS_READWRITE);
    if (!handle.ok()) {
        return handle.error();
    }
    const esp_err_t error = nvs_set_blob(handle.get(), kSyslogKey, &record, sizeof(record));
    return error == ESP_OK ? nvs_commit(handle.get()) : error;
}

bool loadTlsIdentity(latchkey_util::TlsIdentity& out) {
    Handle handle(kCfgNamespace, NVS_READONLY);
    size_t length = 0;
    if (!handle.ok() || nvs_get_blob(handle.get(), kTlsKey, nullptr, &length) != ESP_OK || length == 0) {
        return false;
    }
    std::vector<uint8_t> bytes(length);
    const bool loaded = nvs_get_blob(handle.get(), kTlsKey, bytes.data(), &length) == ESP_OK &&
                        latchkey_util::decodeTlsIdentity(bytes.data(), length, out);
    mbedtls_platform_zeroize(bytes.data(), bytes.size());
    return loaded;
}

esp_err_t saveTlsIdentity(const latchkey_util::TlsIdentity& identity) {
    std::vector<uint8_t> bytes = latchkey_util::encodeTlsIdentity(identity);
    if (bytes.empty()) {
        return ESP_ERR_INVALID_ARG;
    }
    Handle handle(kCfgNamespace, NVS_READWRITE);
    esp_err_t error = handle.error();
    if (handle.ok()) {
        error = nvs_set_blob(handle.get(), kTlsKey, bytes.data(), bytes.size());
        if (error == ESP_OK) {
            error = nvs_commit(handle.get());
        }
    }
    mbedtls_platform_zeroize(bytes.data(), bytes.size());
    return error;
}

esp_err_t loadMqtt(Mqtt& out) {
    Handle handle(kCfgNamespace, NVS_READONLY);
    if (handle.error() == ESP_ERR_NVS_NOT_FOUND) {
        mbedtls_platform_zeroize(out.password.data(), out.password.size());
        out = Mqtt{};
        return ESP_OK;
    }
    if (!handle.ok()) {
        return handle.error();
    }
    MqttRecord record{};
    size_t length = sizeof(record);
    esp_err_t error = nvs_get_blob(handle.get(), kMqttKey, &record, &length);
    if (error == ESP_ERR_NVS_NOT_FOUND) {
        mbedtls_platform_zeroize(out.password.data(), out.password.size());
        out = Mqtt{};
        return ESP_OK;
    }
    if (error == ESP_OK && (length != sizeof(record) || record.version != kMqttRecordVersion)) {
        error = ESP_ERR_INVALID_VERSION;
    }
    if (error == ESP_OK) {
        mbedtls_platform_zeroize(out.password.data(), out.password.size());
        out.enabled = record.enabled != 0;
        out.port = record.port;
        out.host = takeText(record.host);
        out.username = takeText(record.username);
        out.password.assign(record.password, strnlen(record.password, sizeof(record.password)));
        out.prefix = takeText(record.prefix);
    }
    mbedtls_platform_zeroize(&record, sizeof(record));
    return error;
}

esp_err_t saveMqtt(const Mqtt& mqtt) {
    MqttRecord record{};
    record.version = kMqttRecordVersion;
    record.enabled = mqtt.enabled ? 1 : 0;
    record.port = mqtt.port;
    esp_err_t error = putText(record.host, mqtt.host) && putText(record.username, mqtt.username) &&
                              putText(record.password, mqtt.password) && putText(record.prefix, mqtt.prefix)
                          ? ESP_OK
                          : ESP_ERR_INVALID_ARG;
    if (error == ESP_OK) {
        Handle handle(kCfgNamespace, NVS_READWRITE);
        error = handle.error();
        if (handle.ok()) {
            error = nvs_set_blob(handle.get(), kMqttKey, &record, sizeof(record));
            if (error == ESP_OK) {
                error = nvs_commit(handle.get());
            }
        }
    }
    mbedtls_platform_zeroize(&record, sizeof(record));
    return error;
}

esp_err_t erase() { return eraseNamespace(kCfgNamespace); }

}

namespace auth {

bool claimed() {
    Handle handle(kAuthNamespace, NVS_READONLY);
    if (!handle.ok()) {
        return false;
    }
    size_t length = 0;
    return nvs_get_blob(handle.get(), kPasswordKey, nullptr, &length) == ESP_OK &&
           length == latchkey_util::kPasswordRecordSize;
}

bool loadOwner(Owner& out) {
    Handle handle(kAuthNamespace, NVS_READONLY);
    if (!handle.ok()) {
        return false;
    }
    Owner owner;
    latchkey_util::PasswordRecordBytes bytes{};
    size_t length = bytes.size();
    const bool complete = nvs_get_blob(handle.get(), kPasswordKey, bytes.data(), &length) == ESP_OK &&
                          latchkey_util::decodePasswordRecord(bytes.data(), length, owner.password) &&
                          readBlob(handle.get(), kTotpKey, owner.totpSecret);
    mbedtls_platform_zeroize(bytes.data(), bytes.size());
    if (complete) {
        out = owner;
    }
    mbedtls_platform_zeroize(&owner, sizeof(owner));
    return complete;
}

esp_err_t saveOwner(const Owner& owner) {
    const esp_err_t error = saveTotpSecret(owner.totpSecret);
    return error == ESP_OK ? savePassword(owner.password) : error;
}

esp_err_t savePassword(const latchkey_util::PasswordRecord& password) {
    Handle handle(kAuthNamespace, NVS_READWRITE);
    if (!handle.ok()) {
        return handle.error();
    }
    latchkey_util::PasswordRecordBytes bytes = latchkey_util::encodePasswordRecord(password);
    const esp_err_t error = nvs_set_blob(handle.get(), kPasswordKey, bytes.data(), bytes.size());
    mbedtls_platform_zeroize(bytes.data(), bytes.size());
    return error == ESP_OK ? nvs_commit(handle.get()) : error;
}

esp_err_t saveTotpSecret(const TotpSecret& secret) {
    Handle handle(kAuthNamespace, NVS_READWRITE);
    if (!handle.ok()) {
        return handle.error();
    }
    const esp_err_t error = nvs_set_blob(handle.get(), kTotpKey, secret.data(), secret.size());
    return error == ESP_OK ? nvs_commit(handle.get()) : error;
}

esp_err_t loadLoginState(LoginState& out) {
    Handle handle(kAuthNamespace, NVS_READONLY);
    if (handle.error() == ESP_ERR_NVS_NOT_FOUND) {
        out = LoginState{};
        return ESP_OK;
    }
    if (!handle.ok()) {
        return handle.error();
    }
    LoginState state;
    esp_err_t error = nvs_get_u32(handle.get(), "fails", &state.failures);
    if (error == ESP_ERR_NVS_NOT_FOUND) {
        state.failures = 0;
        error = ESP_OK;
    }
    if (error != ESP_OK) {
        return error;
    }
    error = nvs_get_u64(handle.get(), "totp_step", &state.lastStep);
    if (error == ESP_ERR_NVS_NOT_FOUND) {
        state.lastStep = 0;
        error = ESP_OK;
    }
    if (error != ESP_OK) {
        return error;
    }
    out = state;
    return ESP_OK;
}

esp_err_t saveFailures(uint32_t failures) {
    Handle handle(kAuthNamespace, NVS_READWRITE);
    if (!handle.ok()) {
        return handle.error();
    }
    const esp_err_t error = nvs_set_u32(handle.get(), "fails", failures);
    return error == ESP_OK ? nvs_commit(handle.get()) : error;
}

esp_err_t saveLastStep(uint64_t step) {
    Handle handle(kAuthNamespace, NVS_READWRITE);
    if (!handle.ok()) {
        return handle.error();
    }
    const esp_err_t error = nvs_set_u64(handle.get(), "totp_step", step);
    return error == ESP_OK ? nvs_commit(handle.get()) : error;
}

esp_err_t erase() { return eraseNamespace(kAuthNamespace); }

}

namespace locks {

namespace {

template <size_t N>
void terminate(char (&field)[N]) {
    field[N - 1] = '\0';
}

void terminateStrings(Record& record) {
    terminate(record.mac);
    terminate(record.name);
    terminate(record.adminPasscode);
    terminate(record.model);
    terminate(record.hardware);
    terminate(record.firmware);
    terminate(record.manufactureDate);
}

}

esp_err_t list(std::vector<Record>& out) {
    Handle handle(kLocksNamespace, NVS_READONLY);
    if (handle.error() == ESP_ERR_NVS_NOT_FOUND) {
        for (Record& record : out) mbedtls_platform_zeroize(&record, sizeof(record));
        out.clear();
        return ESP_OK;
    }
    if (!handle.ok()) {
        return handle.error();
    }
    std::vector<Record> records;
    records.reserve(kMaxLocks);
    nvs_iterator_t entry = nullptr;
    esp_err_t error = nvs_entry_find_in_handle(handle.get(), NVS_TYPE_BLOB, &entry);
    while (error == ESP_OK) {
        nvs_entry_info_t info{};
        nvs_entry_info(entry, &info);
        Record record;
        size_t length = sizeof(record);
        if (nvs_get_blob(handle.get(), info.key, &record, &length) == ESP_OK && length == sizeof(record) &&
            record.version == kRecordVersion) {
            terminateStrings(record);
            if (records.size() == kMaxLocks) {
                mbedtls_platform_zeroize(&record, sizeof(record));
                error = ESP_ERR_INVALID_SIZE;
                break;
            }
            records.push_back(record);
        }
        mbedtls_platform_zeroize(&record, sizeof(record));
        error = nvs_entry_next(&entry);
    }
    nvs_release_iterator(entry);
    if (error != ESP_ERR_NVS_NOT_FOUND) {
        for (Record& record : records) mbedtls_platform_zeroize(&record, sizeof(record));
        return error;
    }
    for (Record& record : out) mbedtls_platform_zeroize(&record, sizeof(record));
    out = std::move(records);
    return ESP_OK;
}

esp_err_t count(size_t& out) {
    size_t entries = 0;
    nvs_iterator_t entry = nullptr;
    esp_err_t error = nvs_entry_find(NVS_DEFAULT_PART_NAME, kLocksNamespace, NVS_TYPE_ANY, &entry);
    while (error == ESP_OK) {
        ++entries;
        error = nvs_entry_next(&entry);
    }
    nvs_release_iterator(entry);
    if (error != ESP_ERR_NVS_NOT_FOUND) {
        return error;
    }
    out = entries;
    return ESP_OK;
}

esp_err_t save(const Record& record) {
    char key[kLockKeySize];
    if (!lockKey(record.mac, key)) {
        return ESP_ERR_INVALID_ARG;
    }
    Handle handle(kLocksNamespace, NVS_READWRITE);
    if (!handle.ok()) {
        return handle.error();
    }
    const esp_err_t error = nvs_set_blob(handle.get(), key, &record, sizeof(record));
    return error == ESP_OK ? nvs_commit(handle.get()) : error;
}

esp_err_t erase(const char* mac) {
    char key[kLockKeySize];
    if (!lockKey(mac, key)) {
        return ESP_ERR_INVALID_ARG;
    }
    Handle handle(kLocksNamespace, NVS_READWRITE);
    if (!handle.ok()) {
        return handle.error();
    }
    const esp_err_t error = nvs_erase_key(handle.get(), key);
    if (error != ESP_OK && error != ESP_ERR_NVS_NOT_FOUND) {
        return error;
    }
    return nvs_commit(handle.get());
}

esp_err_t eraseAll() { return eraseNamespace(kLocksNamespace); }

}

namespace labels {

esp_err_t loadRetired(const char* mac, latchkey_util::RetiredLabels& out) {
    char key[kLockKeySize];
    if (!lockKey(mac, key)) return ESP_ERR_INVALID_ARG;
    Handle handle(kLabelsNamespace, NVS_READONLY);
    if (handle.error() == ESP_ERR_NVS_NOT_FOUND) {
        out = {};
        return ESP_OK;
    }
    if (!handle.ok()) return handle.error();
    size_t length = 0;
    esp_err_t error = nvs_get_blob(handle.get(), key, nullptr, &length);
    if (error == ESP_ERR_NVS_NOT_FOUND) {
        out = {};
        return ESP_OK;
    }
    if (error != ESP_OK) return error;
    if (length > latchkey_util::kRetiredLabelsBytes) return ESP_ERR_INVALID_SIZE;
    std::vector<uint8_t> bytes(length);
    error = nvs_get_blob(handle.get(), key, bytes.data(), &length);
    if (error != ESP_OK) return error;
    return latchkey_util::RetiredLabels::decode(bytes.data(), length, out) ? ESP_OK : ESP_ERR_INVALID_CRC;
}

esp_err_t saveRetired(const char* mac, const latchkey_util::RetiredLabels& table) {
    char key[kLockKeySize];
    if (!lockKey(mac, key)) return ESP_ERR_INVALID_ARG;
    const auto bytes = table.encode();
    Handle handle(kLabelsNamespace, NVS_READWRITE);
    if (!handle.ok()) return handle.error();
    const esp_err_t error = nvs_set_blob(handle.get(), key, bytes.data(), bytes.size());
    return error == ESP_OK ? nvs_commit(handle.get()) : error;
}

esp_err_t load(const char* mac, Kind kind, latchkey_util::LabelTable& out) {
    char key[kLabelKeySize];
    if (!labelKey(mac, kind, key)) {
        return ESP_ERR_INVALID_ARG;
    }
    Handle handle(kLabelsNamespace, NVS_READONLY);
    if (handle.error() == ESP_ERR_NVS_NOT_FOUND) {
        out = latchkey_util::LabelTable{};
        return ESP_OK;
    }
    if (!handle.ok()) {
        return handle.error();
    }
    size_t length = 0;
    esp_err_t error = nvs_get_blob(handle.get(), key, nullptr, &length);
    if (error == ESP_ERR_NVS_NOT_FOUND) {
        out = latchkey_util::LabelTable{};
        return ESP_OK;
    }
    if (error != ESP_OK) {
        return error;
    }
    std::vector<uint8_t> bytes(length);
    error = nvs_get_blob(handle.get(), key, bytes.data(), &length);
    if (error != ESP_OK) {
        return error;
    }
    return latchkey_util::LabelTable::decode(bytes.data(), length, out) ? ESP_OK : ESP_ERR_INVALID_CRC;
}

esp_err_t save(const char* mac, Kind kind, const latchkey_util::LabelTable& table) {
    char key[kLabelKeySize];
    if (!labelKey(mac, kind, key)) {
        return ESP_ERR_INVALID_ARG;
    }
    if (table.size() == 0) {
        return eraseKey(kLabelsNamespace, key);
    }
    const std::vector<uint8_t> bytes = table.encode();
    if (!growthFits(kLabelsNamespace, key, bytes.size())) {
        return ESP_ERR_NVS_NOT_ENOUGH_SPACE;
    }
    Handle handle(kLabelsNamespace, NVS_READWRITE);
    if (!handle.ok()) {
        return handle.error();
    }
    const esp_err_t error = nvs_set_blob(handle.get(), key, bytes.data(), bytes.size());
    return error == ESP_OK ? nvs_commit(handle.get()) : error;
}

bool fits(const char* mac, Kind kind, const latchkey_util::LabelTable& table) {
    char key[kLabelKeySize];
    return labelKey(mac, kind, key) && growthFits(kLabelsNamespace, key, table.encode().size());
}

esp_err_t erase(const char* mac) {
    for (const Kind kind : kLabelKinds) {
        char key[kLabelKeySize];
        if (!labelKey(mac, kind, key)) {
            return ESP_ERR_INVALID_ARG;
        }
        const esp_err_t error = eraseKey(kLabelsNamespace, key);
        if (error != ESP_OK) {
            return error;
        }
    }
    char key[kLockKeySize];
    if (!lockKey(mac, key)) return ESP_ERR_INVALID_ARG;
    return eraseKey(kLabelsNamespace, key);
}

esp_err_t eraseAll() { return eraseNamespace(kLabelsNamespace); }

}

namespace seeds {

esp_err_t save(const char* mac, const latchkey_util::SeedTable& table) {
    char key[kLockKeySize];
    if (!lockKey(mac, key)) {
        return ESP_ERR_INVALID_ARG;
    }
    Handle handle(kSeedsNamespace, NVS_READWRITE);
    if (!handle.ok()) {
        return handle.error();
    }
    std::array<uint8_t, latchkey_util::kSeedTableSize> bytes = latchkey_util::encodeSeedTable(table);
    const esp_err_t error = nvs_set_blob(handle.get(), key, bytes.data(), bytes.size());
    mbedtls_platform_zeroize(bytes.data(), bytes.size());
    return error == ESP_OK ? nvs_commit(handle.get()) : error;
}

esp_err_t erase(const char* mac) {
    char key[kLockKeySize];
    if (!lockKey(mac, key)) {
        return ESP_ERR_INVALID_ARG;
    }
    return eraseKey(kSeedsNamespace, key);
}

esp_err_t eraseAll() { return eraseNamespace(kSeedsNamespace); }

}

namespace watch {

esp_err_t load(const char* mac, latchkey_util::WatchState& out) {
    char key[kLockKeySize];
    if (!lockKey(mac, key)) {
        return ESP_ERR_INVALID_ARG;
    }
    Handle handle(kWatchNamespace, NVS_READONLY);
    if (handle.error() == ESP_ERR_NVS_NOT_FOUND) {
        out = latchkey_util::WatchState{};
        return ESP_OK;
    }
    if (!handle.ok()) {
        return handle.error();
    }
    std::array<uint8_t, latchkey_util::kWatchStateSize> bytes{};
    size_t length = bytes.size();
    const esp_err_t error = nvs_get_blob(handle.get(), key, bytes.data(), &length);
    if (error == ESP_ERR_NVS_NOT_FOUND) {
        out = latchkey_util::WatchState{};
        return ESP_OK;
    }
    if (error != ESP_OK) {
        return error;
    }
    return latchkey_util::decodeWatchState(bytes.data(), length, out) ? ESP_OK : ESP_ERR_INVALID_CRC;
}

esp_err_t save(const char* mac, const latchkey_util::WatchState& state) {
    char key[kLockKeySize];
    if (!lockKey(mac, key)) {
        return ESP_ERR_INVALID_ARG;
    }
    Handle handle(kWatchNamespace, NVS_READWRITE);
    if (!handle.ok()) {
        return handle.error();
    }
    const std::array<uint8_t, latchkey_util::kWatchStateSize> bytes = latchkey_util::encodeWatchState(state);
    const esp_err_t error = nvs_set_blob(handle.get(), key, bytes.data(), bytes.size());
    return error == ESP_OK ? nvs_commit(handle.get()) : error;
}

esp_err_t erase(const char* mac) {
    char key[kLockKeySize];
    if (!lockKey(mac, key)) {
        return ESP_ERR_INVALID_ARG;
    }
    return eraseKey(kWatchNamespace, key);
}

esp_err_t eraseAll() { return eraseNamespace(kWatchNamespace); }

}

namespace alerts {

esp_err_t load(const char* mac, latchkey_util::LockAlerts& out) {
    char key[kLockKeySize];
    if (!lockKey(mac, key)) {
        return ESP_ERR_INVALID_ARG;
    }
    Handle handle(kAlertsNamespace, NVS_READONLY);
    if (handle.error() == ESP_ERR_NVS_NOT_FOUND) {
        out = latchkey_util::LockAlerts{};
        return ESP_OK;
    }
    if (!handle.ok()) {
        return handle.error();
    }
    std::array<uint8_t, latchkey_util::kLockAlertsBytes> bytes{};
    size_t length = bytes.size();
    const esp_err_t error = nvs_get_blob(handle.get(), key, bytes.data(), &length);
    if (error == ESP_ERR_NVS_NOT_FOUND) {
        out = latchkey_util::LockAlerts{};
        return ESP_OK;
    }
    if (error != ESP_OK) {
        return error;
    }
    return latchkey_util::LockAlerts::decode(bytes.data(), length, out) ? ESP_OK : ESP_ERR_INVALID_CRC;
}

esp_err_t save(const char* mac, const latchkey_util::LockAlerts& alerts) {
    char key[kLockKeySize];
    if (!lockKey(mac, key)) {
        return ESP_ERR_INVALID_ARG;
    }
    Handle handle(kAlertsNamespace, NVS_READWRITE);
    if (!handle.ok()) {
        return handle.error();
    }
    const auto bytes = alerts.encode();
    const esp_err_t error = nvs_set_blob(handle.get(), key, bytes.data(), bytes.size());
    return error == ESP_OK ? nvs_commit(handle.get()) : error;
}

esp_err_t erase(const char* mac) {
    char key[kLockKeySize];
    if (!lockKey(mac, key)) {
        return ESP_ERR_INVALID_ARG;
    }
    return eraseKey(kAlertsNamespace, key);
}

esp_err_t eraseAll() { return eraseNamespace(kAlertsNamespace); }

}

namespace audit {

uint32_t loadNextSeq() {
    Handle handle(kAuditNamespace, NVS_READONLY);
    uint32_t next = 1;
    if (handle.ok() && nvs_get_u32(handle.get(), "next", &next) != ESP_OK) {
        next = 1;
    }
    return next;
}

esp_err_t saveRecord(const Record& record) {
    Handle handle(kAuditNamespace, NVS_READWRITE);
    if (!handle.ok()) {
        return handle.error();
    }
    char key[8];
    slotKey(record.seq, key);
    esp_err_t error = nvs_set_blob(handle.get(), key, &record, sizeof(record));
    if (error == ESP_OK) {
        error = nvs_set_u32(handle.get(), "next", record.seq + 1);
    }
    return error == ESP_OK ? nvs_commit(handle.get()) : error;
}

bool loadRecord(uint32_t seq, Record& out) {
    Handle handle(kAuditNamespace, NVS_READONLY);
    if (!handle.ok()) {
        return false;
    }
    char key[8];
    slotKey(seq, key);
    Record record{};
    size_t length = sizeof(record);
    if (nvs_get_blob(handle.get(), key, &record, &length) != ESP_OK || length != sizeof(record) || record.seq != seq) {
        return false;
    }
    out = record;
    return true;
}

esp_err_t erase() { return eraseNamespace(kAuditNamespace); }

}

}
