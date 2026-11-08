// SPDX-License-Identifier: GPL-3.0-or-later
#include "store.h"

#include <cstdio>
#include <utility>

#include "nvs.h"
#include "nvs_flash.h"

namespace store {

namespace {

constexpr const char* kCfgNamespace = "cfg";
constexpr const char* kAuthNamespace = "auth";
constexpr const char* kAuditNamespace = "audit";

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
        return false;
    }
    value.resize(length - 1);
    out = std::move(value);
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
    if (!complete) {
        return false;
    }
    out = std::move(wifi);
    return true;
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

esp_err_t erase() { return eraseNamespace(kCfgNamespace); }

}

namespace auth {

bool claimed() {
    Handle handle(kAuthNamespace, NVS_READONLY);
    if (!handle.ok()) {
        return false;
    }
    size_t length = 0;
    return nvs_get_blob(handle.get(), "hash", nullptr, &length) == ESP_OK && length == Owner{}.hash.size();
}

bool loadOwner(Owner& out) {
    Handle handle(kAuthNamespace, NVS_READONLY);
    if (!handle.ok()) {
        return false;
    }
    Owner owner;
    const nvs_handle_t h = handle.get();
    const bool complete = readBlob(h, "salt", owner.salt) &&
                          nvs_get_u32(h, "iterations", &owner.iterations) == ESP_OK &&
                          readBlob(h, "totp", owner.totpSecret) && readBlob(h, "hash", owner.hash);
    if (!complete) {
        return false;
    }
    out = owner;
    return true;
}

esp_err_t saveOwner(const Owner& owner) {
    Handle handle(kAuthNamespace, NVS_READWRITE);
    if (!handle.ok()) {
        return handle.error();
    }
    const nvs_handle_t h = handle.get();
    esp_err_t error = nvs_set_blob(h, "salt", owner.salt.data(), owner.salt.size());
    if (error == ESP_OK) {
        error = nvs_set_u32(h, "iterations", owner.iterations);
    }
    if (error == ESP_OK) {
        error = nvs_set_blob(h, "totp", owner.totpSecret.data(), owner.totpSecret.size());
    }
    if (error == ESP_OK) {
        error = nvs_set_blob(h, "hash", owner.hash.data(), owner.hash.size());
    }
    return error == ESP_OK ? nvs_commit(h) : error;
}

esp_err_t erase() { return eraseNamespace(kAuthNamespace); }

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
