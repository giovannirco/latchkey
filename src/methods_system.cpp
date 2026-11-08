// SPDX-License-Identifier: GPL-3.0-or-later
#include <cmath>
#include <cstdint>
#include <cstring>
#include <mutex>
#include <string>
#include <utility>

#include "esp_app_desc.h"
#include "esp_idf_version.h"
#include "esp_log.h"
#include "esp_random.h"
#include "esp_system.h"
#include "esp_timer.h"
#include "lwip/inet.h"
#include "mbedtls/platform_util.h"
#include "psa/crypto.h"
#include "sdkconfig.h"

#include "audit.h"
#include "board.h"
#include "clock.h"
#include "console.h"
#include "latchkey_util/ipv4.h"
#include "latchkey_util/otpauth.h"
#include "methods.h"
#include "rpc.h"
#include "store.h"
#include "wifi.h"

namespace methods {

namespace {

constexpr const char* TAG = "system";
constexpr uint32_t kPasswordIterations = 4400;
constexpr size_t kMinPassword = 12;
constexpr size_t kMaxPassword = 128;
constexpr size_t kMaxSsid = 32;
constexpr size_t kMinWifiPassword = 8;
constexpr size_t kMaxWifiPassword = 63;
constexpr size_t kDefaultAuditPage = 20;
constexpr uint64_t kRestartDelayUs = 500 * 1000;
constexpr const char* kWifiParamsMessage = "wifi needs ssid, password, ip, gateway, netmask and dns";

std::mutex s_claimMutex;

const cJSON* member(const cJSON* object, const char* key) { return cJSON_GetObjectItemCaseSensitive(object, key); }

bool readString(const cJSON* object, const char* key, size_t minLength, size_t maxLength, std::string& out) {
    const cJSON* item = member(object, key);
    if (!cJSON_IsString(item) || item->valuestring == nullptr) {
        return false;
    }
    const size_t length = std::strlen(item->valuestring);
    if (length < minLength || length > maxLength) {
        return false;
    }
    out.assign(item->valuestring, length);
    return true;
}

bool readWhole(const cJSON* item, double minValue, double maxValue, double& out) {
    if (!cJSON_IsNumber(item) || std::floor(item->valuedouble) != item->valuedouble || item->valuedouble < minValue ||
        item->valuedouble > maxValue) {
        return false;
    }
    out = item->valuedouble;
    return true;
}

bool readIpv4(const cJSON* object, const char* key, uint32_t& out) {
    const cJSON* item = member(object, key);
    return cJSON_IsString(item) && item->valuestring != nullptr && latchkey_util::parseIpv4(item->valuestring, out);
}

bool isWifiPassword(const std::string& password) {
    return password.empty() || (password.size() >= kMinWifiPassword && password.size() <= kMaxWifiPassword);
}

bool readWifi(const cJSON* object, store::cfg::Wifi& out) {
    if (!cJSON_IsObject(object)) {
        return false;
    }
    store::cfg::Wifi wifi;
    const bool valid = readString(object, "ssid", 1, kMaxSsid, wifi.ssid) &&
                       readString(object, "password", 0, kMaxWifiPassword, wifi.password) &&
                       isWifiPassword(wifi.password) && readIpv4(object, "ip", wifi.ip) &&
                       readIpv4(object, "gateway", wifi.gateway) && readIpv4(object, "netmask", wifi.netmask) &&
                       readIpv4(object, "dns", wifi.dns) && wifi.dns != 0 &&
                       latchkey_util::isStaticIpv4(wifi.ip, wifi.gateway, wifi.netmask);
    if (!valid) {
        return false;
    }
    out = std::move(wifi);
    return true;
}

bool hashPassword(const std::string& password, store::auth::Owner& owner) {
    psa_key_derivation_operation_t operation = PSA_KEY_DERIVATION_OPERATION_INIT;
    const bool derived =
        psa_key_derivation_setup(&operation, PSA_ALG_PBKDF2_HMAC(PSA_ALG_SHA_256)) == PSA_SUCCESS &&
        psa_key_derivation_input_integer(&operation, PSA_KEY_DERIVATION_INPUT_COST, owner.iterations) == PSA_SUCCESS &&
        psa_key_derivation_input_bytes(&operation, PSA_KEY_DERIVATION_INPUT_SALT, owner.salt.data(),
                                       owner.salt.size()) == PSA_SUCCESS &&
        psa_key_derivation_input_bytes(&operation, PSA_KEY_DERIVATION_INPUT_PASSWORD,
                                       reinterpret_cast<const uint8_t*>(password.data()),
                                       password.size()) == PSA_SUCCESS &&
        psa_key_derivation_output_bytes(&operation, owner.hash.data(), owner.hash.size()) == PSA_SUCCESS;
    psa_key_derivation_abort(&operation);
    return derived;
}

void restartLater() {
    static esp_timer_handle_t timer = nullptr;
    if (timer == nullptr) {
        const esp_timer_create_args_t args = {
            .callback =
                [](void*) {
                    console::flush();
                    esp_restart();
                },
            .arg = nullptr,
            .dispatch_method = ESP_TIMER_TASK,
            .name = "restart",
            .skip_unhandled_events = true,
        };
        ESP_ERROR_CHECK(esp_timer_create(&args, &timer));
    }
    esp_timer_stop(timer);
    ESP_ERROR_CHECK(esp_timer_start_once(timer, kRestartDelayUs));
}

void addIpv4(cJSON* object, const char* key, uint32_t address) {
    char text[16];
    const in_addr value = {htonl(address)};
    cJSON_AddStringToObject(object, key, inet_ntoa_r(value, text, sizeof(text)));
}

cJSON* wifiJson() {
    const wifi::Status status = wifi::status();
    cJSON* json = cJSON_CreateObject();
    cJSON_AddBoolToObject(json, "configured", status.configured);
    cJSON_AddBoolToObject(json, "connected", status.connected);
    if (status.configured) {
        cJSON_AddStringToObject(json, "ssid", status.ssid.c_str());
    } else {
        cJSON_AddNullToObject(json, "ssid");
    }
    if (status.connected) {
        addIpv4(json, "ip", status.ip);
        cJSON_AddNumberToObject(json, "rssi", status.rssi);
    } else {
        cJSON_AddNullToObject(json, "ip");
        cJSON_AddNullToObject(json, "rssi");
    }
    return json;
}

rpc::Reply info(const cJSON*, const rpc::Context&) {
    cJSON* result = cJSON_CreateObject();
    cJSON_AddStringToObject(result, "firmware", esp_app_get_description()->version);
    cJSON_AddStringToObject(result, "board", board::name());
    cJSON_AddStringToObject(result, "chip", CONFIG_IDF_TARGET);
    cJSON_AddStringToObject(result, "idf", esp_get_idf_version());
    cJSON_AddNumberToObject(result, "uptime_ms", static_cast<double>(esp_timer_get_time() / 1000));
    cJSON* heap = cJSON_AddObjectToObject(result, "heap");
    cJSON_AddNumberToObject(heap, "free", esp_get_free_heap_size());
    cJSON_AddNumberToObject(heap, "min_free", esp_get_minimum_free_heap_size());
    const store::Usage usage = store::usage();
    cJSON* nvs = cJSON_AddObjectToObject(result, "nvs");
    cJSON_AddNumberToObject(nvs, "used_entries", usage.usedEntries);
    cJSON_AddNumberToObject(nvs, "available_entries", usage.availableEntries);
    cJSON_AddNumberToObject(nvs, "total_entries", usage.totalEntries);
    cJSON_AddBoolToObject(result, "claimed", store::auth::claimed());
    cJSON_AddItemToObject(result, "wifi", wifiJson());
    const bool synced = wallclock::synced();
    cJSON_AddBoolToObject(result, "time_synced", synced);
    if (synced) {
        cJSON_AddNumberToObject(result, "utc", static_cast<double>(wallclock::utcSeconds()));
    } else {
        cJSON_AddNullToObject(result, "utc");
    }
    cJSON* button = cJSON_AddObjectToObject(result, "button");
    cJSON_AddNumberToObject(button, "gpio", board::buttonGpio());
    cJSON_AddBoolToObject(button, "pressed", board::buttonPressed());
    cJSON_AddNumberToObject(button, "presses", board::buttonPresses());
    return rpc::ok(result);
}

rpc::Reply setup(const cJSON* params, const rpc::Context&) {
    std::lock_guard<std::mutex> lock(s_claimMutex);
    if (store::auth::claimed()) {
        return rpc::fail("already_claimed", "the board already has an owner");
    }
    store::cfg::Wifi wifi;
    if (!readWifi(member(params, "wifi"), wifi)) {
        return rpc::fail("invalid_params", kWifiParamsMessage);
    }
    std::string password;
    if (!readString(params, "password", kMinPassword, kMaxPassword, password)) {
        return rpc::fail("invalid_params", "password must be 12 to 128 bytes");
    }
    store::auth::Owner owner;
    owner.iterations = kPasswordIterations;
    esp_fill_random(owner.salt.data(), owner.salt.size());
    esp_fill_random(owner.totpSecret.data(), owner.totpSecret.size());
    const int64_t started = esp_timer_get_time();
    const bool hashed = hashPassword(password, owner);
    mbedtls_platform_zeroize(password.data(), password.size());
    if (!hashed) {
        return rpc::fail("internal", "password hashing failed");
    }
    ESP_LOGI(TAG, "owner password hashed with %u iterations in %lld ms", static_cast<unsigned>(owner.iterations),
             static_cast<long long>((esp_timer_get_time() - started) / 1000));
    const bool stored = store::cfg::saveWifi(wifi) == ESP_OK && store::auth::saveOwner(owner) == ESP_OK;
    const std::string uri =
        latchkey_util::otpauthUri(board::name(), owner.totpSecret.data(), owner.totpSecret.size());
    mbedtls_platform_zeroize(&owner, sizeof(owner));
    if (!stored) {
        return rpc::fail("internal", "cannot store the owner");
    }
    wifi::apply(wifi);
    cJSON* result = cJSON_CreateObject();
    cJSON_AddStringToObject(result, "otpauth", uri.c_str());
    return rpc::ok(result);
}

rpc::Reply wifiSet(const cJSON* params, const rpc::Context&) {
    store::cfg::Wifi wifi;
    if (!readWifi(params, wifi)) {
        return rpc::fail("invalid_params", kWifiParamsMessage);
    }
    if (store::cfg::saveWifi(wifi) != ESP_OK) {
        return rpc::fail("internal", "cannot store the Wi-Fi configuration");
    }
    wifi::apply(wifi);
    return rpc::ok();
}

rpc::Reply reboot(const cJSON*, const rpc::Context&) {
    restartLater();
    return rpc::ok();
}

rpc::Reply factoryReset(const cJSON*, const rpc::Context&) {
    std::lock_guard<std::mutex> lock(s_claimMutex);
    const bool erased =
        store::auth::erase() == ESP_OK && store::cfg::erase() == ESP_OK && audit::clear() == ESP_OK;
    if (!erased) {
        return rpc::fail("internal", "erase failed");
    }
    ESP_LOGW(TAG, "factory reset: owner, Wi-Fi and audit erased");
    restartLater();
    return rpc::ok();
}

rpc::Reply timeSet(const cJSON* params, const rpc::Context&) {
    double utc = 0;
    if (!readWhole(member(params, "utc"), wallclock::kMinUtc, wallclock::kMaxUtc, utc)) {
        return rpc::fail("invalid_params", "utc must be whole seconds from 2024 to 2100");
    }
    if (!wallclock::set(static_cast<int64_t>(utc))) {
        return rpc::fail("internal", "cannot set the clock");
    }
    return rpc::ok();
}

rpc::Reply auditList(const cJSON* params, const rpc::Context&) {
    double before = UINT32_MAX;
    const cJSON* beforeItem = member(params, "before");
    if (beforeItem != nullptr && !cJSON_IsNull(beforeItem) && !readWhole(beforeItem, 1, UINT32_MAX, before)) {
        return rpc::fail("invalid_params", "before must be a sequence number");
    }
    double limit = kDefaultAuditPage;
    const cJSON* limitItem = member(params, "limit");
    if (limitItem != nullptr && !readWhole(limitItem, 1, audit::kMaxPage, limit)) {
        return rpc::fail("invalid_params", "limit must be 1 to 50");
    }
    const audit::Page page = audit::list(static_cast<uint32_t>(before), static_cast<size_t>(limit));
    cJSON* result = cJSON_CreateObject();
    cJSON* entries = cJSON_AddArrayToObject(result, "entries");
    for (const audit::StoredEntry& stored : page.entries) {
        cJSON_AddItemToArray(entries, audit::toJson(stored));
    }
    if (page.more) {
        cJSON_AddNumberToObject(result, "next", page.entries.back().seq);
    } else {
        cJSON_AddNullToObject(result, "next");
    }
    return rpc::ok(result);
}

}

void registerSystem() {
    rpc::registerMethod("system.info", {.audited = false}, info);
    rpc::registerMethod("system.setup", {.needsSession = false, .serialOnly = true}, setup);
    rpc::registerMethod("system.wifi.set", {}, wifiSet);
    rpc::registerMethod("system.reboot", {}, reboot);
    rpc::registerMethod("system.factoryReset", {.needsButton = true}, factoryReset);
    rpc::registerMethod("system.time.set", {.serialOnly = true}, timeSet);
    rpc::registerMethod("audit.list", {.audited = false}, auditList);
}

}
