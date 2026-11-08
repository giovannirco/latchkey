// SPDX-License-Identifier: GPL-3.0-or-later
#include <cmath>
#include <cstdint>
#include <cstring>
#include <mutex>
#include <string>
#include <utility>

#include "esp_app_desc.h"
#include "esp_heap_caps.h"
#include "esp_idf_version.h"
#include "esp_log.h"
#include "esp_random.h"
#include "esp_system.h"
#include "esp_timer.h"
#include "freertos/FreeRTOS.h"
#include "freertos/task.h"
#include "lwip/inet.h"
#include "mbedtls/platform_util.h"
#include "psa/crypto.h"
#include "sdkconfig.h"

#include "audit.h"
#include "ble_central.h"
#include "board.h"
#include "clock.h"
#include "console.h"
#include "latchkey_util/ipv4.h"
#include "latchkey_util/otpauth.h"
#include "lock_manager.h"
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
constexpr size_t kMaxLogTag = 15;

struct LogLevelName {
    const char* name;
    esp_log_level_t level;
};

constexpr LogLevelName kLogLevels[] = {
    {"none", ESP_LOG_NONE}, {"error", ESP_LOG_ERROR}, {"warn", ESP_LOG_WARN},
    {"info", ESP_LOG_INFO}, {"debug", ESP_LOG_DEBUG}, {"verbose", ESP_LOG_VERBOSE},
};

std::mutex s_claimMutex;
esp_timer_handle_t s_restartTimer = nullptr;

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

void restartNow(void*) {
    console::flush();
    esp_restart();
}

esp_err_t restartLater() {
    esp_timer_stop(s_restartTimer);
    const esp_err_t error = esp_timer_start_once(s_restartTimer, kRestartDelayUs);
    if (error != ESP_OK) {
        ESP_LOGE(TAG, "restart timer: %s", esp_err_to_name(error));
    }
    return error;
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

uint32_t stackFree(const char* task) {
    TaskHandle_t handle = xTaskGetHandle(task);
    return handle != nullptr ? uxTaskGetStackHighWaterMark(handle) : 0;
}

cJSON* bleJson() {
    const ble::Stats stats = ble::stats();
    cJSON* json = cJSON_CreateObject();
    cJSON_AddBoolToObject(json, "ready", stats.ready);
    cJSON_AddBoolToObject(json, "scanning", stats.scan != ble::ScanMode::Off);
    cJSON_AddBoolToObject(json, "connected", stats.connected);
    cJSON_AddNumberToObject(json, "reports", stats.reports);
    cJSON_AddNumberToObject(json, "lock_reports", stats.lockReports);
    cJSON_AddNumberToObject(json, "frames", stats.frames);
    cJSON_AddNumberToObject(json, "bad_crc", stats.badCrc);
    cJSON_AddNumberToObject(json, "dropped", stats.dropped);
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
    cJSON_AddNumberToObject(heap, "largest_block", heap_caps_get_largest_free_block(MALLOC_CAP_INTERNAL));
    cJSON* stacks = cJSON_AddObjectToObject(result, "stack_free");
    cJSON_AddNumberToObject(stacks, "lock_worker", lock_manager::workerStackFree());
    cJSON_AddNumberToObject(stacks, "nimble_host", stackFree("nimble_host"));
    cJSON_AddNumberToObject(stacks, "console", stackFree("console"));
    cJSON_AddItemToObject(result, "ble", bleJson());
    store::Usage usage;
    if (store::usage(usage) != ESP_OK) {
        cJSON_Delete(result);
        return rpc::fail("internal", "cannot read NVS usage");
    }
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
    if (store::cfg::saveWifi(wifi) != ESP_OK || wifi::apply(wifi) != ESP_OK) {
        mbedtls_platform_zeroize(&owner, sizeof(owner));
        return rpc::fail("internal", "cannot store or apply the Wi-Fi configuration");
    }
    const bool stored = store::auth::saveOwner(owner) == ESP_OK;
    const std::string uri =
        latchkey_util::otpauthUri(board::name(), owner.totpSecret.data(), owner.totpSecret.size());
    mbedtls_platform_zeroize(&owner, sizeof(owner));
    if (!stored) {
        return rpc::fail("internal", "cannot store the owner");
    }
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
    if (wifi::apply(wifi) != ESP_OK) {
        return rpc::fail("internal", "cannot apply the Wi-Fi configuration");
    }
    return rpc::ok();
}

rpc::Reply reboot(const cJSON*, const rpc::Context&) {
    return restartLater() == ESP_OK ? rpc::ok() : rpc::fail("internal", "cannot schedule the restart");
}

rpc::Reply factoryReset(const cJSON* params, const rpc::Context&) {
    const cJSON* forceItem = member(params, "force");
    if (forceItem != nullptr && !cJSON_IsNull(forceItem) && !cJSON_IsBool(forceItem)) {
        return rpc::fail("invalid_params", "force must be true or false");
    }
    const bool force = cJSON_IsTrue(forceItem);
    std::lock_guard<std::mutex> lock(s_claimMutex);
    size_t locks = 0;
    if (lock_manager::storedCount(locks) != ESP_OK) {
        return rpc::fail("internal", "cannot read the stored locks");
    }
    if (locks > 0 && !force) {
        return rpc::fail("locks_paired",
                         "the board holds lock keys: factory-reset or forget each lock first, or pass force");
    }
    if (lock_manager::eraseAll() != ESP_OK) {
        return rpc::fail("internal", "cannot erase the lock keys");
    }
    const bool erased = store::auth::erase() == ESP_OK && store::cfg::erase() == ESP_OK && audit::clear() == ESP_OK;
    if (!erased) {
        lock_manager::cancelErase();
        return rpc::fail("internal", "the lock keys are erased, but the rest of the reset failed");
    }
    ESP_LOGW(TAG, "factory reset: owner, Wi-Fi, locks and audit erased");
    return restartLater() == ESP_OK ? rpc::ok() : rpc::fail("internal", "erased, but cannot schedule the restart");
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

rpc::Reply logSet(const cJSON* params, const rpc::Context&) {
    std::string tag;
    std::string level;
    if (!readString(params, "tag", 1, kMaxLogTag, tag) || !readString(params, "level", 1, 8, level)) {
        return rpc::fail("invalid_params", "log.set needs a tag and a level");
    }
    for (const LogLevelName& entry : kLogLevels) {
        if (level == entry.name) {
            esp_log_level_set(tag.c_str(), entry.level);
            return rpc::ok();
        }
    }
    return rpc::fail("invalid_params", "level is none, error, warn, info, debug or verbose");
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
    const esp_timer_create_args_t restart = {
        .callback = restartNow,
        .arg = nullptr,
        .dispatch_method = ESP_TIMER_TASK,
        .name = "restart",
        .skip_unhandled_events = true,
    };
    ESP_ERROR_CHECK(esp_timer_create(&restart, &s_restartTimer));
    rpc::registerMethod("system.info", {.audited = false}, info);
    rpc::registerMethod("system.setup", {.needsSession = false, .serialOnly = true}, setup);
    rpc::registerMethod("system.wifi.set", {}, wifiSet);
    rpc::registerMethod("system.reboot", {}, reboot);
    rpc::registerMethod("system.factoryReset", {.needsButton = true}, factoryReset);
    rpc::registerMethod("system.time.set", {.serialOnly = true}, timeSet);
    rpc::registerMethod("system.log.set", {.serialOnly = true, .audited = false}, logSet);
    rpc::registerMethod("audit.list", {.audited = false}, auditList);
}

}
