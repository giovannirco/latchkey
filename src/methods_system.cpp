// SPDX-License-Identifier: GPL-3.0-or-later
#include <cmath>
#include <cstdint>
#include <cstring>
#include <mutex>
#include <optional>
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
#include "sdkconfig.h"

#include "audit.h"
#include "auth.h"
#include "ble_central.h"
#include "board.h"
#include "certs.h"
#include "clock.h"
#include "console.h"
#include "http.h"
#include "jobs.h"
#include "latchkey_util/ipv4.h"
#include "latchkey_util/otpauth.h"
#include "latchkey_util/tz.h"
#include "lock_manager.h"
#include "methods.h"
#include "mqtt.h"
#include "rpc.h"
#include "store.h"
#include "wifi.h"

namespace methods {

namespace {

constexpr const char* TAG = "system";
constexpr size_t kMaxSsid = 32;
constexpr size_t kMinWifiPassword = 8;
constexpr size_t kMaxWifiPassword = 63;
constexpr uint64_t kRestartDelayUs = 500 * 1000;
constexpr const char* kWifiParamsMessage = "wifi needs ssid, password, ip, gateway, netmask and dns";
constexpr size_t kMaxLogTag = 15;
constexpr size_t kAuditEntryText = 128;

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
    cJSON_AddNumberToObject(json, "lockReports", stats.lockReports);
    cJSON_AddNumberToObject(json, "frames", stats.frames);
    cJSON_AddNumberToObject(json, "badCrc", stats.badCrc);
    cJSON_AddNumberToObject(json, "dropped", stats.dropped);
    return json;
}

rpc::Reply info(const cJSON*, const rpc::Context&) {
    cJSON* result = cJSON_CreateObject();
    cJSON_AddStringToObject(result, "firmware", esp_app_get_description()->version);
    cJSON_AddStringToObject(result, "board", board::name());
    cJSON_AddStringToObject(result, "chip", CONFIG_IDF_TARGET);
    cJSON_AddStringToObject(result, "idf", esp_get_idf_version());
    cJSON_AddNumberToObject(result, "uptime", static_cast<double>(esp_timer_get_time() / 1000000));
    cJSON* heap = cJSON_AddObjectToObject(result, "heap");
    cJSON_AddNumberToObject(heap, "free", esp_get_free_heap_size());
    cJSON_AddNumberToObject(heap, "minFree", esp_get_minimum_free_heap_size());
    cJSON_AddNumberToObject(heap, "largestBlock", heap_caps_get_largest_free_block(MALLOC_CAP_INTERNAL));
    cJSON* stacks = cJSON_AddObjectToObject(result, "stackFree");
    cJSON_AddNumberToObject(stacks, "lockWorker", lock_manager::workerStackFree());
    cJSON_AddNumberToObject(stacks, "nimbleHost", stackFree("nimble_host"));
    cJSON_AddNumberToObject(stacks, "console", stackFree("console"));
    cJSON_AddNumberToObject(stacks, "httpsServer", http::serverStackFree());
    cJSON_AddNumberToObject(stacks, "webRequests", http::workerStackFree());
    cJSON_AddNumberToObject(stacks, "webJobs", jobs::stackFree());
    cJSON_AddNumberToObject(stacks, "mqtt", mqtt::stackFree());
    cJSON_AddNumberToObject(stacks, "mqttClient", mqtt::clientStackFree());
    cJSON_AddItemToObject(result, "ble", bleJson());
    cJSON_AddItemToObject(result, "warnings", lock_manager::warnings());
    store::Usage usage;
    if (store::usage(usage) != ESP_OK) {
        cJSON_Delete(result);
        return rpc::fail("internal", "cannot read NVS usage");
    }
    cJSON* nvs = cJSON_AddObjectToObject(result, "nvs");
    cJSON_AddNumberToObject(nvs, "usedEntries", usage.usedEntries);
    cJSON_AddNumberToObject(nvs, "availableEntries", usage.availableEntries);
    cJSON_AddNumberToObject(nvs, "totalEntries", usage.totalEntries);
    cJSON_AddNumberToObject(nvs, "reservedEntries", store::reservedEntries());
    cJSON_AddBoolToObject(result, "claimed", store::auth::claimed());
    cJSON_AddItemToObject(result, "wifi", wifiJson());
    const bool synced = wallclock::synced();
    cJSON* time = cJSON_AddObjectToObject(result, "time");
    cJSON_AddStringToObject(result, "timezone", wallclock::timezone().c_str());
    if (synced) {
        const int64_t utc = wallclock::utcSeconds();
        cJSON_AddNumberToObject(time, "utc", static_cast<double>(utc));
        cJSON_AddStringToObject(result, "localTime",
                                latchkey_util::localTimestamp(utc, wallclock::utcOffsetAt(utc)).c_str());
    } else {
        cJSON_AddNullToObject(time, "utc");
        cJSON_AddNullToObject(result, "localTime");
    }
    cJSON_AddBoolToObject(time, "synced", synced);
    const std::optional<std::string> fingerprint = certs::fingerprint();
    if (fingerprint.has_value()) {
        cJSON_AddStringToObject(result, "certFingerprint", fingerprint->c_str());
    } else {
        cJSON_AddNullToObject(result, "certFingerprint");
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
        return rpc::fail("invalid_argument", kWifiParamsMessage);
    }
    std::string password;
    if (!readString(params, "password", auth::kMinPassword, auth::kMaxPassword, password)) {
        return rpc::fail("invalid_argument", "password must be 12 to 128 bytes");
    }
    store::auth::Owner owner;
    owner.password.iterations = auth::kPasswordIterations;
    esp_fill_random(owner.password.salt.data(), owner.password.salt.size());
    esp_fill_random(owner.totpSecret.data(), owner.totpSecret.size());
    const int64_t started = esp_timer_get_time();
    const bool hashed = auth::hashPassword(password, owner.password);
    mbedtls_platform_zeroize(password.data(), password.size());
    if (!hashed) {
        return rpc::fail("internal", "password hashing failed");
    }
    ESP_LOGI(TAG, "owner password hashed with %u iterations in %lld ms", static_cast<unsigned>(owner.password.iterations),
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
        return rpc::fail("invalid_argument", kWifiParamsMessage);
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

bool readForce(const cJSON* params, bool& force) {
    const cJSON* forceItem = member(params, "force");
    if (forceItem != nullptr && !cJSON_IsNull(forceItem) && !cJSON_IsBool(forceItem)) {
        return false;
    }
    force = cJSON_IsTrue(forceItem);
    return true;
}

rpc::Reply checkLocksKept(bool force) {
    size_t locks = 0;
    if (lock_manager::storedCount(locks) != ESP_OK) {
        return rpc::fail("internal", "cannot read the stored locks");
    }
    if (locks > 0 && !force) {
        return rpc::fail("locks_paired",
                         "the board holds lock keys: factory-reset or forget each lock first, or pass force");
    }
    return rpc::ok();
}

rpc::Reply checkFactoryReset(const cJSON* params, const rpc::Context&) {
    bool force = false;
    if (!readForce(params, force)) {
        return rpc::fail("invalid_argument", "force must be true or false");
    }
    return checkLocksKept(force);
}

rpc::Reply factoryReset(const cJSON* params, const rpc::Context&) {
    bool force = false;
    if (!readForce(params, force)) {
        return rpc::fail("invalid_argument", "force must be true or false");
    }
    std::lock_guard<std::mutex> lock(s_claimMutex);
    rpc::Reply problem = checkLocksKept(force);
    if (!problem.error.empty()) {
        return problem;
    }
    if (!mqtt::forgetAll()) {
        ESP_LOGW(TAG, "factory reset: the Home Assistant entities could not be removed from the broker");
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
        return rpc::fail("invalid_argument", "utc must be whole seconds from 2024 to 2100");
    }
    if (!wallclock::set(static_cast<int64_t>(utc))) {
        return rpc::fail("internal", "cannot set the clock");
    }
    return rpc::ok();
}

cJSON* timezoneJson() {
    cJSON* result = cJSON_CreateObject();
    cJSON_AddStringToObject(result, "tz", wallclock::timezone().c_str());
    if (wallclock::synced()) {
        cJSON_AddNumberToObject(result, "utcOffset", wallclock::utcOffsetSeconds());
    } else {
        cJSON_AddNullToObject(result, "utcOffset");
    }
    return result;
}

rpc::Reply timezoneGet(const cJSON*, const rpc::Context&) { return rpc::ok(timezoneJson()); }

rpc::Reply timezoneSet(const cJSON* params, const rpc::Context&) {
    std::string timezone;
    if (!readString(params, "tz", 1, latchkey_util::kMaxTimeZoneLength, timezone)) {
        return rpc::fail("invalid_argument", "tz must be a POSIX TZ string such as CET-1CEST,M3.5.0,M10.5.0/3");
    }
    const esp_err_t error = wallclock::setTimezone(timezone);
    if (error == ESP_ERR_INVALID_ARG) {
        return rpc::fail("invalid_argument",
                         "tz must be a POSIX TZ string such as CET-1CEST,M3.5.0,M10.5.0/3, with rules for daylight time");
    }
    if (error != ESP_OK) {
        return rpc::fail("internal", "cannot store the time zone");
    }
    return rpc::ok(timezoneJson());
}

rpc::Reply logSet(const cJSON* params, const rpc::Context&) {
    std::string tag;
    std::string level;
    if (!readString(params, "tag", 1, kMaxLogTag, tag) || !readString(params, "level", 1, 8, level)) {
        return rpc::fail("invalid_argument", "log.set needs a tag and a level");
    }
    for (const LogLevelName& entry : kLogLevels) {
        if (level == entry.name) {
            esp_log_level_set(tag.c_str(), entry.level);
            return rpc::ok();
        }
    }
    return rpc::fail("invalid_argument", "level is none, error, warn, info, debug or verbose");
}

rpc::Reply auditList(const cJSON* params, const rpc::Context&) {
    double before = UINT32_MAX;
    const cJSON* beforeItem = member(params, "before");
    if (beforeItem != nullptr && !cJSON_IsNull(beforeItem) && !readWhole(beforeItem, 1, UINT32_MAX, before)) {
        return rpc::fail("invalid_argument", "before must be a sequence number");
    }
    double limit = audit::kMaxPage;
    const cJSON* limitItem = member(params, "limit");
    if (limitItem != nullptr && !readWhole(limitItem, 1, audit::kMaxPage, limit)) {
        return rpc::fail("invalid_argument", "limit must be 1 to 50");
    }
    std::string entries = "[";
    bool more = false;
    uint32_t next = 0;
    {
        const audit::Page page = audit::list(static_cast<uint32_t>(before), static_cast<size_t>(limit));
        entries.reserve(page.entries.size() * kAuditEntryText + 2);
        for (const audit::StoredEntry& stored : page.entries) {
            const rpc::Json entry(audit::toJson(stored));
            char* text = cJSON_PrintUnformatted(entry.get());
            if (text == nullptr) {
                return rpc::fail("internal", "out of memory listing the audit log");
            }
            if (entries.size() > 1) {
                entries += ',';
            }
            entries += text;
            cJSON_free(text);
        }
        more = page.more;
        next = page.more ? page.entries.back().seq : 0;
    }
    entries += ']';
    cJSON* result = cJSON_CreateObject();
    const bool added = cJSON_AddRawToObject(result, "entries", entries.c_str()) != nullptr;
    std::string().swap(entries);
    if (!added) {
        cJSON_Delete(result);
        return rpc::fail("internal", "out of memory listing the audit log");
    }
    cJSON_AddBoolToObject(result, "more", more);
    if (more) {
        cJSON_AddNumberToObject(result, "next", next);
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
    rpc::registerMethod("system.factoryReset", {.needsButton = true}, factoryReset, checkFactoryReset);
    rpc::registerMethod("system.time.set", {.serialOnly = true}, timeSet);
    rpc::registerMethod("system.timezone.get", {.audited = false}, timezoneGet);
    rpc::registerMethod("system.timezone.set", {}, timezoneSet);
    rpc::registerMethod("system.log.set", {.serialOnly = true, .audited = false}, logSet);
    rpc::registerMethod("audit.list", {.audited = false}, auditList);
}

}
