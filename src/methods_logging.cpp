// SPDX-License-Identifier: GPL-3.0-or-later
#include <cmath>
#include <cstdint>
#include <optional>
#include <string>
#include <string_view>

#include "nvs.h"
#include "sdkconfig.h"

#include "latchkey_util/hostname.h"
#include "latchkey_util/log_ring.h"
#include "latchkey_util/syslog.h"
#include "logs.h"
#include "methods.h"
#include "rpc.h"
#include "store.h"
#include "syslog_client.h"

namespace methods {

namespace {

constexpr size_t kMaxLines = 100;
#if CONFIG_IDF_TARGET_ESP32
constexpr size_t kPageBytes = 2048;
#else
constexpr size_t kPageBytes = 8192;
#endif
constexpr const char* kLevelMessage = "level is error, warn, info, debug or verbose";

const cJSON* member(const cJSON* object, const char* key) { return cJSON_GetObjectItemCaseSensitive(object, key); }

bool present(const cJSON* item) { return item != nullptr && !cJSON_IsNull(item); }

bool readWhole(const cJSON* item, double minValue, double maxValue, double& out) {
    if (!cJSON_IsNumber(item) || std::floor(item->valuedouble) != item->valuedouble || item->valuedouble < minValue ||
        item->valuedouble > maxValue) {
        return false;
    }
    out = item->valuedouble;
    return true;
}

std::optional<latchkey_util::LogLevel> readLevel(const cJSON* item) {
    if (!cJSON_IsString(item) || item->valuestring == nullptr) {
        return std::nullopt;
    }
    return latchkey_util::parseLogLevel(item->valuestring);
}

bool readText(const cJSON* params, const char* key, std::string& out) {
    const cJSON* item = member(params, key);
    if (!present(item)) {
        out.clear();
        return true;
    }
    if (!cJSON_IsString(item) || item->valuestring == nullptr) {
        return false;
    }
    std::string_view text(item->valuestring);
    while (!text.empty() && text.front() == ' ') {
        text.remove_prefix(1);
    }
    while (!text.empty() && text.back() == ' ') {
        text.remove_suffix(1);
    }
    out.assign(text);
    return true;
}

rpc::Reply logsList(const cJSON* params, const rpc::Context&) {
    std::optional<uint32_t> since;
    double number = 0;
    if (present(member(params, "since"))) {
        if (!readWhole(member(params, "since"), 0, UINT32_MAX, number)) {
            return rpc::fail("invalid_argument", "since must be the sequence number of a log line");
        }
        since = static_cast<uint32_t>(number);
    }
    latchkey_util::LogLevel threshold = latchkey_util::LogLevel::Verbose;
    if (present(member(params, "level"))) {
        const std::optional<latchkey_util::LogLevel> level = readLevel(member(params, "level"));
        if (!level.has_value()) {
            return rpc::fail("invalid_argument", kLevelMessage);
        }
        threshold = *level;
    }
    double limit = kMaxLines;
    if (present(member(params, "limit")) && !readWhole(member(params, "limit"), 1, kMaxLines, limit)) {
        return rpc::fail("invalid_argument", "limit must be 1 to 100");
    }
    const size_t wanted = static_cast<size_t>(limit);
    logs::Cursor cursor = since.has_value() ? logs::after(*since) : logs::newest(wanted, threshold);
    const uint64_t first = since.has_value() ? static_cast<uint64_t>(*since) + 1 : 0;
    const uint32_t oldest = logs::oldest();
    const uint32_t missed = since.has_value() && first < oldest ? static_cast<uint32_t>(oldest - first) : 0;
    std::string lines = "[";
    std::string line;
    size_t count = 0;
    bool more = false;
    uint32_t next = cursor.seq > 0 ? cursor.seq - 1 : 0;
    latchkey_util::LogEntry entry;
    while (true) {
        uint32_t skipped = 0;
        if (!logs::read(cursor, threshold, entry, skipped)) {
            next = cursor.seq > 0 ? cursor.seq - 1 : 0;
            break;
        }
        if (count == wanted) {
            more = true;
            break;
        }
        line.clear();
        latchkey_util::appendLogEntryJson(line, entry, logs::timesOf(entry));
        if (count > 0 && lines.size() + line.size() + 2 > kPageBytes) {
            more = true;
            break;
        }
        if (count > 0) {
            lines += ',';
        }
        lines += line;
        ++count;
        next = entry.seq;
    }
    lines += ']';
    cJSON* result = cJSON_CreateObject();
    if (cJSON_AddRawToObject(result, "lines", lines.c_str()) == nullptr) {
        cJSON_Delete(result);
        return rpc::fail("internal", "out of memory listing the log lines");
    }
    cJSON_AddBoolToObject(result, "more", more);
    cJSON_AddNumberToObject(result, "next", next);
    cJSON_AddNumberToObject(result, "missed", missed);
    return rpc::ok(result);
}

cJSON* syslogJson() {
    const store::cfg::Syslog settings = syslog_client::settings();
    const syslog_client::Status status = syslog_client::status();
    cJSON* json = cJSON_CreateObject();
    cJSON_AddBoolToObject(json, "enabled", settings.enabled);
    cJSON_AddStringToObject(json, "host", settings.host.c_str());
    cJSON_AddNumberToObject(json, "port", settings.port);
    cJSON_AddStringToObject(json, "transport", settings.tcp ? "tcp" : "udp");
    cJSON_AddStringToObject(json, "appName", settings.appName.c_str());
    cJSON_AddStringToObject(json, "level", std::string(latchkey_util::logLevelName(settings.level)).c_str());
    cJSON_AddBoolToObject(json, "connected", status.connected);
    cJSON_AddNumberToObject(json, "sent", status.sent);
    cJSON_AddNumberToObject(json, "dropped", status.dropped);
    cJSON_AddNumberToObject(json, "errors", status.errors);
    return json;
}

rpc::Reply syslogGet(const cJSON*, const rpc::Context&) { return rpc::ok(syslogJson()); }

rpc::Reply syslogSet(const cJSON* params, const rpc::Context&) {
    store::cfg::Syslog settings;
    const cJSON* enabled = member(params, "enabled");
    if (!cJSON_IsBool(enabled)) {
        return rpc::fail("invalid_argument", "enabled must be true or false");
    }
    settings.enabled = cJSON_IsTrue(enabled);
    if (!readText(params, "host", settings.host) ||
        (!settings.host.empty() && !latchkey_util::isHostname(settings.host))) {
        return rpc::fail("invalid_argument", "host must be a host name or an IPv4 address of at most 64 characters");
    }
    if (settings.enabled && settings.host.empty()) {
        return rpc::fail("invalid_argument", "host is required to turn remote logging on");
    }
    double port = latchkey_util::kDefaultSyslogPort;
    if (present(member(params, "port")) && !readWhole(member(params, "port"), 1, 65535, port)) {
        return rpc::fail("invalid_argument", "port must be 1 to 65535");
    }
    settings.port = static_cast<uint16_t>(port);
    std::string transport;
    if (!readText(params, "transport", transport) || (!transport.empty() && transport != "udp" && transport != "tcp")) {
        return rpc::fail("invalid_argument", "transport is udp or tcp");
    }
    settings.tcp = transport == "tcp";
    std::string appName;
    if (!readText(params, "appName", appName) || (!appName.empty() && !latchkey_util::isSyslogAppName(appName))) {
        return rpc::fail("invalid_argument", "appName must be 1 to 48 printable ASCII characters without spaces");
    }
    if (!appName.empty()) {
        settings.appName = appName;
    }
    if (present(member(params, "level"))) {
        const std::optional<latchkey_util::LogLevel> level = readLevel(member(params, "level"));
        if (!level.has_value()) {
            return rpc::fail("invalid_argument", kLevelMessage);
        }
        settings.level = *level;
    }
    const esp_err_t error = syslog_client::apply(settings);
    if (error == ESP_ERR_NVS_NOT_ENOUGH_SPACE) {
        return rpc::fail("storage_full", "the board's storage is down to what it keeps for pairing and the audit log");
    }
    if (error != ESP_OK) {
        return rpc::fail("internal", "cannot store or start remote logging");
    }
    return rpc::ok(syslogJson());
}

}

void addLoggingInfo(cJSON* info) {
    const logs::Stats stats = logs::stats();
    cJSON* ring = cJSON_AddObjectToObject(info, "logs");
    cJSON_AddNumberToObject(ring, "lines", stats.lines);
    cJSON_AddNumberToObject(ring, "capacity", stats.capacity);
    cJSON_AddNumberToObject(ring, "withheld", stats.withheld);
    const syslog_client::Status status = syslog_client::status();
    cJSON* shipping = cJSON_AddObjectToObject(info, "syslog");
    cJSON_AddBoolToObject(shipping, "enabled", syslog_client::settings().enabled);
    cJSON_AddBoolToObject(shipping, "connected", status.connected);
    cJSON_AddNumberToObject(shipping, "sent", status.sent);
    cJSON_AddNumberToObject(shipping, "dropped", status.dropped);
    cJSON_AddNumberToObject(shipping, "errors", status.errors);
}

void registerLogging() {
    rpc::registerMethod("system.logs", {.audited = false}, logsList);
    rpc::registerMethod("system.syslog.get", {.audited = false}, syslogGet);
    rpc::registerMethod("system.syslog.set", {}, syslogSet);
}

}
