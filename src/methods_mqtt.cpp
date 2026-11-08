// SPDX-License-Identifier: GPL-3.0-or-later
#include <cmath>
#include <cstdint>
#include <cstring>
#include <mutex>
#include <string>
#include <string_view>
#include <utility>

#include "mbedtls/platform_util.h"

#include "latchkey_util/ha_discovery.h"
#include "latchkey_util/label.h"
#include "latchkey_util/mqtt_settings.h"
#include "methods.h"
#include "mqtt.h"
#include "rpc.h"
#include "store.h"

namespace methods {

namespace {

constexpr double kMaxPort = 65535;
constexpr const char* kSpaces = " \t\r\n\f\v";
constexpr const char* kHostMessage = "host must be a host name or an IPv4 address of at most 64 characters";
constexpr const char* kUsernameMessage = "username must be at most 64 printable characters";
constexpr const char* kPrefixMessage = "prefix must be 1 to 32 letters, digits, - or _";
constexpr const char* kPasswordMessage = "password must be a string of at most 64 bytes";

std::mutex s_mutex;

rpc::Reply invalid(const char* message) { return rpc::fail("invalid_argument", message); }

const cJSON* member(const cJSON* params, const char* key) { return cJSON_GetObjectItemCaseSensitive(params, key); }

bool absent(const cJSON* item) { return item == nullptr || cJSON_IsNull(item); }

void wipe(std::string& secret) {
    secret.resize(secret.capacity());
    mbedtls_platform_zeroize(secret.data(), secret.size());
    secret.clear();
}

std::string trimmed(std::string_view text) {
    const size_t begin = text.find_first_not_of(kSpaces);
    if (begin == std::string_view::npos) {
        return {};
    }
    return std::string(text.substr(begin, text.find_last_not_of(kSpaces) - begin + 1));
}

bool readText(const cJSON* params, const char* key, std::string& out) {
    const cJSON* item = member(params, key);
    if (absent(item)) {
        out.clear();
        return true;
    }
    if (!cJSON_IsString(item) || item->valuestring == nullptr) {
        return false;
    }
    out = trimmed(item->valuestring);
    return true;
}

bool isUsername(const std::string& username) {
    std::string normalized;
    return username.empty() ||
           (latchkey_util::normalizeLabel(username, latchkey_util::kMaxMqttUsername, normalized) &&
            username.size() <= latchkey_util::kMaxMqttUsername);
}

bool readPort(const cJSON* params, uint16_t& out) {
    const cJSON* item = member(params, "port");
    if (absent(item)) {
        out = latchkey_util::kDefaultMqttPort;
        return true;
    }
    if (!cJSON_IsNumber(item) || std::floor(item->valuedouble) != item->valuedouble || item->valuedouble < 1 ||
        item->valuedouble > kMaxPort) {
        return false;
    }
    out = static_cast<uint16_t>(item->valuedouble);
    return true;
}

rpc::Reply readSettings(const cJSON* params, store::cfg::Mqtt& out, bool& passwordGiven) {
    const cJSON* enabled = member(params, "enabled");
    if (!cJSON_IsBool(enabled)) {
        return invalid("enabled must be true or false");
    }
    store::cfg::Mqtt settings;
    settings.enabled = cJSON_IsTrue(enabled);
    if (!readText(params, "host", settings.host)) {
        return invalid(kHostMessage);
    }
    if (settings.host.empty() && settings.enabled) {
        return invalid("host is required to turn MQTT on");
    }
    if (!settings.host.empty() && !latchkey_util::isMqttHost(settings.host)) {
        return invalid(kHostMessage);
    }
    if (!readPort(params, settings.port)) {
        return invalid("port must be a whole number from 1 to 65535");
    }
    if (!readText(params, "username", settings.username) || !isUsername(settings.username)) {
        return invalid(kUsernameMessage);
    }
    if (!readText(params, "prefix", settings.prefix)) {
        return invalid(kPrefixMessage);
    }
    if (settings.prefix.empty()) {
        settings.prefix = latchkey_util::kDefaultHaPrefix;
    }
    if (settings.prefix.size() > latchkey_util::kMaxHaPrefix || !latchkey_util::isHaId(settings.prefix)) {
        return invalid(kPrefixMessage);
    }
    const cJSON* password = member(params, "password");
    passwordGiven = !absent(password);
    if (passwordGiven) {
        if (!cJSON_IsString(password) || password->valuestring == nullptr ||
            std::strlen(password->valuestring) > latchkey_util::kMaxMqttPassword) {
            return invalid(kPasswordMessage);
        }
        settings.password = password->valuestring;
    }
    out = settings;
    wipe(settings.password);
    return rpc::ok();
}

cJSON* view(const store::cfg::Mqtt& settings) {
    const mqtt::Status status = mqtt::status();
    cJSON* json = cJSON_CreateObject();
    cJSON_AddBoolToObject(json, "enabled", settings.enabled);
    cJSON_AddStringToObject(json, "host", settings.host.c_str());
    cJSON_AddNumberToObject(json, "port", settings.port);
    cJSON_AddStringToObject(json, "username", settings.username.c_str());
    cJSON_AddStringToObject(json, "prefix", settings.prefix.c_str());
    cJSON_AddBoolToObject(json, "passwordSet", !settings.password.empty());
    cJSON_AddBoolToObject(json, "connected", settings.enabled && status.connected);
    if (settings.enabled && !status.problem.empty()) {
        cJSON_AddStringToObject(json, "problem", status.problem.c_str());
    } else {
        cJSON_AddNullToObject(json, "problem");
    }
    return json;
}

rpc::Reply get(const cJSON*, const rpc::Context&) {
    store::cfg::Mqtt settings;
    if (store::cfg::loadMqtt(settings) != ESP_OK) {
        return rpc::fail("internal", "cannot read the MQTT settings");
    }
    rpc::Reply reply = rpc::ok(view(settings));
    wipe(settings.password);
    return reply;
}

rpc::Reply set(const cJSON* params, const rpc::Context&) {
    store::cfg::Mqtt settings;
    bool passwordGiven = false;
    rpc::Reply problem = readSettings(params, settings, passwordGiven);
    if (!problem.error.empty()) {
        return problem;
    }
    std::lock_guard<std::mutex> lock(s_mutex);
    if (!passwordGiven) {
        store::cfg::Mqtt current;
        const esp_err_t error = store::cfg::loadMqtt(current);
        if (error != ESP_OK && error != ESP_ERR_INVALID_VERSION) {
            wipe(current.password);
            return rpc::fail("internal", "cannot read the MQTT settings");
        }
        if (latchkey_util::keepsPassword({current.host, current.port, current.username},
                                         {settings.host, settings.port, settings.username})) {
            settings.password = current.password;
        }
        wipe(current.password);
    }
    if (store::cfg::saveMqtt(settings) != ESP_OK) {
        wipe(settings.password);
        return rpc::fail("internal", "cannot store the MQTT settings");
    }
    if (!mqtt::apply(settings)) {
        wipe(settings.password);
        return rpc::fail("internal", "the settings are stored, but MQTT cannot start: restart the board");
    }
    rpc::Reply reply = rpc::ok(view(settings));
    wipe(settings.password);
    return reply;
}

}

void registerMqtt() {
    rpc::registerMethod("mqtt.get", {.audited = false}, get);
    rpc::registerMethod("mqtt.set", {}, set);
}

}
