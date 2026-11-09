// SPDX-License-Identifier: GPL-3.0-or-later
#include "access_requests.h"

#include <cmath>
#include <cstdio>
#include <cstring>

#include "esp_heap_caps.h"
#include "esp_log.h"
#include "mbedtls/platform_util.h"

#include "clock.h"
#include "latchkey_util/ble_adv.h"
#include "latchkey_util/credential_id.h"
#include "latchkey_util/feature_gate.h"
#include "latchkey_util/label.h"
#include "latchkey_util/label_table.h"
#include "latchkey_util/lock_time.h"
#include "latchkey_util/passcode_rules.h"
#include "lock_manager.h"

namespace lock_access {

namespace {

constexpr const char* TAG = "access";
constexpr int64_t kLatestUtc = 4102444800;

bool isText(const cJSON* item) { return cJSON_IsString(item) && item->valuestring != nullptr; }

bool isBlank(const char* text) {
    for (const char* c = text; *c != '\0'; ++c) {
        if (std::strchr(" \t\r\n\f\v", *c) == nullptr) {
            return false;
        }
    }
    return true;
}

bool readUtc(const cJSON* item, int64_t& out) {
    if (!cJSON_IsNumber(item) || std::floor(item->valuedouble) != item->valuedouble || item->valuedouble < 0 ||
        item->valuedouble > kLatestUtc) {
        return false;
    }
    out = static_cast<int64_t>(item->valuedouble);
    return true;
}

const latchkey_util::UtcOffsetAt& offsetAt() {
    static const latchkey_util::UtcOffsetAt offset = [](int64_t utc) { return wallclock::utcOffsetAt(utc); };
    return offset;
}

}

void wipe(std::string& text) {
    text.resize(text.capacity());
    mbedtls_platform_zeroize(text.data(), text.size());
    text.clear();
}

Secret& Secret::operator=(const Secret& other) {
    if (this != &other) {
        wipe(value_);
        value_ = other.value_;
    }
    return *this;
}

rpc::Reply invalid(const char* message) { return rpc::fail("invalid_argument", message); }

rpc::Reply withTarget(rpc::Reply reply, const std::string& mac) {
    reply.target = mac;
    return reply;
}

const cJSON* member(const cJSON* params, const char* key) { return cJSON_GetObjectItemCaseSensitive(params, key); }

bool absent(const cJSON* item) { return item == nullptr || cJSON_IsNull(item); }

bool readLock(const cJSON* params, std::string& out) {
    const cJSON* item = member(params, "lock");
    uint8_t address[latchkey_util::kBleAddressSize];
    if (!isText(item) || !latchkey_util::parseBleAddress(item->valuestring, address)) {
        return false;
    }
    out = latchkey_util::formatBleAddress(address);
    return true;
}

bool readName(const cJSON* item, std::string& out) {
    if (absent(item)) {
        out.clear();
        return true;
    }
    if (!isText(item)) {
        return false;
    }
    if (isBlank(item->valuestring)) {
        out.clear();
        return true;
    }
    return latchkey_util::normalizeLabel(item->valuestring, latchkey_util::kMaxLabelNameCodePoints, out) &&
           out.size() <= latchkey_util::kMaxLabelNameBytes;
}

bool readCode(const cJSON* item, Secret& out) {
    if (absent(item) || (isText(item) && item->valuestring[0] == '\0')) {
        out = Secret();
        return true;
    }
    if (!isText(item) || !ttlock::isPasscode(item->valuestring)) {
        return false;
    }
    out = Secret(item->valuestring);
    return true;
}

bool readWindow(const cJSON* item, ttlock::Validity& out) {
    int64_t start = 0;
    int64_t end = 0;
    return cJSON_IsObject(item) && readUtc(member(item, "start"), start) && readUtc(member(item, "end"), end) &&
           latchkey_util::lockValidity(start, end, offsetAt(), out);
}

bool readCycle(const cJSON* item, std::optional<latchkey_util::WeeklyWindow>& out) {
    if (absent(item)) {
        out.reset();
        return true;
    }
    const cJSON* days = member(item, "days");
    const cJSON* start = member(item, "start");
    const cJSON* end = member(item, "end");
    if (!cJSON_IsObject(item) || !cJSON_IsArray(days) || !isText(start) || !isText(end)) {
        return false;
    }
    latchkey_util::WeeklyWindow window;
    const cJSON* day = nullptr;
    cJSON_ArrayForEach(day, days) {
        if (!cJSON_IsNumber(day) || std::floor(day->valuedouble) != day->valuedouble ||
            !latchkey_util::addWeekday(static_cast<int>(day->valuedouble), window.days)) {
            return false;
        }
    }
    if (!latchkey_util::parseClockTime(start->valuestring, window.startMinute) ||
        !latchkey_util::parseClockTime(end->valuestring, window.endMinute) || !latchkey_util::isWeeklyWindow(window)) {
        return false;
    }
    out = window;
    return true;
}

bool readCredentialId(const cJSON* item, uint64_t maximum, uint64_t& out) {
    return isText(item) && latchkey_util::parseCredentialId(item->valuestring, maximum, out);
}

rpc::Reply gate(const std::string& mac, std::initializer_list<ttlock::Feature> needed) {
    uint64_t mask = 0;
    rpc::Reply known = lock_manager::featureMask(mac, mask);
    if (!known.error.empty()) {
        return known;
    }
    const std::optional<ttlock::Feature> missing = latchkey_util::firstMissingFeature(mask, needed);
    if (missing.has_value()) {
        return rpc::fail("unsupported", latchkey_util::missingFeatureMessage(*missing).c_str());
    }
    return rpc::ok();
}

bool utcWindow(const ttlock::Validity& validity, latchkey_util::UtcWindow& out) {
    return latchkey_util::utcOfLockTime(validity.start, offsetAt(), out.start) &&
           latchkey_util::utcOfLockTime(validity.end, offsetAt(), out.end);
}

rpc::Reply labelsUnreadable(esp_err_t error) {
    ESP_LOGE(TAG, "cannot read the labels: %s", esp_err_to_name(error));
    return rpc::fail("internal", "the board cannot read its names for this lock");
}

rpc::Reply storageFull() {
    return rpc::fail("storage_full",
                     "the board's storage is nearly full and keeps the rest for pairing and the audit log: remove "
                     "names, or forget a lock you no longer use");
}

bool listFits(size_t textBound) {
    return latchkey_util::listFitsInHeap(textBound, heap_caps_get_free_size(MALLOC_CAP_8BIT),
                                         heap_caps_get_largest_free_block(MALLOC_CAP_8BIT));
}

rpc::Reply tooLarge(size_t entries, const char* noun) {
    char message[120];
    std::snprintf(message, sizeof(message), "listing %u %s exceeds this board's response memory limits",
                  static_cast<unsigned>(entries), noun);
    return rpc::fail("too_large", message);
}

cJSON* rawJson(const std::string& text) { return cJSON_CreateRaw(text.c_str()); }

std::string easyCodeWarning(const std::string& code) {
    if (!latchkey_util::isEasyCode(code)) {
        return {};
    }
    return "this code is easy to guess; use 7 to 9 digits that are not a run or one repeated digit, since the lock "
           "opens whenever the code appears among the digits typed";
}

void addWarnings(cJSON* result, std::initializer_list<std::string_view> warnings) {
    std::string joined;
    for (const std::string_view warning : warnings) {
        if (warning.empty()) {
            continue;
        }
        if (!joined.empty()) {
            joined += "; ";
        }
        joined.append(warning.data(), warning.size());
    }
    if (!joined.empty()) {
        cJSON_AddStringToObject(result, "warning", joined.c_str());
    }
}

}
