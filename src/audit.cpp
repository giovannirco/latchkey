// SPDX-License-Identifier: GPL-3.0-or-later
#include "audit.h"

#include <algorithm>
#include <cstring>
#include <mutex>

#include "esp_log.h"

#include "events.h"
#include "store.h"

namespace audit {

namespace {

constexpr const char* TAG = "audit";

std::mutex s_mutex;
uint32_t s_nextSeq = 1;

template <size_t N>
void copyField(char (&field)[N], const std::string& value) {
    const size_t length = std::min(value.size(), N - 1);
    std::memcpy(field, value.data(), length);
    field[length] = '\0';
}

template <size_t N>
std::string readField(const char (&field)[N]) {
    return std::string(field, strnlen(field, N));
}

uint32_t oldestSeq(uint32_t next) { return next > store::audit::kCapacity ? next - store::audit::kCapacity : 1; }

StoredEntry fromRecord(const store::audit::Record& record) {
    StoredEntry stored;
    stored.seq = record.seq;
    stored.entry.utc = record.utc;
    stored.entry.origin = record.origin == 0 ? rpc::Transport::Serial : rpc::Transport::Web;
    stored.entry.method = readField(record.method);
    stored.entry.target = readField(record.target);
    stored.entry.result = readField(record.result);
    return stored;
}

}

void init() {
    std::lock_guard<std::mutex> lock(s_mutex);
    s_nextSeq = store::audit::loadNextSeq();
}

void append(const Entry& entry) {
    StoredEntry stored{0, entry};
    {
        std::lock_guard<std::mutex> lock(s_mutex);
        store::audit::Record record{};
        record.seq = s_nextSeq;
        record.utc = entry.utc;
        record.origin = entry.origin == rpc::Transport::Serial ? 0 : 1;
        copyField(record.method, entry.method);
        copyField(record.target, entry.target);
        copyField(record.result, entry.result);
        const esp_err_t error = store::audit::saveRecord(record);
        if (error != ESP_OK) {
            ESP_LOGE(TAG, "cannot store entry %u: %s", static_cast<unsigned>(record.seq), esp_err_to_name(error));
            return;
        }
        ++s_nextSeq;
        stored = fromRecord(record);
    }
    events::publish("audit.appended", toJson(stored));
}

Page list(uint32_t before, size_t limit) {
    std::lock_guard<std::mutex> lock(s_mutex);
    Page page;
    const uint32_t oldest = oldestSeq(s_nextSeq);
    uint32_t seq = std::min(before, s_nextSeq);
    while (seq > oldest && page.entries.size() < limit) {
        --seq;
        store::audit::Record record{};
        if (store::audit::loadRecord(seq, record)) {
            page.entries.push_back(fromRecord(record));
        }
    }
    page.more = seq > oldest;
    return page;
}

esp_err_t clear() {
    std::lock_guard<std::mutex> lock(s_mutex);
    const esp_err_t error = store::audit::erase();
    s_nextSeq = store::audit::loadNextSeq();
    return error;
}

cJSON* toJson(const StoredEntry& stored) {
    cJSON* json = cJSON_CreateObject();
    cJSON_AddNumberToObject(json, "seq", stored.seq);
    if (stored.entry.utc == 0) {
        cJSON_AddNullToObject(json, "utc");
    } else {
        cJSON_AddNumberToObject(json, "utc", stored.entry.utc);
    }
    cJSON_AddStringToObject(json, "origin", rpc::toString(stored.entry.origin));
    cJSON_AddStringToObject(json, "method", stored.entry.method.c_str());
    cJSON_AddStringToObject(json, "target", stored.entry.target.c_str());
    cJSON_AddStringToObject(json, "result", stored.entry.result.c_str());
    return json;
}

}
