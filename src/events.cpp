// SPDX-License-Identifier: GPL-3.0-or-later
#include "events.h"

#include <mutex>
#include <utility>
#include <vector>

#include "esp_log.h"

namespace events {

namespace {

constexpr const char* TAG = "events";

std::mutex& sinksMutex() {
    static std::mutex mutex;
    return mutex;
}

std::vector<Sink>& sinks() {
    static std::vector<Sink> list;
    return list;
}

}

void addSink(Sink sink) {
    std::lock_guard<std::mutex> lock(sinksMutex());
    sinks().push_back(std::move(sink));
}

void publish(const char* name, cJSON* data) {
    cJSON* event = cJSON_CreateObject();
    cJSON_AddStringToObject(event, "event", name);
    cJSON* payload = data != nullptr ? data : cJSON_CreateObject();
    if (!cJSON_AddItemToObject(event, "data", payload)) {
        cJSON_Delete(payload);
    }
    char* text = cJSON_PrintUnformatted(event);
    cJSON_Delete(event);
    if (text == nullptr) {
        ESP_LOGE(TAG, "out of memory rendering event %s, dropped", name);
        return;
    }
    const std::string line(text);
    cJSON_free(text);
    std::vector<Sink> targets;
    {
        std::lock_guard<std::mutex> lock(sinksMutex());
        targets = sinks();
    }
    for (const Sink& sink : targets) {
        sink(line);
    }
}

}
