// SPDX-License-Identifier: GPL-3.0-or-later
#include "ota.h"

#include <cinttypes>
#include <cstdint>
#include <cstdlib>
#include <optional>
#include <string>

#include "cJSON.h"
#include "esp_app_desc.h"
#include "esp_log.h"
#include "esp_ota_ops.h"
#include "esp_partition.h"
#include "esp_system.h"
#include "esp_timer.h"
#include "freertos/FreeRTOS.h"
#include "freertos/task.h"
#include "sdkconfig.h"

#include "console.h"
#include "http.h"
#include "latchkey_util/app_image.h"
#include "latchkey_util/first_boot.h"
#include "rpc.h"
#include "store.h"
#include "wifi.h"

namespace ota {

namespace {

constexpr const char* TAG = "ota";
constexpr uint32_t kCheckStack = 4096;
constexpr UBaseType_t kCheckPriority = 1;
constexpr TickType_t kCheckPeriod = pdMS_TO_TICKS(1000);
constexpr uint16_t kChipId = CONFIG_IDF_FIRMWARE_CHIP_ID;

int64_t nowUs() { return esp_timer_get_time(); }

bool pendingVerify() {
    esp_ota_img_states_t state;
    return esp_ota_get_state_partition(esp_ota_get_running_partition(), &state) == ESP_OK &&
           state == ESP_OTA_IMG_PENDING_VERIFY;
}

void restartNow(void*) {
    console::flush();
    esp_restart();
}

latchkey_util::FirstBootSignals readSignals() {
    latchkey_util::FirstBootSignals signals;
    store::Usage usage;
    size_t locks = 0;
    signals.storageReadable = store::usage(usage) == ESP_OK && store::locks::count(locks) == ESP_OK;
    signals.consoleRunning = xTaskGetHandle("console") != nullptr;
    const wifi::Status status = wifi::status();
    signals.wifiConfigured = status.configured;
    signals.wifiStarted = wifi::running();
    signals.wifiConnected = status.connected;
    signals.webServing = http::serving();
    return signals;
}

void watchFirstBoot(void*) {
    while (true) {
        vTaskDelay(kCheckPeriod);
        const latchkey_util::FirstBootSignals signals = readSignals();
        const auto uptime = static_cast<uint32_t>(nowUs() / 1000000);
        const latchkey_util::FirstBootVerdict verdict = latchkey_util::judgeFirstBoot(signals, uptime);
        if (verdict == latchkey_util::FirstBootVerdict::Healthy) {
            const esp_err_t error = esp_ota_mark_app_valid_cancel_rollback();
            if (error == ESP_OK) {
                ESP_LOGI(TAG, "firmware %s passed its first-boot check and is kept", esp_app_get_description()->version);
            } else {
                ESP_LOGE(TAG, "cannot keep the firmware: %s", esp_err_to_name(error));
            }
            break;
        }
        if (verdict == latchkey_util::FirstBootVerdict::Unhealthy) {
            ESP_LOGE(TAG, "the new firmware failed its first-boot check (%s); restarting into the previous one",
                     latchkey_util::firstBootProblem(signals));
            restartNow(nullptr);
        }
    }
    vTaskDelete(nullptr);
}

const char* stateName(esp_ota_img_states_t state) {
    switch (state) {
        case ESP_OTA_IMG_NEW:
            return "new";
        case ESP_OTA_IMG_PENDING_VERIFY:
            return "pending_verify";
        case ESP_OTA_IMG_VALID:
            return "valid";
        case ESP_OTA_IMG_INVALID:
            return "invalid";
        case ESP_OTA_IMG_ABORTED:
            return "aborted";
        case ESP_OTA_IMG_UNDEFINED:
            return "undefined";
    }
    return "unknown";
}

void addText(cJSON* object, const char* key, const std::optional<std::string>& value) {
    if (value.has_value()) {
        cJSON_AddStringToObject(object, key, value->c_str());
    } else {
        cJSON_AddNullToObject(object, key);
    }
}

cJSON* slotJson(const esp_partition_t* partition) {
    cJSON* slot = cJSON_CreateObject();
    cJSON_AddStringToObject(slot, "slot", partition->label);
    uint8_t bytes[latchkey_util::kAppImageHeadBytes];
    latchkey_util::AppImageHead head;
    const bool image = esp_partition_read(partition, 0, bytes, sizeof(bytes)) == ESP_OK &&
                       latchkey_util::checkAppImageHead(bytes, sizeof(bytes), kChipId,
                                                        esp_app_get_description()->project_name,
                                                        head) != latchkey_util::ImageHeadVerdict::NotAnImage;
    addText(slot, "version", image ? std::optional<std::string>(head.version) : std::nullopt);
    addText(slot, "elfSha256", image ? std::optional<std::string>(head.elfSha256) : std::nullopt);
    esp_ota_img_states_t state;
    addText(slot, "state",
            esp_ota_get_state_partition(partition, &state) == ESP_OK ? std::optional<std::string>(stateName(state))
                                                                     : std::nullopt);
    return slot;
}

rpc::Reply status(const cJSON*, const rpc::Context&) {
    const esp_partition_t* running = esp_ota_get_running_partition();
    const esp_partition_t* other = esp_ota_get_next_update_partition(nullptr);
    const esp_partition_t* boot = esp_ota_get_boot_partition();
    if (running == nullptr || other == nullptr || boot == nullptr) {
        return rpc::fail("internal", "cannot read the app slots");
    }
    cJSON* result = cJSON_CreateObject();
    cJSON_AddItemToObject(result, "running", slotJson(running));
    cJSON_AddItemToObject(result, "other", slotJson(other));
    cJSON_AddStringToObject(result, "boot", boot->label);
    return rpc::ok(result);
}

}

void start() {
    rpc::registerMethod("system.ota.status", {.serialOnly = true, .audited = false}, status);
    const esp_partition_t* running = esp_ota_get_running_partition();
    if (!pendingVerify()) {
        ESP_LOGI(TAG, "running %s from %s", esp_app_get_description()->version, running->label);
        return;
    }
    ESP_LOGW(TAG, "first boot of %s from %s: it is kept once it has run %" PRIu32 " s with storage, console and Wi-Fi",
             esp_app_get_description()->version, running->label, latchkey_util::kFirstBootSettleSeconds);
    if (xTaskCreate(watchFirstBoot, "ota_check", kCheckStack, nullptr, kCheckPriority, nullptr) != pdPASS) {
        ESP_LOGE(TAG, "cannot start the first-boot check");
        abort();
    }
}

}
