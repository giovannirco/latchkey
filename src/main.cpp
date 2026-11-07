// SPDX-License-Identifier: GPL-3.0-or-later
#include <cinttypes>
#include <cstdio>

#include "esp_app_desc.h"
#include "esp_idf_version.h"
#include "esp_log.h"
#include "esp_system.h"
#include "freertos/FreeRTOS.h"
#include "freertos/task.h"
#include "sdkconfig.h"

#include "board.h"

namespace {

constexpr const char* TAG = "latchkey";
constexpr TickType_t HEAP_REPORT_PERIOD = pdMS_TO_TICKS(10000);

}

extern "C" void app_main() {
    std::printf("latchkey %s board=%s chip=%s idf=%s\n", esp_app_get_description()->version, board::name(),
                CONFIG_IDF_TARGET, esp_get_idf_version());
    while (true) {
        ESP_LOGI(TAG, "free heap %" PRIu32 " bytes", esp_get_free_heap_size());
        vTaskDelay(HEAP_REPORT_PERIOD);
    }
}
