// SPDX-License-Identifier: GPL-3.0-or-later
#include "board.h"

#include <atomic>

#include "driver/gpio.h"
#include "esp_timer.h"
#include "freertos/FreeRTOS.h"
#include "freertos/task.h"

#include "latchkey_util/debounce.h"

#ifndef LATCHKEY_BOARD
#error "LATCHKEY_BOARD must be set by the PlatformIO environment"
#endif

#ifndef LATCHKEY_BUTTON_GPIO
#error "LATCHKEY_BUTTON_GPIO must be set by the PlatformIO environment"
#endif

namespace board {

namespace {

constexpr uint64_t kSamplePeriodUs = 10 * 1000;
constexpr TickType_t kPressPoll = pdMS_TO_TICKS(50);
constexpr uint8_t kStableSamples = 3;
constexpr gpio_num_t kButton = static_cast<gpio_num_t>(LATCHKEY_BUTTON_GPIO);

latchkey_util::Debouncer s_debouncer(kStableSamples);
std::atomic<bool> s_pressed{false};
std::atomic<uint32_t> s_presses{0};

void sampleButton(void*) {
    const bool active = gpio_get_level(kButton) == 0;
    if (s_debouncer.update(active)) {
        s_presses.fetch_add(1);
    }
    s_pressed = s_debouncer.pressed();
}

}

const char* name() { return LATCHKEY_BOARD; }

int buttonGpio() { return LATCHKEY_BUTTON_GPIO; }

void init() {
    const gpio_config_t button = {
        .pin_bit_mask = 1ULL << LATCHKEY_BUTTON_GPIO,
        .mode = GPIO_MODE_INPUT,
        .pull_up_en = GPIO_PULLUP_ENABLE,
        .pull_down_en = GPIO_PULLDOWN_DISABLE,
        .intr_type = GPIO_INTR_DISABLE,
    };
    ESP_ERROR_CHECK(gpio_config(&button));
    const esp_timer_create_args_t sampler = {
        .callback = sampleButton,
        .arg = nullptr,
        .dispatch_method = ESP_TIMER_TASK,
        .name = "button",
        .skip_unhandled_events = true,
    };
    esp_timer_handle_t timer = nullptr;
    ESP_ERROR_CHECK(esp_timer_create(&sampler, &timer));
    ESP_ERROR_CHECK(esp_timer_start_periodic(timer, kSamplePeriodUs));
}

bool buttonPressed() { return s_pressed; }

uint32_t buttonPresses() { return s_presses; }

bool waitForPress(uint32_t timeoutMs) {
    const uint32_t before = s_presses;
    const int64_t deadline = esp_timer_get_time() + static_cast<int64_t>(timeoutMs) * 1000;
    while (s_presses == before && esp_timer_get_time() < deadline) {
        vTaskDelay(kPressPoll);
    }
    return s_presses != before;
}

}
