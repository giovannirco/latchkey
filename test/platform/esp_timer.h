// SPDX-License-Identifier: GPL-3.0-or-later
#pragma once

#include <cstdint>
#include "esp_err.h"

inline constexpr int ESP_TIMER_TASK = 0;
using esp_timer_handle_t = void*;
struct esp_timer_create_args_t {
    void (*callback)(void*);
    void* arg;
    int dispatch_method;
    const char* name;
    bool skip_unhandled_events;
};
int64_t esp_timer_get_time();
esp_err_t esp_timer_create(const esp_timer_create_args_t*, esp_timer_handle_t*);
esp_err_t esp_timer_start_periodic(esp_timer_handle_t, uint64_t);
esp_err_t esp_timer_start_once(esp_timer_handle_t, uint64_t);
esp_err_t esp_timer_stop(esp_timer_handle_t);
