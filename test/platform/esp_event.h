// SPDX-License-Identifier: GPL-3.0-or-later
#pragma once

#include <cstdint>
#include "esp_err.h"

using esp_event_base_t = const char*;
inline constexpr esp_event_base_t IP_EVENT = "ip";
inline constexpr int32_t IP_EVENT_STA_GOT_IP = 1;
esp_err_t esp_event_handler_register(esp_event_base_t, int32_t, void (*)(void*, esp_event_base_t, int32_t, void*), void*);
