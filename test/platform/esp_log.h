// SPDX-License-Identifier: GPL-3.0-or-later
#pragma once

enum esp_log_level_t { ESP_LOG_NONE, ESP_LOG_ERROR, ESP_LOG_WARN, ESP_LOG_INFO, ESP_LOG_DEBUG, ESP_LOG_VERBOSE };
void esp_log_level_set(const char*, esp_log_level_t);

#define ESP_LOGE(...) ((void)0)
#define ESP_LOGW(...) ((void)0)
#define ESP_LOGI(...) ((void)0)
#define ESP_LOGD(...) ((void)0)
