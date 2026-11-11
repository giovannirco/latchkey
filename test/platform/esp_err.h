// SPDX-License-Identifier: GPL-3.0-or-later
#pragma once

#include <cstdlib>

using esp_err_t = int;
inline constexpr esp_err_t ESP_OK = 0;
inline constexpr esp_err_t ESP_FAIL = -1;
inline constexpr esp_err_t ESP_ERR_NO_MEM = 0x101;
inline constexpr esp_err_t ESP_ERR_INVALID_ARG = 0x102;
inline constexpr esp_err_t ESP_ERR_INVALID_STATE = 0x103;
inline constexpr esp_err_t ESP_ERR_INVALID_SIZE = 0x104;
inline constexpr esp_err_t ESP_ERR_INVALID_VERSION = 0x10A;
inline constexpr esp_err_t ESP_ERR_NOT_FOUND = 0x105;
inline constexpr esp_err_t ESP_ERR_INVALID_CRC = 0x109;
inline const char* esp_err_to_name(esp_err_t) { return "fixture-error"; }
#define ESP_ERROR_CHECK(value) do { if ((value) != ESP_OK) std::abort(); } while (false)
