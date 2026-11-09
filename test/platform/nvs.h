// SPDX-License-Identifier: GPL-3.0-or-later
#pragma once

#include <cstddef>
#include <cstdint>

#include "esp_err.h"

using nvs_handle_t = uint32_t;
enum nvs_open_mode_t { NVS_READONLY, NVS_READWRITE };
enum nvs_type_t { NVS_TYPE_U32 = 0x04, NVS_TYPE_BLOB = 0x42, NVS_TYPE_ANY = 0xFF };
inline constexpr esp_err_t ESP_ERR_NVS_NOT_FOUND = 0x1102;
inline constexpr esp_err_t ESP_ERR_NVS_TYPE_MISMATCH = 0x1103;
inline constexpr esp_err_t ESP_ERR_NVS_INVALID_LENGTH = 0x110c;

struct nvs_iterator;
using nvs_iterator_t = nvs_iterator*;
struct nvs_entry_info_t { char namespace_name[16]; char key[16]; nvs_type_t type; };

esp_err_t nvs_open(const char* name, nvs_open_mode_t mode, nvs_handle_t* out);
void nvs_close(nvs_handle_t handle);
esp_err_t nvs_find_key(nvs_handle_t handle, const char* key, nvs_type_t* type);
esp_err_t nvs_get_blob(nvs_handle_t handle, const char* key, void* out, size_t* length);
esp_err_t nvs_get_u32(nvs_handle_t handle, const char* key, uint32_t* out);
esp_err_t nvs_set_blob(nvs_handle_t handle, const char* key, const void* value, size_t length);
esp_err_t nvs_erase_key(nvs_handle_t handle, const char* key);
esp_err_t nvs_commit(nvs_handle_t handle);
esp_err_t nvs_entry_find_in_handle(nvs_handle_t handle, nvs_type_t type, nvs_iterator_t* out);
esp_err_t nvs_entry_next(nvs_iterator_t* entry);
esp_err_t nvs_entry_info(nvs_iterator_t entry, nvs_entry_info_t* out);
esp_err_t nvs_erase_all(nvs_handle_t handle);
void nvs_release_iterator(nvs_iterator_t entry);
