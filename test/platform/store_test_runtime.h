// SPDX-License-Identifier: GPL-3.0-or-later
#pragma once

#define LATCHKEY_NATIVE_REAL_STORE
#include "key_store_test_runtime.h"
#include "../../src/store.cpp"

esp_err_t nvs_flash_init() { return ESP_OK; }

esp_err_t nvs_get_stats(const char*, nvs_stats_t* stats) {
    if (!canRead()) return ESP_FAIL;
    *stats = {0, s_available, s_available, s_namespaces.size()};
    return ESP_OK;
}

esp_err_t nvs_get_str(nvs_handle_t handle, const char* key, char* out, size_t* length) {
    return nvs_get_blob(handle, key, out, length);
}

esp_err_t nvs_set_str(nvs_handle_t handle, const char* key, const char* text) {
    return nvs_set_blob(handle, key, text, std::strlen(text) + 1);
}

esp_err_t nvs_get_u64(nvs_handle_t handle, const char* key, uint64_t* out) {
    size_t length = sizeof(*out);
    return nvs_get_blob(handle, key, out, &length);
}

esp_err_t nvs_set_u64(nvs_handle_t handle, const char* key, uint64_t value) {
    return nvs_set_blob(handle, key, &value, sizeof(value));
}

esp_err_t nvs_set_u32(nvs_handle_t handle, const char* key, uint32_t value) {
    return mutate([&] {
        const auto* bytes = reinterpret_cast<const uint8_t*>(&value);
        s_namespaces.at(s_handles.at(handle))[key] = {NVS_TYPE_U32, {bytes, bytes + sizeof(value)}};
    });
}

esp_err_t nvs_entry_find(const char*, const char* name, nvs_type_t type, nvs_iterator_t* out) {
    nvs_handle_t handle;
    const auto error = nvs_open(name, NVS_READONLY, &handle);
    if (error != ESP_OK) return error;
    const auto found = nvs_entry_find_in_handle(handle, type, out);
    nvs_close(handle);
    return found;
}
