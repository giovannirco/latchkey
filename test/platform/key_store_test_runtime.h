// SPDX-License-Identifier: GPL-3.0-or-later
#pragma once

#include <unity.h>
#include <cstring>
#include <functional>
#include <map>
#include <string>
#include <vector>

#include "nvs.h"
#include "../../src/key_store.cpp"

struct StoredValue {
    nvs_type_t type = NVS_TYPE_BLOB;
    std::vector<uint8_t> bytes;
    bool operator==(const StoredValue&) const = default;
};

using Entries = std::map<std::string, StoredValue>;
static std::map<std::string, Entries> s_namespaces;
static std::map<nvs_handle_t, std::string> s_handles;
static size_t s_reads;
static size_t s_writes;
static size_t s_failRead;
static size_t s_failWrite;
static size_t s_preflightReads;
static bool s_failAfter;
static size_t s_available;
static uint32_t s_reserveSequence;
static std::function<void()> s_afterMutation;
static constexpr std::string_view kMac = "00:00:5E:00:53:01";
static constexpr const char* kKey = "00005E005301";
static constexpr const char* kOtherKey = "00005E005309";

void resetNvsFixture() {
    s_namespaces.clear();
    s_handles.clear();
    s_reads = s_writes = s_failRead = s_failWrite = s_preflightReads = 0;
    s_failAfter = false;
    s_available = 4096;
    s_reserveSequence = 0;
    s_afterMutation = {};
}

void clearNvsFixture() { TEST_ASSERT_TRUE(s_handles.empty()); }

static bool canRead() { return ++s_reads != s_failRead; }

template <typename Mutation>
static esp_err_t mutate(Mutation mutation) {
    if (s_writes == 0) s_preflightReads = s_reads;
    ++s_writes;
    if (s_writes == s_failWrite && !s_failAfter) return ESP_FAIL;
    mutation();
    if (s_afterMutation) s_afterMutation();
    return s_writes == s_failWrite ? ESP_FAIL : ESP_OK;
}

esp_err_t nvs_open(const char* name, nvs_open_mode_t mode, nvs_handle_t* out) {
    if (!canRead()) return ESP_FAIL;
    if (!s_namespaces.contains(name)) {
        if (mode == NVS_READONLY) return ESP_ERR_NVS_NOT_FOUND;
        const auto error = mutate([&] { s_namespaces.emplace(name, Entries{}); });
        if (error != ESP_OK) return error;
    }
    *out = s_handles.empty() ? 1 : s_handles.rbegin()->first + 1;
    s_handles[*out] = name;
    return ESP_OK;
}

void nvs_close(nvs_handle_t handle) { s_handles.erase(handle); }

esp_err_t nvs_find_key(nvs_handle_t handle, const char* key, nvs_type_t* type) {
    if (!canRead()) return ESP_FAIL;
    const auto& entries = s_namespaces.at(s_handles.at(handle));
    if (!entries.contains(key)) return ESP_ERR_NVS_NOT_FOUND;
    *type = entries.at(key).type;
    return ESP_OK;
}

esp_err_t nvs_get_blob(nvs_handle_t handle, const char* key, void* out, size_t* length) {
    if (!canRead()) return ESP_FAIL;
    const auto& entries = s_namespaces.at(s_handles.at(handle));
    if (!entries.contains(key)) return ESP_ERR_NVS_NOT_FOUND;
    const auto& value = entries.at(key);
    if (value.type != NVS_TYPE_BLOB) return ESP_ERR_NVS_TYPE_MISMATCH;
    if (out != nullptr && *length < value.bytes.size()) return ESP_ERR_NVS_INVALID_LENGTH;
    if (out != nullptr) std::memcpy(out, value.bytes.data(), value.bytes.size());
    *length = value.bytes.size();
    return ESP_OK;
}

esp_err_t nvs_get_u32(nvs_handle_t handle, const char* key, uint32_t* out) {
    if (!canRead()) return ESP_FAIL;
    const auto& entries = s_namespaces.at(s_handles.at(handle));
    if (!entries.contains(key)) return ESP_ERR_NVS_NOT_FOUND;
    const auto& value = entries.at(key);
    if (value.type != NVS_TYPE_U32 || value.bytes.size() != 4) return ESP_ERR_NVS_TYPE_MISMATCH;
    std::memcpy(out, value.bytes.data(), 4);
    return ESP_OK;
}

esp_err_t nvs_set_blob(nvs_handle_t handle, const char* key, const void* value, size_t length) {
    return mutate([&] {
        const auto* bytes = static_cast<const uint8_t*>(value);
        s_namespaces.at(s_handles.at(handle))[key] = {NVS_TYPE_BLOB, {bytes, bytes + length}};
    });
}

esp_err_t nvs_erase_key(nvs_handle_t handle, const char* key) {
    auto& entries = s_namespaces.at(s_handles.at(handle));
    if (!entries.contains(key)) return ESP_ERR_NVS_NOT_FOUND;
    return mutate([&] { entries.erase(key); });
}

esp_err_t nvs_commit(nvs_handle_t) { return mutate([] {}); }

struct nvs_iterator { Entries::const_iterator current; Entries::const_iterator end; nvs_type_t type; };

esp_err_t nvs_entry_find_in_handle(nvs_handle_t handle, nvs_type_t type, nvs_iterator_t* out) {
    if (!canRead()) return ESP_FAIL;
    const auto& entries = s_namespaces.at(s_handles.at(handle));
    if (entries.empty()) return ESP_ERR_NVS_NOT_FOUND;
    auto current = entries.begin();
    while (current != entries.end() && type != NVS_TYPE_ANY && current->second.type != type) ++current;
    if (current == entries.end()) return ESP_ERR_NVS_NOT_FOUND;
    *out = new nvs_iterator{current, entries.end(), type};
    return ESP_OK;
}

esp_err_t nvs_entry_next(nvs_iterator_t* entry) {
    if (!canRead()) return ESP_FAIL;
    ++(*entry)->current;
    while ((*entry)->current != (*entry)->end && (*entry)->type != NVS_TYPE_ANY &&
           (*entry)->current->second.type != (*entry)->type) ++(*entry)->current;
    if ((*entry)->current != (*entry)->end) return ESP_OK;
    delete *entry;
    *entry = nullptr;
    return ESP_ERR_NVS_NOT_FOUND;
}

void nvs_release_iterator(nvs_iterator_t entry) { delete entry; }

esp_err_t nvs_entry_info(nvs_iterator_t entry, nvs_entry_info_t* out) {
    std::memset(out, 0, sizeof(*out));
    std::strcpy(out->key, entry->current->first.c_str());
    out->type = entry->current->second.type;
    return ESP_OK;
}

esp_err_t nvs_erase_all(nvs_handle_t handle) {
    return mutate([&] { s_namespaces.at(s_handles.at(handle)).clear(); });
}

#ifndef LATCHKEY_NATIVE_REAL_STORE
namespace store {

esp_err_t usage(Usage& out) {
    if (!canRead()) return ESP_FAIL;
    out.availableEntries = s_available;
    return ESP_OK;
}

size_t reservedEntries(uint32_t nextSequence) {
    s_reserveSequence = nextSequence;
    return 100;
}

}
#endif
