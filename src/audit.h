// SPDX-License-Identifier: GPL-3.0-or-later
#pragma once

#include <cstddef>
#include <cstdint>
#include <string>
#include <vector>

#include "esp_err.h"
#include "rpc.h"

namespace audit {

struct Entry {
    uint32_t utc = 0;
    rpc::Transport origin = rpc::Transport::Serial;
    std::string method;
    std::string target;
    std::string result;
};

struct StoredEntry {
    uint32_t seq = 0;
    Entry entry;
};

struct Page {
    std::vector<StoredEntry> entries;
    bool more = false;
};

inline constexpr size_t kMaxPage = 50;

void init();

void append(const Entry& entry);

Page list(uint32_t before, size_t limit);

esp_err_t clear();

cJSON* toJson(const StoredEntry& stored);

}
