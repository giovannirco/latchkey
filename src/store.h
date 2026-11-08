// SPDX-License-Identifier: GPL-3.0-or-later
#pragma once

#include <array>
#include <cstddef>
#include <cstdint>
#include <string>

#include "esp_err.h"

namespace store {

struct Usage {
    size_t usedEntries = 0;
    size_t availableEntries = 0;
    size_t totalEntries = 0;
};

void init();

Usage usage();

namespace cfg {

struct Wifi {
    std::string ssid;
    std::string password;
    uint32_t ip = 0;
    uint32_t gateway = 0;
    uint32_t netmask = 0;
    uint32_t dns = 0;
};

bool loadWifi(Wifi& out);

esp_err_t saveWifi(const Wifi& wifi);

esp_err_t erase();

}

namespace auth {

struct Owner {
    std::array<uint8_t, 16> salt{};
    uint32_t iterations = 0;
    std::array<uint8_t, 32> hash{};
    std::array<uint8_t, 20> totpSecret{};
};

bool claimed();

bool loadOwner(Owner& out);

esp_err_t saveOwner(const Owner& owner);

esp_err_t erase();

}

namespace audit {

inline constexpr uint32_t kCapacity = 200;

struct Record {
    uint32_t seq;
    uint32_t utc;
    uint8_t origin;
    char method[32];
    char target[24];
    char result[20];
};

uint32_t loadNextSeq();

esp_err_t saveRecord(const Record& record);

bool loadRecord(uint32_t seq, Record& out);

esp_err_t erase();

}

}
