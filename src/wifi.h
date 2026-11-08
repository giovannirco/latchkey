// SPDX-License-Identifier: GPL-3.0-or-later
#pragma once

#include <cstdint>
#include <string>

#include "esp_err.h"
#include "store.h"

namespace wifi {

struct Status {
    bool configured = false;
    bool connected = false;
    std::string ssid;
    uint32_t ip = 0;
    int rssi = 0;
};

void start(const store::cfg::Wifi* config);

esp_err_t apply(const store::cfg::Wifi& config);

Status status();

uint32_t address();

}
