// SPDX-License-Identifier: GPL-3.0-or-later
#pragma once

#include <cstdint>

#include "esp_err.h"
#include "store.h"

namespace syslog_client {

struct Status {
    bool connected = false;
    uint32_t sent = 0;
    uint32_t dropped = 0;
    uint32_t errors = 0;
};

void start();

esp_err_t apply(const store::cfg::Syslog& settings);

store::cfg::Syslog settings();

Status status();

void wake();

uint32_t stackFree();

}
