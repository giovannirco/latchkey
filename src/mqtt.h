// SPDX-License-Identifier: GPL-3.0-or-later
#pragma once

#include <cstdint>
#include <string>

#include "store.h"

namespace mqtt {

struct Status {
    bool connected = false;
    std::string problem;
};

void start();

bool apply(const store::cfg::Mqtt& settings);

bool forgetAll();

Status status();

uint32_t stackFree();

uint32_t clientStackFree();

}
