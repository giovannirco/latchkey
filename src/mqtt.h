// SPDX-License-Identifier: GPL-3.0-or-later
#pragma once

#include <cstdint>

#include "store.h"

namespace mqtt {

void start();

bool apply(const store::cfg::Mqtt& settings);

uint32_t stackFree();

}
