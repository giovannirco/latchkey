// SPDX-License-Identifier: GPL-3.0-or-later
#pragma once

#include <cstdint>

namespace http {

void start();

uint32_t serverStackFree();

uint32_t workerStackFree();

}
