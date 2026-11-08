// SPDX-License-Identifier: GPL-3.0-or-later
#pragma once

#include <cstdint>
#include <functional>

namespace board {

const char* name();

int buttonGpio();

void init();

bool buttonPressed();

uint32_t buttonPresses();

bool waitForPress(uint32_t timeoutMs, const std::function<bool()>& keepWaiting);

}
