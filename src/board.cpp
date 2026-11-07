// SPDX-License-Identifier: GPL-3.0-or-later
#include "board.h"

#ifndef LATCHKEY_BOARD
#error "LATCHKEY_BOARD must be set by the PlatformIO environment"
#endif

#ifndef LATCHKEY_BUTTON_GPIO
#error "LATCHKEY_BUTTON_GPIO must be set by the PlatformIO environment"
#endif

namespace board {

const char* name() { return LATCHKEY_BOARD; }

int buttonGpio() { return LATCHKEY_BUTTON_GPIO; }

}
