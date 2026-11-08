// SPDX-License-Identifier: GPL-3.0-or-later
#pragma once

#include <string_view>

namespace console {

void begin();

void start();

void writeLine(std::string_view json);

void flush();

}
