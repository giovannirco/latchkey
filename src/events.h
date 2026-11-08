// SPDX-License-Identifier: GPL-3.0-or-later
#pragma once

#include <functional>
#include <string>

#include "cJSON.h"

namespace events {

using Sink = std::function<void(const std::string& line)>;

void addSink(Sink sink);

void publish(const char* name, cJSON* data);

}
