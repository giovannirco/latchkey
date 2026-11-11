// SPDX-License-Identifier: GPL-3.0-or-later
#pragma once

#include <cstdint>
#include <optional>

#include "esp_http_server.h"

namespace http {

void start();

bool fromBoardAddress(httpd_req_t* req);

std::optional<uint32_t> serverStackFree();

uint32_t workerStackFree();

}
