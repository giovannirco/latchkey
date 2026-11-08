// SPDX-License-Identifier: GPL-3.0-or-later
#pragma once

#include "esp_err.h"
#include "esp_http_server.h"

namespace ota {

void start();

esp_err_t accept(httpd_req_t* req);

}
