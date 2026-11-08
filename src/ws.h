// SPDX-License-Identifier: GPL-3.0-or-later
#pragma once

#include <cstddef>
#include <cstdint>
#include <optional>
#include <string>

#include "esp_err.h"
#include "esp_http_server.h"

namespace ws {

void init();

void attach(httpd_handle_t server, size_t maxSockets);

esp_err_t admit(httpd_req_t* req);

esp_err_t receive(httpd_req_t* req);

void deliver(std::optional<uint32_t> session, std::string line);

void service();

}
