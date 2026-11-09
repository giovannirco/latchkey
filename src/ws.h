// SPDX-License-Identifier: GPL-3.0-or-later
#pragma once

#include <cstddef>
#include <cstdint>
#include <optional>

#include "esp_err.h"
#include "esp_http_server.h"
#include "latchkey_util/rpc_text.h"

namespace ws {

void init();

void attach(httpd_handle_t server, size_t maxSockets);

esp_err_t admit(httpd_req_t* req);

esp_err_t receive(httpd_req_t* req);

void deliver(std::optional<uint32_t> session, latchkey_util::RpcText line);

void service();

}
