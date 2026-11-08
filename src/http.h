// SPDX-License-Identifier: GPL-3.0-or-later
#pragma once

#include <cstdint>
#include <string>

#include "esp_err.h"
#include "esp_http_server.h"

namespace http {

void start();

bool serving();

bool fromBoardAddress(httpd_req_t* req);

std::string sessionToken(httpd_req_t* req);

esp_err_t sendJson(httpd_req_t* req, const char* status, const std::string& json);

esp_err_t refuse(httpd_req_t* req, const char* status, const char* code, const char* message);

uint32_t serverStackFree();

uint32_t workerStackFree();

}
