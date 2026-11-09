// SPDX-License-Identifier: GPL-3.0-or-later
#pragma once

#include "esp_http_server.h"

inline constexpr int HTTPD_SSL_TRANSPORT_SECURE = 0;
struct httpd_ssl_config_t {
    httpd_config_t httpd;
    int transport_mode = 0, port_secure = 0, port_insecure = 0;
    const uint8_t* servercert = nullptr;
    const uint8_t* prvtkey_pem = nullptr;
    size_t servercert_len = 0, prvtkey_len = 0;
    bool session_tickets = false;
    int tls_handshake_timeout_ms = 0;
};
esp_err_t httpd_ssl_start(httpd_handle_t*, const httpd_ssl_config_t*);
