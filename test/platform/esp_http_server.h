// SPDX-License-Identifier: GPL-3.0-or-later
#pragma once

#include <cstddef>
#include <cstdint>
#include <sys/types.h>

#include "esp_err.h"

using httpd_handle_t = void*;
struct httpd_req_t {
    httpd_handle_t handle = nullptr;
    size_t content_len = 0;
    const char* uri = "/api/rpc";
    void* sess_ctx = nullptr;
    void (*free_ctx)(void*) = nullptr;
};
enum httpd_err_code_t {
    HTTPD_400_BAD_REQUEST, HTTPD_404_NOT_FOUND, HTTPD_405_METHOD_NOT_ALLOWED, HTTPD_408_REQ_TIMEOUT,
    HTTPD_411_LENGTH_REQUIRED, HTTPD_414_URI_TOO_LONG, HTTPD_431_REQ_HDR_FIELDS_TOO_LARGE,
    HTTPD_500_INTERNAL_SERVER_ERROR, HTTPD_501_METHOD_NOT_IMPLEMENTED, HTTPD_505_VERSION_NOT_SUPPORTED
};
inline constexpr const char* HTTPD_200 = "200 OK";
inline constexpr int HTTPD_SOCK_ERR_TIMEOUT = -3;
inline constexpr int ESP_HTTPD_DEF_CTRL_PORT = 32768;
enum httpd_method_t { HTTP_GET, HTTP_POST };
enum httpd_ws_client_info_t { HTTPD_WS_CLIENT_INVALID, HTTPD_WS_CLIENT_HTTP, HTTPD_WS_CLIENT_WEBSOCKET };
enum httpd_ws_type_t { HTTPD_WS_TYPE_TEXT };
struct httpd_ws_frame_t {
    bool final = false;
    httpd_ws_type_t type = HTTPD_WS_TYPE_TEXT;
    uint8_t* payload = nullptr;
    size_t len = 0;
};
struct httpd_uri_t {
    const char* uri = nullptr;
    httpd_method_t method = HTTP_GET;
    esp_err_t (*handler)(httpd_req_t*) = nullptr;
    bool is_websocket = false;
    esp_err_t (*ws_pre_handshake_cb)(httpd_req_t*) = nullptr;
};
struct httpd_config_t {
    int server_port = 0, ctrl_port = 0, recv_wait_timeout = 0, send_wait_timeout = 0;
    int keep_alive_idle = 0, keep_alive_interval = 0, keep_alive_count = 0;
    size_t stack_size = 0, max_open_sockets = 0, max_uri_handlers = 0, max_resp_headers = 0;
    bool lru_purge_enable = false, keep_alive_enable = false;
    bool (*uri_match_fn)(const char*, const char*, size_t) = nullptr;
};
inline httpd_config_t HTTPD_DEFAULT_CONFIG() { return {}; }
bool httpd_uri_match_wildcard(const char*, const char*, size_t);
esp_err_t httpd_resp_set_hdr(httpd_req_t*, const char*, const char*);
esp_err_t httpd_resp_set_status(httpd_req_t*, const char*);
esp_err_t httpd_resp_set_type(httpd_req_t*, const char*);
esp_err_t httpd_resp_send(httpd_req_t*, const char*, ssize_t);
size_t httpd_req_get_hdr_value_len(httpd_req_t*, const char*);
esp_err_t httpd_req_get_hdr_value_str(httpd_req_t*, const char*, char*, size_t);
esp_err_t httpd_req_get_cookie_val(httpd_req_t*, const char*, char*, size_t*);
int httpd_req_recv(httpd_req_t*, char*, size_t);
int httpd_req_to_sockfd(httpd_req_t*);
esp_err_t httpd_req_async_handler_begin(httpd_req_t*, httpd_req_t**);
esp_err_t httpd_req_async_handler_complete(httpd_req_t*);
esp_err_t httpd_sess_trigger_close(httpd_handle_t, int);
esp_err_t httpd_sess_update_lru_counter(httpd_handle_t, int);
void* httpd_sess_get_ctx(httpd_handle_t, int);
esp_err_t httpd_register_err_handler(httpd_handle_t, httpd_err_code_t, esp_err_t (*)(httpd_req_t*, httpd_err_code_t));
esp_err_t httpd_register_uri_handler(httpd_handle_t, const httpd_uri_t*);
esp_err_t httpd_start(httpd_handle_t*, const httpd_config_t*);
esp_err_t httpd_get_client_list(httpd_handle_t, size_t*, int*);
httpd_ws_client_info_t httpd_ws_get_fd_info(httpd_handle_t, int);
esp_err_t httpd_ws_recv_frame(httpd_req_t*, httpd_ws_frame_t*, size_t);
esp_err_t httpd_ws_send_frame_async(httpd_handle_t, int, httpd_ws_frame_t*);
esp_err_t httpd_queue_work(httpd_handle_t, void (*)(void*), void*);
