// SPDX-License-Identifier: GPL-3.0-or-later
#include "http.h"

#include <atomic>
#include <cstdlib>
#include <cstring>
#include <new>
#include <optional>
#include <string>
#include <string_view>

#include "esp_event.h"
#include "esp_http_server.h"
#include "esp_https_server.h"
#include "esp_log.h"
#include "esp_netif.h"
#include "esp_timer.h"
#include "freertos/FreeRTOS.h"
#include "freertos/queue.h"
#include "freertos/task.h"
#include "lwip/inet.h"
#include "mbedtls/platform_util.h"
#include "sdkconfig.h"

#include "certs.h"
#include "latchkey_util/web.h"
#include "ota.h"
#include "rpc.h"
#include "wifi.h"
#include "ws.h"

extern const uint8_t kPageStart[] asm("_binary_index_html_gz_start");
extern const uint8_t kPageEnd[] asm("_binary_index_html_gz_end");
extern const char kPolicy[] asm("_binary_index_html_gz_csp_txt_start");

namespace http {

namespace {

constexpr const char* TAG = "http";
#if CONFIG_IDF_TARGET_ESP32
constexpr uint16_t kHttpsSockets = 3;
#else
constexpr uint16_t kHttpsSockets = 4;
#endif
constexpr uint32_t kHttpsStack = 6144;
constexpr uint32_t kRedirectStack = 3072;
constexpr uint32_t kWorkerStack = 6144;
constexpr uint32_t kInitStack = 8192;
constexpr UBaseType_t kTaskPriority = 5;
constexpr uint16_t kUriHandlers = 4;
constexpr uint16_t kResponseHeaders = 8;
constexpr uint16_t kSendTimeoutS = 3;
constexpr uint16_t kReceiveTimeoutS = 4;
constexpr uint32_t kHandshakeTimeoutMs = 3500;
constexpr int64_t kBodyDeadlineUs = 10 * 1000 * 1000;
constexpr int kKeepAliveIdleS = 30;
constexpr int kKeepAliveIntervalS = 5;
constexpr int kKeepAliveCount = 3;
constexpr size_t kMaxBody = 8192;
constexpr size_t kHeaderValue = 300;
constexpr size_t kTokenBuffer = 65;

struct Request {
    httpd_req_t* req;
    std::string body;
};

struct ErrorReply {
    httpd_err_code_t error;
    const char* status;
    const char* code;
    const char* message;
    bool keepOpen;
};

constexpr ErrorReply kErrors[] = {
    {HTTPD_400_BAD_REQUEST, "400 Bad Request", "bad_request", "the request could not be read", false},
    {HTTPD_404_NOT_FOUND, "404 Not Found", "not_found", "no such page", true},
    {HTTPD_405_METHOD_NOT_ALLOWED, "405 Method Not Allowed", "method_not_allowed", "method not allowed", true},
    {HTTPD_408_REQ_TIMEOUT, "408 Request Timeout", "timeout", "the request did not arrive in time", false},
    {HTTPD_411_LENGTH_REQUIRED, "411 Length Required", "bad_request", "the request needs a length", false},
    {HTTPD_414_URI_TOO_LONG, "414 URI Too Long", "bad_request", "the address is too long", false},
    {HTTPD_431_REQ_HDR_FIELDS_TOO_LARGE, "431 Request Header Fields Too Large", "bad_request",
     "the request headers are too large", false},
    {HTTPD_500_INTERNAL_SERVER_ERROR, "500 Internal Server Error", "internal", "the board could not answer", false},
    {HTTPD_501_METHOD_NOT_IMPLEMENTED, "501 Not Implemented", "bad_request", "method not supported", false},
    {HTTPD_505_VERSION_NOT_SUPPORTED, "505 HTTP Version Not Supported", "bad_request", "HTTP version not supported",
     false},
};

httpd_handle_t s_https = nullptr;
httpd_handle_t s_redirect = nullptr;
QueueHandle_t s_requests = nullptr;
TaskHandle_t s_worker = nullptr;
std::atomic<TaskHandle_t> s_server{nullptr};
std::atomic<bool> s_started{false};
std::atomic<bool> s_serving{false};

void securityHeaders(httpd_req_t* req) {
    httpd_resp_set_hdr(req, "Content-Security-Policy", kPolicy);
    httpd_resp_set_hdr(req, "X-Frame-Options", "DENY");
    httpd_resp_set_hdr(req, "Referrer-Policy", "no-referrer");
    httpd_resp_set_hdr(req, "X-Content-Type-Options", "nosniff");
    httpd_resp_set_hdr(req, "Cache-Control", "no-store");
}

}

esp_err_t sendJson(httpd_req_t* req, const char* status, const std::string& json) {
    securityHeaders(req);
    httpd_resp_set_status(req, status);
    httpd_resp_set_type(req, "application/json");
    return httpd_resp_send(req, json.data(), static_cast<ssize_t>(json.size()));
}

esp_err_t refuse(httpd_req_t* req, const char* status, const char* code, const char* message) {
    sendJson(req, status, rpc::errorLine(code, message));
    return ESP_FAIL;
}

std::string sessionToken(httpd_req_t* req) {
    char token[kTokenBuffer] = {};
    size_t length = sizeof(token);
    std::string value;
    if (httpd_req_get_cookie_val(req, latchkey_util::kSessionCookieName, token, &length) == ESP_OK) {
        value = token;
    }
    mbedtls_platform_zeroize(token, sizeof(token));
    return value;
}

namespace {

esp_err_t answerError(httpd_req_t* req, httpd_err_code_t error) {
    for (const ErrorReply& reply : kErrors) {
        if (reply.error == error) {
            const esp_err_t sent = sendJson(req, reply.status, rpc::errorLine(reply.code, reply.message));
            return sent == ESP_OK && reply.keepOpen ? ESP_OK : ESP_FAIL;
        }
    }
    return ESP_FAIL;
}

void registerErrors(httpd_handle_t server) {
    for (const ErrorReply& reply : kErrors) {
        httpd_register_err_handler(server, reply.error, answerError);
    }
}

bool header(httpd_req_t* req, const char* name, char (&value)[kHeaderValue]) {
    return httpd_req_get_hdr_value_str(req, name, value, sizeof(value)) == ESP_OK;
}

void noteServerTask() { s_server.store(xTaskGetCurrentTaskHandle()); }

esp_err_t answerEvents(httpd_req_t* req) {
    if (httpd_ws_get_fd_info(req->handle, httpd_req_to_sockfd(req)) == HTTPD_WS_CLIENT_WEBSOCKET) {
        return ws::receive(req);
    }
    httpd_resp_set_hdr(req, "Upgrade", "websocket");
    return sendJson(req, "426 Upgrade Required",
                    rpc::errorLine("upgrade_required", "this address takes WebSocket connections only"));
}

esp_err_t servePage(httpd_req_t* req) {
    noteServerTask();
    const std::string_view uri(req->uri);
    const std::string_view path = uri.substr(0, uri.find('?'));
    if (path != "/" && path != "/index.html") {
        return answerError(req, HTTPD_404_NOT_FOUND);
    }
    securityHeaders(req);
    httpd_resp_set_type(req, "text/html; charset=utf-8");
    httpd_resp_set_hdr(req, "Content-Encoding", "gzip");
    return httpd_resp_send(req, reinterpret_cast<const char*>(kPageStart), kPageEnd - kPageStart);
}

bool readBody(httpd_req_t* req, std::string& body) {
    body.resize(req->content_len);
    const int64_t deadline = esp_timer_get_time() + kBodyDeadlineUs;
    size_t received = 0;
    while (received < body.size()) {
        if (esp_timer_get_time() > deadline) {
            return false;
        }
        const int count = httpd_req_recv(req, body.data() + received, body.size() - received);
        if (count == HTTPD_SOCK_ERR_TIMEOUT) {
            continue;
        }
        if (count <= 0) {
            return false;
        }
        received += static_cast<size_t>(count);
    }
    return true;
}

esp_err_t acceptRpc(httpd_req_t* req) {
    noteServerTask();
    if (!fromBoardAddress(req)) {
        return refuse(req, "403 Forbidden", "forbidden", "cross-origin request refused");
    }
    char type[kHeaderValue];
    if (!header(req, "Content-Type", type) || !latchkey_util::isJsonContentType(type)) {
        return refuse(req, "415 Unsupported Media Type", "invalid_argument", "send application/json");
    }
    if (req->content_len > kMaxBody) {
        return refuse(req, "413 Content Too Large", "invalid_argument", "request too large");
    }
    auto* request = new (std::nothrow) Request{nullptr, {}};
    if (request == nullptr || httpd_req_async_handler_begin(req, &request->req) != ESP_OK) {
        delete request;
        return refuse(req, "503 Service Unavailable", "busy", "the board is out of memory");
    }
    if (xQueueSend(s_requests, &request, 0) != pdTRUE) {
        refuse(request->req, "503 Service Unavailable", "busy", "the board is answering other requests");
        httpd_req_async_handler_complete(request->req);
        delete request;
        return ESP_FAIL;
    }
    return ESP_OK;
}

void abandon(httpd_req_t* req) {
    const httpd_handle_t server = req->handle;
    const int fd = httpd_req_to_sockfd(req);
    httpd_req_async_handler_complete(req);
    httpd_sess_trigger_close(server, fd);
}

void answer(Request& request) {
    httpd_req_t* req = request.req;
    if (!readBody(req, request.body)) {
        mbedtls_platform_zeroize(request.body.data(), request.body.size());
        abandon(req);
        return;
    }
    std::string token = sessionToken(req);
    rpc::Response response = rpc::dispatch(request.body.c_str(), rpc::Transport::Web, token);
    mbedtls_platform_zeroize(token.data(), token.size());
    mbedtls_platform_zeroize(request.body.data(), request.body.size());
    std::string cookie;
    if (!response.sessionToken.empty()) {
        cookie = latchkey_util::sessionCookie(response.sessionToken);
        httpd_resp_set_hdr(req, "Set-Cookie", cookie.c_str());
    } else if (response.endSession) {
        httpd_resp_set_hdr(req, "Set-Cookie", latchkey_util::kClearedSessionCookie);
    }
    if (sendJson(req, HTTPD_200, response.json) != ESP_OK) {
        ESP_LOGW(TAG, "a reply could not be sent");
    }
    mbedtls_platform_zeroize(cookie.data(), cookie.size());
    mbedtls_platform_zeroize(response.sessionToken.data(), response.sessionToken.size());
    httpd_req_async_handler_complete(req);
    ws::service();
}

void serveRequests(void*) {
    while (true) {
        Request* request = nullptr;
        if (xQueueReceive(s_requests, &request, portMAX_DELAY) == pdTRUE) {
            answer(*request);
            delete request;
        }
    }
}

esp_err_t redirect(httpd_req_t* req) {
    char host[kHeaderValue];
    const std::optional<std::string> target =
        header(req, "Host", host) ? latchkey_util::httpsRedirect(host) : std::nullopt;
    if (!target.has_value()) {
        return refuse(req, "400 Bad Request", "bad_request", "the Host header is missing or malformed");
    }
    securityHeaders(req);
    httpd_resp_set_status(req, "301 Moved Permanently");
    httpd_resp_set_hdr(req, "Location", target->c_str());
    return httpd_resp_send(req, nullptr, 0);
}

esp_err_t startHttps(const latchkey_util::TlsIdentity& identity) {
    httpd_ssl_config_t config{};
    config.httpd = HTTPD_DEFAULT_CONFIG();
    config.httpd.ctrl_port = ESP_HTTPD_DEF_CTRL_PORT + 1;
    config.transport_mode = HTTPD_SSL_TRANSPORT_SECURE;
    config.port_secure = 443;
    config.port_insecure = 80;
    config.servercert = identity.certificate.data();
    config.servercert_len = identity.certificate.size();
    config.prvtkey_pem = identity.key.data();
    config.prvtkey_len = identity.key.size();
    config.session_tickets = true;
    config.tls_handshake_timeout_ms = kHandshakeTimeoutMs;
    config.httpd.recv_wait_timeout = kReceiveTimeoutS;
    config.httpd.stack_size = kHttpsStack;
    config.httpd.max_open_sockets = kHttpsSockets;
    config.httpd.max_uri_handlers = kUriHandlers;
    config.httpd.max_resp_headers = kResponseHeaders;
    config.httpd.lru_purge_enable = true;
    config.httpd.send_wait_timeout = kSendTimeoutS;
    config.httpd.keep_alive_enable = true;
    config.httpd.keep_alive_idle = kKeepAliveIdleS;
    config.httpd.keep_alive_interval = kKeepAliveIntervalS;
    config.httpd.keep_alive_count = kKeepAliveCount;
    config.httpd.uri_match_fn = httpd_uri_match_wildcard;
    const esp_err_t started = httpd_ssl_start(&s_https, &config);
    if (started != ESP_OK) {
        return started;
    }
    httpd_uri_t events{};
    events.uri = "/api/events";
    events.method = HTTP_GET;
    events.handler = answerEvents;
    events.is_websocket = true;
    events.ws_pre_handshake_cb = ws::admit;
    httpd_uri_t api{};
    api.uri = "/api/rpc";
    api.method = HTTP_POST;
    api.handler = acceptRpc;
    httpd_uri_t firmware{};
    firmware.uri = "/api/ota";
    firmware.method = HTTP_POST;
    firmware.handler = ota::accept;
    httpd_uri_t page{};
    page.uri = "/*";
    page.method = HTTP_GET;
    page.handler = servePage;
    for (const httpd_uri_t* uri : {&events, &api, &firmware, &page}) {
        const esp_err_t registered = httpd_register_uri_handler(s_https, uri);
        if (registered != ESP_OK) {
            return registered;
        }
    }
    registerErrors(s_https);
    ws::attach(s_https, kHttpsSockets);
    return ESP_OK;
}

esp_err_t startRedirect() {
    httpd_config_t config = HTTPD_DEFAULT_CONFIG();
    config.server_port = 80;
    config.ctrl_port = ESP_HTTPD_DEF_CTRL_PORT;
    config.max_open_sockets = 1;
    config.max_uri_handlers = 1;
    config.stack_size = kRedirectStack;
    config.lru_purge_enable = true;
    config.uri_match_fn = httpd_uri_match_wildcard;
    const esp_err_t started = httpd_start(&s_redirect, &config);
    if (started != ESP_OK) {
        return started;
    }
    httpd_uri_t any{};
    any.uri = "/*";
    any.method = HTTP_GET;
    any.handler = redirect;
    const esp_err_t registered = httpd_register_uri_handler(s_redirect, &any);
    registerErrors(s_redirect);
    return registered;
}

void startServers(void* arg) {
    const uint32_t ipv4 = static_cast<uint32_t>(reinterpret_cast<uintptr_t>(arg));
    latchkey_util::TlsIdentity identity;
    esp_err_t error = certs::ensure(ipv4, identity);
    if (error == ESP_OK) {
        error = startHttps(identity);
    }
    mbedtls_platform_zeroize(identity.key.data(), identity.key.size());
    if (error == ESP_OK) {
        error = startRedirect();
    }
    if (error != ESP_OK) {
        ESP_LOGE(TAG, "the web server did not start: %s", esp_err_to_name(error));
    } else {
        s_serving = true;
        ESP_LOGI(TAG, "HTTPS on port 443, redirect on port 80");
    }
    vTaskDelete(nullptr);
}

void onGotIp(void*, esp_event_base_t, int32_t, void* data) {
    if (s_started.exchange(true)) {
        return;
    }
    const auto* event = static_cast<const ip_event_got_ip_t*>(data);
    const uintptr_t ipv4 = ntohl(event->ip_info.ip.addr);
    if (xTaskCreate(startServers, "http_init", kInitStack, reinterpret_cast<void*>(ipv4), kTaskPriority, nullptr) !=
        pdPASS) {
        ESP_LOGE(TAG, "cannot start the web server task");
    }
}

}

void start() {
    ws::init();
    s_requests = xQueueCreate(kHttpsSockets, sizeof(Request*));
    if (s_requests == nullptr ||
        xTaskCreate(serveRequests, "rpc_web", kWorkerStack, nullptr, kTaskPriority, &s_worker) != pdPASS) {
        ESP_LOGE(TAG, "cannot start the web request worker");
        abort();
    }
    ESP_ERROR_CHECK(esp_event_handler_register(IP_EVENT, IP_EVENT_STA_GOT_IP, onGotIp, nullptr));
}

bool serving() { return s_serving; }

bool fromBoardAddress(httpd_req_t* req) {
    const uint32_t own = wifi::address();
    char host[kHeaderValue];
    if (!header(req, "Host", host) || !latchkey_util::isOwnHost(host, own)) {
        return false;
    }
    if (httpd_req_get_hdr_value_len(req, "Origin") == 0) {
        return true;
    }
    char origin[kHeaderValue];
    return header(req, "Origin", origin) && latchkey_util::isOwnOrigin(origin, own);
}

uint32_t serverStackFree() {
    const TaskHandle_t task = s_server.load();
    return task != nullptr ? uxTaskGetStackHighWaterMark(task) : 0;
}

uint32_t workerStackFree() { return s_worker != nullptr ? uxTaskGetStackHighWaterMark(s_worker) : 0; }

}
