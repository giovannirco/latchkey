// SPDX-License-Identifier: GPL-3.0-or-later
#pragma once

#include <algorithm>
#include <array>
#include <cerrno>
#include <cstring>
#include <deque>
#include <functional>
#include <map>
#include <string>
#include <utility>
#include <vector>

#include "esp_event.h"
#include "esp_https_server.h"
#include "esp_timer.h"
#include "freertos/queue.h"
#include "freertos/task.h"
#include "lwip/sockets.h"

namespace http_fixture {
struct Socket {
    uint32_t session = 0;
    bool closed = false;
    void* context = nullptr;
    void (*freeContext)(void*) = nullptr;
    bool shutdownPending = false;
    bool asynchronous = false;
};
struct SessionSlot {
    int fd = -1;
    uint64_t lruCounter = 0;
};
inline std::map<std::string, std::string> headers;
inline std::string cookie, body, status, reply;
inline std::map<int, Socket> sockets;
inline std::array<SessionSlot, 4> slots;
inline uint64_t lruCounter = 0;
inline size_t queuedCloses = 0;
inline size_t shutdownCalls = 0, shutdownsOutsideServer = 0;
inline bool onServerTask = false;
inline std::vector<std::pair<int, std::string>> sent;
inline std::deque<std::pair<void (*)(void*), void*>> work;
inline std::function<void()> onSend;
inline std::function<void()> onCloseRequested;
inline std::function<void(char*, size_t)> onReceive;
inline std::function<void()> onComplete;
inline void* request = nullptr;
inline bool rejectQueue = false, rejectAsync = false, rejectWork = false, rejectClose = false;
inline bool rejectList = false, rejectSend = false;
inline size_t offset = 0, recvCalls = 0, completed = 0, closed = 0;
inline size_t readChunk = SIZE_MAX;
inline int recvError = 0;
inline int64_t now = 0, readDelay = 0;
inline int fd = 10;
inline bool openSocket(int fd, Socket socket) {
    for (auto& slot : slots) {
        if (slot.fd != -1) continue;
        slot = {fd, ++lruCounter};
        sockets[fd] = socket;
        return true;
    }
    return false;
}
inline void retireSocket(int fd) {
    for (auto& slot : slots) {
        if (slot.fd != fd || fd == -1) continue;
        auto& socket = sockets.at(fd);
        socket.closed = true;
        if (socket.freeContext) socket.freeContext(socket.context);
        socket.context = nullptr;
        socket.freeContext = nullptr;
        slot.fd = -1;
        ++closed;
        if (std::none_of(slots.begin(), slots.end(), [](const auto& entry) { return entry.fd != -1; })) lruCounter = 0;
        return;
    }
}
inline void reset() {
    for (const auto& [fd, socket] : sockets) if (socket.freeContext) socket.freeContext(socket.context);
    headers = {{"Host", "192.0.2.1"}, {"Content-Type", "application/json"}};
    cookie = "fixture-session";
    body.clear(); status.clear(); reply.clear(); sockets.clear(); sent.clear(); work.clear(); onSend = {}; onReceive = {};
    onCloseRequested = {}; onComplete = {};
    slots = {};
    lruCounter = queuedCloses = 0;
    shutdownCalls = shutdownsOutsideServer = 0;
    onServerTask = false;
    request = nullptr;
    rejectQueue = rejectAsync = rejectWork = rejectClose = rejectList = rejectSend = false;
    offset = recvCalls = completed = closed = 0;
    readChunk = SIZE_MAX;
    recvError = 0;
    now = readDelay = 0;
    fd = 10;
}
inline void runWork() {
    const auto callback = work.front();
    work.pop_front();
    onServerTask = true;
    callback.first(callback.second);
    for (const auto& [fd, socket] : sockets) {
        if (!socket.closed && socket.shutdownPending) retireSocket(fd);
    }
    onServerTask = false;
}
}

int lwip_shutdown(int fd, int how) {
    using namespace http_fixture;
    ++shutdownCalls;
    if (!onServerTask) ++shutdownsOutsideServer;
    const auto found = sockets.find(fd);
    if (found == sockets.end() || found->second.closed) { errno = EBADF; return -1; }
    if (how != SHUT_RDWR) { errno = EINVAL; return -1; }
    if (rejectClose) { errno = ENOMEM; return -1; }
    if (onCloseRequested) onCloseRequested();
    found->second.shutdownPending = true;
    return 0;
}

bool httpd_uri_match_wildcard(const char*, const char*, size_t) { return false; }
esp_err_t httpd_resp_set_hdr(httpd_req_t*, const char*, const char*) { return ESP_OK; }
esp_err_t httpd_resp_set_status(httpd_req_t*, const char* status) { http_fixture::status = status; return ESP_OK; }
esp_err_t httpd_resp_set_type(httpd_req_t*, const char*) { return ESP_OK; }
esp_err_t httpd_resp_send(httpd_req_t*, const char* data, ssize_t size) {
    http_fixture::reply.assign(data != nullptr ? data : "", static_cast<size_t>(size));
    return http_fixture::rejectSend ? ESP_FAIL : ESP_OK;
}
size_t httpd_req_get_hdr_value_len(httpd_req_t*, const char* name) { return http_fixture::headers[name].size(); }
esp_err_t httpd_req_get_hdr_value_str(httpd_req_t*, const char* name, char* output, size_t capacity) {
    const auto found = http_fixture::headers.find(name);
    if (found == http_fixture::headers.end() || found->second.size() >= capacity) return ESP_FAIL;
    std::memcpy(output, found->second.c_str(), found->second.size() + 1);
    return ESP_OK;
}
esp_err_t httpd_req_get_cookie_val(httpd_req_t*, const char*, char* output, size_t* capacity) {
    if (http_fixture::cookie.empty() || http_fixture::cookie.size() >= *capacity) return ESP_FAIL;
    std::memcpy(output, http_fixture::cookie.c_str(), http_fixture::cookie.size() + 1);
    *capacity = http_fixture::cookie.size() + 1;
    return ESP_OK;
}
int httpd_req_recv(httpd_req_t*, char* output, size_t capacity) {
    using namespace http_fixture;
    ++recvCalls;
    if (onReceive) onReceive(output, capacity);
    now += readDelay;
    if (recvError != 0) return recvError;
    const size_t count = std::min({capacity, body.size() - offset, readChunk});
    std::memcpy(output, body.data() + offset, count);
    offset += count;
    return static_cast<int>(count);
}
int httpd_req_to_sockfd(httpd_req_t*) { return http_fixture::fd; }
esp_err_t httpd_req_async_handler_begin(httpd_req_t* req, httpd_req_t** out) {
    if (http_fixture::rejectAsync) return ESP_FAIL;
    http_fixture::sockets.at(http_fixture::fd).asynchronous = true;
    *out = req;
    return ESP_OK;
}
esp_err_t httpd_req_async_handler_complete(httpd_req_t*) {
    ++http_fixture::completed;
    auto& socket = http_fixture::sockets.at(http_fixture::fd);
    socket.asynchronous = false;
    if (socket.shutdownPending) http_fixture::retireSocket(http_fixture::fd);
    if (http_fixture::onComplete) http_fixture::onComplete();
    return ESP_OK;
}
esp_err_t httpd_sess_trigger_close(httpd_handle_t server, int fd) {
    using namespace http_fixture;
    if (rejectClose) return ESP_FAIL;
    for (auto& slot : slots) {
        if (slot.fd != fd) continue;
        if (onCloseRequested) onCloseRequested();
        const auto result = httpd_queue_work(server, [](void* arg) {
            auto* slot = static_cast<SessionSlot*>(arg);
            if (slot->lruCounter != 0) retireSocket(slot->fd);
        }, &slot);
        if (result == ESP_OK) ++queuedCloses;
        return result;
    }
    return ESP_FAIL;
}
esp_err_t httpd_sess_update_lru_counter(httpd_handle_t, int fd) {
    for (auto& slot : http_fixture::slots) {
        if (slot.fd == fd) {
            slot.lruCounter = ++http_fixture::lruCounter;
            return ESP_OK;
        }
    }
    return ESP_FAIL;
}
void* httpd_sess_get_ctx(httpd_handle_t, int fd) {
    const auto found = http_fixture::sockets.find(fd);
    return found == http_fixture::sockets.end() ? nullptr : found->second.context;
}
esp_err_t httpd_register_err_handler(httpd_handle_t, httpd_err_code_t, esp_err_t (*)(httpd_req_t*, httpd_err_code_t)) {
    return ESP_OK;
}
esp_err_t httpd_register_uri_handler(httpd_handle_t, const httpd_uri_t*) { return ESP_OK; }
esp_err_t httpd_start(httpd_handle_t* server, const httpd_config_t*) { *server = reinterpret_cast<void*>(1); return ESP_OK; }
esp_err_t httpd_ssl_start(httpd_handle_t* server, const httpd_ssl_config_t*) { *server = reinterpret_cast<void*>(1); return ESP_OK; }
esp_err_t httpd_get_client_list(httpd_handle_t, size_t* count, int* fds) {
    if (http_fixture::rejectList) return ESP_FAIL;
    size_t written = 0;
    for (const auto& [fd, socket] : http_fixture::sockets) {
        if (socket.closed || written == *count) continue;
        fds[written++] = fd;
    }
    *count = written;
    return ESP_OK;
}
httpd_ws_client_info_t httpd_ws_get_fd_info(httpd_handle_t, int fd) {
    return http_fixture::sockets.contains(fd) && !http_fixture::sockets.at(fd).closed
        ? HTTPD_WS_CLIENT_WEBSOCKET : HTTPD_WS_CLIENT_INVALID;
}
esp_err_t httpd_ws_recv_frame(httpd_req_t*, httpd_ws_frame_t*, size_t) { return ESP_OK; }
esp_err_t httpd_ws_send_frame_async(httpd_handle_t, int fd, httpd_ws_frame_t* frame) {
    if (http_fixture::onSend) http_fixture::onSend();
    if (http_fixture::rejectSend) return ESP_FAIL;
    http_fixture::sent.emplace_back(fd, std::string(reinterpret_cast<char*>(frame->payload), frame->len));
    return ESP_OK;
}
esp_err_t httpd_queue_work(httpd_handle_t, void (*callback)(void*), void* arg) {
    if (http_fixture::rejectWork) return ESP_FAIL;
    http_fixture::work.emplace_back(callback, arg);
    return ESP_OK;
}
int64_t esp_timer_get_time() { return http_fixture::now; }
esp_err_t esp_timer_create(const esp_timer_create_args_t*, esp_timer_handle_t* timer) {
    *timer = reinterpret_cast<void*>(1); return ESP_OK;
}
esp_err_t esp_timer_start_periodic(esp_timer_handle_t, uint64_t) { return ESP_OK; }
QueueHandle_t xQueueCreate(UBaseType_t, UBaseType_t) { return reinterpret_cast<void*>(1); }
BaseType_t xQueueSend(QueueHandle_t, const void* value, TickType_t) {
    if (http_fixture::rejectQueue) return 0;
    std::memcpy(&http_fixture::request, value, sizeof(void*));
    return pdTRUE;
}
BaseType_t xQueueReceive(QueueHandle_t, void*, TickType_t) { return 0; }
BaseType_t xTaskCreate(void (*)(void*), const char*, uint32_t, void*, UBaseType_t, TaskHandle_t*) { return pdPASS; }
TaskHandle_t xTaskGetCurrentTaskHandle() { return reinterpret_cast<void*>(1); }
uint32_t uxTaskGetStackHighWaterMark(TaskHandle_t) { return 0; }
void vTaskDelete(TaskHandle_t) {}
void xTaskNotifyGive(TaskHandle_t) {}
uint32_t ulTaskNotifyTake(BaseType_t, TickType_t) { return 0; }
esp_err_t esp_event_handler_register(esp_event_base_t, int32_t, void (*)(void*, esp_event_base_t, int32_t, void*), void*) {
    return ESP_OK;
}
