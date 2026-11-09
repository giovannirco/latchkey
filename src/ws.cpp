// SPDX-License-Identifier: GPL-3.0-or-later
#include "ws.h"

#include <array>
#include <cstdlib>
#include <mutex>
#include <utility>

#include "esp_log.h"
#include "esp_timer.h"
#include "lwip/sockets.h"
#include "mbedtls/platform_util.h"

#include "auth.h"
#include "events.h"
#include "http.h"
#include "latchkey_util/web.h"

namespace ws {

namespace {

constexpr const char* TAG = "ws";
constexpr size_t kMaxPending = 32;
constexpr size_t kMaxQueuedBytes = latchkey_util::kMaxRpcResponse + 1;
constexpr size_t kMaxSockets = 4;
constexpr size_t kMaxClientFrame = 128;
constexpr size_t kTokenBuffer = 65;
constexpr uint64_t kSweepPeriodUs = 5 * 1000 * 1000;

struct Outgoing {
    bool broadcast = true;
    uint32_t session = 0;
    latchkey_util::RpcText line;
};

struct Socket {
    uint32_t session;
    int fd;
    bool failed = false;
};

std::mutex s_mutex;
std::array<Outgoing, kMaxPending> s_pending;
std::array<Socket*, kMaxSockets> s_sockets{};
size_t s_pendingCount = 0;
size_t s_count = 0;
size_t s_bytes = 0;
httpd_handle_t s_server = nullptr;
size_t s_maxSockets = 0;
bool s_queued = false;

void failSessionLocked(uint32_t session) {
    for (Socket* socket : s_sockets) if (socket != nullptr && socket->session == session) socket->failed = true;
}

bool failedSocket(int fd) {
    std::lock_guard<std::mutex> lock(s_mutex);
    for (const Socket* socket : s_sockets) if (socket != nullptr && socket->fd == fd) return socket->failed;
    return false;
}

void freeSocket(void* context) {
    {
        std::lock_guard<std::mutex> lock(s_mutex);
        for (Socket*& socket : s_sockets) if (socket == context) socket = nullptr;
    }
    free(context);
}

void failSession(uint32_t session) {
    std::lock_guard<std::mutex> lock(s_mutex);
    failSessionLocked(session);
}

bool closeSocket(int fd, uint32_t session) {
    if (shutdown(fd, SHUT_RDWR) == 0) return true;
    failSession(session);
    return false;
}

void release(Outgoing& out) {
    const size_t bytes = out.line.capacity() + 1;
    out.line.clear();
    s_bytes -= bytes;
    --s_count;
}

bool sendTo(int fd, const latchkey_util::RpcText& line) {
    httpd_ws_frame_t frame{};
    frame.final = true;
    frame.type = HTTPD_WS_TYPE_TEXT;
    frame.payload = reinterpret_cast<uint8_t*>(const_cast<char*>(line.c_str()));
    frame.len = line.size();
    return httpd_ws_send_frame_async(s_server, fd, &frame) == ESP_OK;
}

bool serve(int fd, const std::array<Outgoing, kMaxPending>& batch, size_t count) {
    const auto* context = static_cast<const Socket*>(httpd_sess_get_ctx(s_server, fd));
    if (context == nullptr) return shutdown(fd, SHUT_RDWR) == 0;
    const uint32_t session = context->session;
    if (!auth::sessionOpen(session) || failedSocket(fd)) {
        return closeSocket(fd, session);
    }
    httpd_sess_update_lru_counter(s_server, fd);
    for (size_t i = 0; i < count; ++i) {
        const Outgoing& out = batch[i];
        if (failedSocket(fd)) return closeSocket(fd, session);
        if ((out.broadcast || out.session == session) && !sendTo(fd, out.line)) {
            ESP_LOGW(TAG, "event socket %d does not take frames: closing it", fd);
            return closeSocket(fd, session);
        }
    }
    return true;
}

void pass(void*) {
    std::array<Outgoing, kMaxPending> batch;
    size_t count = 0;
    {
        std::lock_guard<std::mutex> lock(s_mutex);
        count = std::exchange(s_pendingCount, 0);
        for (size_t i = 0; i < count; ++i) batch[i] = std::move(s_pending[i]);
        s_queued = false;
    }
    std::array<int, kMaxSockets> fds{};
    size_t sockets = s_maxSockets;
    const bool scanned = httpd_get_client_list(s_server, &sockets, fds.data()) == ESP_OK;
    if (scanned) {
        for (size_t i = 0; i < sockets; ++i) {
            if (httpd_ws_get_fd_info(s_server, fds[i]) == HTTPD_WS_CLIENT_WEBSOCKET) {
                serve(fds[i], batch, count);
            }
        }
    }
    std::lock_guard<std::mutex> lock(s_mutex);
    if (!scanned) {
        for (size_t i = 0; i < count; ++i) {
            if (!batch[i].broadcast) failSessionLocked(batch[i].session);
        }
    }
    for (size_t i = 0; i < count; ++i) release(batch[i]);
}

void schedule(bool due) {
    if (!due) {
        return;
    }
    if (httpd_queue_work(s_server, pass, nullptr) != ESP_OK) {
        std::lock_guard<std::mutex> lock(s_mutex);
        s_queued = false;
        ESP_LOGE(TAG, "the web server's work queue is full: events wait for the next one");
    }
}

void enqueue(Outgoing out) {
    bool due = false;
    {
        std::lock_guard<std::mutex> lock(s_mutex);
        if (s_server == nullptr) {
            return;
        }
        const size_t bytes = out.line.capacity() + 1;
        while (!out.line.empty() && (s_count == kMaxPending || bytes > kMaxQueuedBytes - s_bytes)) {
            size_t victim = 0;
            while (victim < s_pendingCount && !s_pending[victim].broadcast) ++victim;
            if (victim == s_pendingCount) break;
            release(s_pending[victim]);
            --s_pendingCount;
            for (size_t i = victim; i < s_pendingCount; ++i) s_pending[i] = std::move(s_pending[i + 1]);
        }
        if (out.line.empty() || s_count == kMaxPending || bytes > kMaxQueuedBytes - s_bytes) {
            if (!out.broadcast) failSessionLocked(out.session);
        } else {
            s_pending[s_pendingCount++] = std::move(out);
            s_bytes += bytes;
            ++s_count;
        }
        due = !s_queued;
        s_queued = true;
    }
    schedule(due);
}

std::optional<uint32_t> sessionOf(httpd_req_t* req) {
    char token[kTokenBuffer] = {};
    size_t length = sizeof(token);
    std::optional<uint32_t> session;
    if (httpd_req_get_cookie_val(req, latchkey_util::kSessionCookieName, token, &length) == ESP_OK) {
        session = auth::sessionFor(token);
    }
    mbedtls_platform_zeroize(token, sizeof(token));
    return session;
}

}

void init() {
    events::addSink([](const std::string& line) {
        latchkey_util::RpcText text(latchkey_util::RpcText::Limit::Response);
        if (text.assign(line)) enqueue(Outgoing{true, 0, std::move(text)});
    });
    auth::onSessionsEnded(service);
}

void attach(httpd_handle_t server, size_t maxSockets) {
    if (maxSockets > kMaxSockets) {
        ESP_LOGE(TAG, "event socket capacity exceeded");
        return;
    }
    {
        std::lock_guard<std::mutex> lock(s_mutex);
        s_maxSockets = maxSockets;
        s_server = server;
    }
    const esp_timer_create_args_t sweep = {
        .callback = [](void*) { service(); },
        .arg = nullptr,
        .dispatch_method = ESP_TIMER_TASK,
        .name = "ws_sweep",
        .skip_unhandled_events = true,
    };
    esp_timer_handle_t timer = nullptr;
    ESP_ERROR_CHECK(esp_timer_create(&sweep, &timer));
    ESP_ERROR_CHECK(esp_timer_start_periodic(timer, kSweepPeriodUs));
}

esp_err_t admit(httpd_req_t* req) {
    if (!http::fromBoardAddress(req)) {
        ESP_LOGW(TAG, "refused an event socket for another address or origin");
        return ESP_FAIL;
    }
    const std::optional<uint32_t> session = sessionOf(req);
    if (!session.has_value()) {
        return ESP_FAIL;
    }
    auto* socket = static_cast<Socket*>(malloc(sizeof(Socket)));
    if (socket == nullptr) {
        return ESP_FAIL;
    }
    *socket = {*session, httpd_req_to_sockfd(req), false};
    {
        std::lock_guard<std::mutex> lock(s_mutex);
        for (Socket*& slot : s_sockets) {
            if (slot == nullptr) {
                slot = socket;
                req->sess_ctx = socket;
                req->free_ctx = freeSocket;
                return ESP_OK;
            }
        }
    }
    free(socket);
    return ESP_FAIL;
}

esp_err_t receive(httpd_req_t* req) {
    httpd_ws_frame_t frame{};
    if (httpd_ws_recv_frame(req, &frame, 0) != ESP_OK) {
        return ESP_FAIL;
    }
    if (frame.len == 0) {
        return ESP_OK;
    }
    if (frame.len > kMaxClientFrame) {
        return ESP_FAIL;
    }
    uint8_t payload[kMaxClientFrame];
    frame.payload = payload;
    return httpd_ws_recv_frame(req, &frame, frame.len);
}

void deliver(std::optional<uint32_t> session, latchkey_util::RpcText line) {
    if (!session.has_value()) {
        return;
    }
    enqueue(Outgoing{false, *session, std::move(line)});
}

void service() {
    bool due = false;
    {
        std::lock_guard<std::mutex> lock(s_mutex);
        if (s_server == nullptr) {
            return;
        }
        due = !s_queued;
        s_queued = true;
    }
    schedule(due);
}

}
