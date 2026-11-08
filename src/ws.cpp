// SPDX-License-Identifier: GPL-3.0-or-later
#include "ws.h"

#include <cstdlib>
#include <deque>
#include <mutex>
#include <utility>
#include <vector>

#include "esp_log.h"
#include "esp_timer.h"
#include "mbedtls/platform_util.h"

#include "auth.h"
#include "events.h"
#include "http.h"
#include "latchkey_util/backlog.h"
#include "latchkey_util/web.h"

namespace ws {

namespace {

constexpr const char* TAG = "ws";
constexpr size_t kMaxPending = 32;
constexpr size_t kMaxClientFrame = 128;
constexpr size_t kTokenBuffer = 65;
constexpr uint64_t kSweepPeriodUs = 5 * 1000 * 1000;

struct Outgoing {
    bool broadcast = true;
    uint32_t session = 0;
    std::string line;
};

std::mutex s_mutex;
std::deque<Outgoing> s_pending;
httpd_handle_t s_server = nullptr;
size_t s_maxSockets = 0;
bool s_queued = false;

void discard(Outgoing& out) {
    if (!out.broadcast) {
        mbedtls_platform_zeroize(out.line.data(), out.line.size());
    }
}

bool sendTo(int fd, const std::string& line) {
    httpd_ws_frame_t frame{};
    frame.final = true;
    frame.type = HTTPD_WS_TYPE_TEXT;
    frame.payload = reinterpret_cast<uint8_t*>(const_cast<char*>(line.data()));
    frame.len = line.size();
    return httpd_ws_send_frame_async(s_server, fd, &frame) == ESP_OK;
}

void serve(int fd, const std::deque<Outgoing>& batch) {
    const auto* session = static_cast<const uint32_t*>(httpd_sess_get_ctx(s_server, fd));
    if (session == nullptr || !auth::sessionOpen(*session)) {
        httpd_sess_trigger_close(s_server, fd);
        return;
    }
    httpd_sess_update_lru_counter(s_server, fd);
    for (const Outgoing& out : batch) {
        if ((out.broadcast || out.session == *session) && !sendTo(fd, out.line)) {
            ESP_LOGW(TAG, "event socket %d does not take frames: closing it", fd);
            httpd_sess_trigger_close(s_server, fd);
            return;
        }
    }
}

void pass(void*) {
    std::deque<Outgoing> batch;
    {
        std::lock_guard<std::mutex> lock(s_mutex);
        batch.swap(s_pending);
        s_queued = false;
    }
    std::vector<int> fds(s_maxSockets);
    size_t count = fds.size();
    if (httpd_get_client_list(s_server, &count, fds.data()) == ESP_OK) {
        for (size_t i = 0; i < count; ++i) {
            if (httpd_ws_get_fd_info(s_server, fds[i]) == HTTPD_WS_CLIENT_WEBSOCKET) {
                serve(fds[i], batch);
            }
        }
    }
    for (Outgoing& out : batch) {
        discard(out);
    }
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
            discard(out);
            return;
        }
        std::optional<Outgoing> dropped = latchkey_util::pushBounded(
            s_pending, std::move(out), kMaxPending, [](const Outgoing& line) { return line.broadcast; });
        if (dropped.has_value()) {
            ESP_LOGW(TAG, "event queue full: dropped the oldest %s", dropped->broadcast ? "event" : "job result");
            discard(*dropped);
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
    events::addSink([](const std::string& line) { enqueue(Outgoing{true, 0, line}); });
    auth::onSessionsEnded(service);
}

void attach(httpd_handle_t server, size_t maxSockets) {
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
    auto* id = static_cast<uint32_t*>(malloc(sizeof(uint32_t)));
    if (id == nullptr) {
        return ESP_FAIL;
    }
    *id = *session;
    req->sess_ctx = id;
    req->free_ctx = free;
    return ESP_OK;
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

void deliver(std::optional<uint32_t> session, std::string line) {
    if (!session.has_value()) {
        mbedtls_platform_zeroize(line.data(), line.size());
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
