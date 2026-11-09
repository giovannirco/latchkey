// SPDX-License-Identifier: GPL-3.0-or-later
#include "syslog_client.h"

#include <atomic>
#include <cerrno>
#include <cstring>
#include <mutex>
#include <string>

#include "esp_log.h"
#include "esp_timer.h"
#include "freertos/FreeRTOS.h"
#include "freertos/task.h"
#include "lwip/netdb.h"
#include "lwip/sockets.h"

#include "board.h"
#include "latchkey_util/rate_limit.h"
#include "latchkey_util/syslog.h"
#include "logs.h"
#include "wifi.h"

namespace syslog_client {

namespace {

constexpr const char* TAG = "syslog";
constexpr uint32_t kTaskStack = 3584;
constexpr UBaseType_t kTaskPriority = 2;
constexpr uint32_t kLineBit = 1;
constexpr uint32_t kSettingsBit = 2;
constexpr TickType_t kNetworkPoll = pdMS_TO_TICKS(1000);
constexpr TickType_t kIdleCheck = pdMS_TO_TICKS(30000);
constexpr int kConnectTimeoutS = 5;
constexpr int kTcpSendTimeoutS = 5;
constexpr int kUdpSendTimeoutS = 1;
constexpr int kKeepAliveIdleS = 60;
constexpr int kKeepAliveIntervalS = 10;
constexpr int kKeepAliveCount = 3;
constexpr latchkey_util::RateLimiter::Policy kBackoff{1, 1, 120};

std::mutex s_mutex;
store::cfg::Syslog s_settings;
uint32_t s_generation = 0;
TaskHandle_t s_task = nullptr;
std::atomic<TaskHandle_t> s_wakeTarget{nullptr};
std::atomic<bool> s_connected{false};
std::atomic<uint32_t> s_sent{0};
std::atomic<uint32_t> s_dropped{0};
std::atomic<uint32_t> s_errors{0};

struct Plan {
    store::cfg::Syslog settings;
    uint32_t generation = 0;
};

Plan snapshot() {
    std::lock_guard<std::mutex> lock(s_mutex);
    return {s_settings, s_generation};
}

bool changedSince(uint32_t generation) {
    std::lock_guard<std::mutex> lock(s_mutex);
    return s_generation != generation;
}

int64_t nowMs() { return esp_timer_get_time() / 1000; }

const char* transportName(const store::cfg::Syslog& settings) { return settings.tcp ? "tcp" : "udp"; }

uint32_t waitForWake(TickType_t ticks) {
    uint32_t bits = 0;
    xTaskNotifyWait(0, UINT32_MAX, &bits, ticks);
    return bits;
}

void waitForSettings(TickType_t ticks) {
    const TickType_t started = xTaskGetTickCount();
    TickType_t left = ticks;
    while ((waitForWake(left) & kSettingsBit) == 0) {
        const TickType_t elapsed = xTaskGetTickCount() - started;
        if (ticks != portMAX_DELAY && elapsed >= ticks) {
            return;
        }
        left = ticks == portMAX_DELAY ? portMAX_DELAY : ticks - elapsed;
    }
}

bool resolve(const std::string& host, uint16_t port, sockaddr_in& out) {
    addrinfo hints{};
    hints.ai_family = AF_INET;
    addrinfo* found = nullptr;
    if (getaddrinfo(host.c_str(), nullptr, &hints, &found) != 0 || found == nullptr) {
        return false;
    }
    std::memcpy(&out, found->ai_addr, sizeof(out));
    freeaddrinfo(found);
    out.sin_port = htons(port);
    return true;
}

class Connection {
public:
    Connection() = default;

    Connection(const Connection&) = delete;
    Connection& operator=(const Connection&) = delete;

    ~Connection() { close(); }

    bool open(const store::cfg::Syslog& settings, int& problem) {
        close();
        problem = 0;
        sockaddr_in address{};
        if (!resolve(settings.host, settings.port, address)) {
            return false;
        }
        tcp_ = settings.tcp;
        errno = 0;
        fd_ = socket(AF_INET, tcp_ ? SOCK_STREAM : SOCK_DGRAM, tcp_ ? IPPROTO_TCP : IPPROTO_UDP);
        const bool ready = fd_ >= 0 && (tcp_ ? connectStream(address) : connectDatagram(address));
        if (!ready) {
            problem = errno != 0 ? errno : EIO;
            close();
        }
        return ready;
    }

    bool send(const std::string& data) {
        size_t written = 0;
        while (written < data.size()) {
            const int count = ::send(fd_, data.data() + written, data.size() - written, 0);
            if (count <= 0) {
                return false;
            }
            written += static_cast<size_t>(count);
        }
        return true;
    }

    bool peerClosed() {
        if (!tcp_) {
            return false;
        }
        char byte = 0;
        const int count = recv(fd_, &byte, 1, MSG_PEEK | MSG_DONTWAIT);
        return count == 0 || (count < 0 && errno != EAGAIN && errno != EWOULDBLOCK);
    }

    bool isOpen() const { return fd_ >= 0; }

    void close() {
        if (fd_ >= 0) {
            ::close(fd_);
            fd_ = -1;
        }
    }

private:
    void sendTimeout(int seconds) {
        const timeval timeout = {seconds, 0};
        setsockopt(fd_, SOL_SOCKET, SO_SNDTIMEO, &timeout, sizeof(timeout));
    }

    bool connectDatagram(const sockaddr_in& address) {
        if (connect(fd_, reinterpret_cast<const sockaddr*>(&address), sizeof(address)) != 0) {
            return false;
        }
        sendTimeout(kUdpSendTimeoutS);
        return true;
    }

    bool connectStream(const sockaddr_in& address) {
        const int flags = fcntl(fd_, F_GETFL, 0);
        fcntl(fd_, F_SETFL, flags | O_NONBLOCK);
        if (connect(fd_, reinterpret_cast<const sockaddr*>(&address), sizeof(address)) != 0) {
            if (errno != EINPROGRESS) {
                return false;
            }
            fd_set writable;
            FD_ZERO(&writable);
            FD_SET(fd_, &writable);
            timeval timeout = {kConnectTimeoutS, 0};
            if (select(fd_ + 1, nullptr, &writable, nullptr, &timeout) <= 0) {
                errno = ETIMEDOUT;
                return false;
            }
            int problem = 0;
            socklen_t length = sizeof(problem);
            if (getsockopt(fd_, SOL_SOCKET, SO_ERROR, &problem, &length) != 0 || problem != 0) {
                errno = problem;
                return false;
            }
        }
        fcntl(fd_, F_SETFL, flags);
        const int on = 1;
        setsockopt(fd_, SOL_SOCKET, SO_KEEPALIVE, &on, sizeof(on));
        setsockopt(fd_, IPPROTO_TCP, TCP_KEEPIDLE, &kKeepAliveIdleS, sizeof(kKeepAliveIdleS));
        setsockopt(fd_, IPPROTO_TCP, TCP_KEEPINTVL, &kKeepAliveIntervalS, sizeof(kKeepAliveIntervalS));
        setsockopt(fd_, IPPROTO_TCP, TCP_KEEPCNT, &kKeepAliveCount, sizeof(kKeepAliveCount));
        sendTimeout(kTcpSendTimeoutS);
        return true;
    }

    int fd_ = -1;
    bool tcp_ = false;
};

class Sender {
public:
    Sender() : backoff_(kBackoff) {}

    void run() {
        while (true) {
            takeSettings();
            if (!settings_.enabled) {
                waitForSettings(portMAX_DELAY);
            } else if (!connection_.isOpen()) {
                connect();
            } else if (!ship()) {
                fail("cannot send to", sendProblem_);
            } else if (!changedSince(generation_)) {
                waitForWake(kIdleCheck);
                if (connection_.peerClosed()) {
                    connection_.close();
                    s_connected = false;
                }
            }
        }
    }

private:
    void takeSettings() {
        Plan plan = snapshot();
        if (started_ && plan.generation == generation_) {
            return;
        }
        const bool wasEnabled = started_ && settings_.enabled;
        started_ = true;
        generation_ = plan.generation;
        settings_ = std::move(plan.settings);
        connection_.close();
        s_connected = false;
        backoff_.recordSuccess();
        warned_ = false;
        if (settings_.enabled && !wasEnabled) {
            cursor_ = logs::oldestCursor();
        }
        if (settings_.enabled) {
            ESP_LOGI(TAG, "sending %s and more severe lines to %s:%u over %s",
                     std::string(latchkey_util::logLevelName(settings_.level)).c_str(), settings_.host.c_str(),
                     static_cast<unsigned>(settings_.port), transportName(settings_));
        } else if (wasEnabled) {
            ESP_LOGI(TAG, "remote logging is off");
        }
    }

    void connect() {
        if (wifi::address() == 0) {
            waitForSettings(kNetworkPoll);
            return;
        }
        const uint32_t wait = backoff_.retryAfterSeconds(nowMs());
        if (wait > 0) {
            waitForSettings(pdMS_TO_TICKS(wait * 1000));
            return;
        }
        int problem = 0;
        if (!connection_.open(settings_, problem)) {
            fail(problem == 0 ? "cannot resolve" : "cannot connect to", problem);
            return;
        }
        s_connected = true;
    }

    void fail(const char* what, int problem) {
        connection_.close();
        s_connected = false;
        ++s_errors;
        backoff_.recordFailure(nowMs());
        if (!warned_) {
            warned_ = true;
            ESP_LOGW(TAG, "%s %s:%u over %s (errno %d); retrying, waiting longer each time", what,
                     settings_.host.c_str(), static_cast<unsigned>(settings_.port), transportName(settings_),
                     problem);
        }
    }

    bool ship() {
        latchkey_util::LogEntry entry;
        while (!changedSince(generation_)) {
            uint32_t skipped = 0;
            const bool found = logs::read(cursor_, settings_.level, entry, skipped);
            s_dropped += skipped;
            if (!found) {
                return true;
            }
            if (!connection_.send(render(entry))) {
                sendProblem_ = errno;
                cursor_ = logs::after(entry.seq - 1);
                return false;
            }
            ++s_sent;
            backoff_.recordSuccess();
            if (warned_) {
                warned_ = false;
                ESP_LOGI(TAG, "sending to %s:%u over %s again", settings_.host.c_str(),
                         static_cast<unsigned>(settings_.port), transportName(settings_));
            }
        }
        return true;
    }

    const std::string& render(const latchkey_util::LogEntry& entry) {
        const latchkey_util::LogTimes times = logs::timesOf(entry);
        latchkey_util::SyslogMessage message;
        message.level = entry.level;
        message.seq = entry.seq;
        message.uptimeMs = times.uptimeMs;
        message.utcMs = times.utcMs;
        message.hostname = board::name();
        message.appName = settings_.appName;
        message.tag = entry.tagText();
        message.message = entry.messageText();
        const size_t limit =
            settings_.tcp ? latchkey_util::kMaxSyslogTcpMessage : latchkey_util::kMaxSyslogUdpMessage;
        latchkey_util::formatSyslog(message_, message, limit);
        if (!settings_.tcp) {
            return message_;
        }
        latchkey_util::frameOctetCounted(frame_, message_);
        return frame_;
    }

    latchkey_util::RateLimiter backoff_;
    Connection connection_;
    store::cfg::Syslog settings_;
    uint32_t generation_ = 0;
    bool started_ = false;
    bool warned_ = false;
    int sendProblem_ = 0;
    logs::Cursor cursor_;
    std::string message_;
    std::string frame_;
};

void run(void*) {
    Sender sender;
    sender.run();
}

esp_err_t activate(const store::cfg::Syslog& settings) {
    std::lock_guard<std::mutex> lock(s_mutex);
    s_settings = settings;
    ++s_generation;
    if (s_task == nullptr && settings.enabled) {
        if (xTaskCreate(run, "syslog", kTaskStack, nullptr, kTaskPriority, &s_task) != pdPASS) {
            s_task = nullptr;
            return ESP_ERR_NO_MEM;
        }
    } else if (s_task != nullptr) {
        xTaskNotify(s_task, kSettingsBit, eSetBits);
    }
    s_wakeTarget = settings.enabled ? s_task : nullptr;
    return ESP_OK;
}

}

void start() {
    store::cfg::Syslog stored;
    const esp_err_t loaded = store::cfg::loadSyslog(stored);
    if (loaded != ESP_OK) {
        ESP_LOGE(TAG, "cannot read the remote logging settings (%s): remote logging stays off", esp_err_to_name(loaded));
        return;
    }
    if (activate(stored) != ESP_OK) {
        ESP_LOGE(TAG, "cannot start the remote logging task");
    }
}

esp_err_t apply(const store::cfg::Syslog& settings) {
    const esp_err_t stored = store::cfg::saveSyslog(settings);
    return stored == ESP_OK ? activate(settings) : stored;
}

store::cfg::Syslog settings() {
    std::lock_guard<std::mutex> lock(s_mutex);
    return s_settings;
}

Status status() { return {s_connected, s_sent, s_dropped, s_errors}; }

void wake() {
    TaskHandle_t task = s_wakeTarget;
    if (task != nullptr) {
        xTaskNotify(task, kLineBit, eSetBits);
    }
}

uint32_t stackFree() {
    std::lock_guard<std::mutex> lock(s_mutex);
    return s_task != nullptr ? uxTaskGetStackHighWaterMark(s_task) : 0;
}

}
