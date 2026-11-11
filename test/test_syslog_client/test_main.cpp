// SPDX-License-Identifier: GPL-3.0-or-later
#include <unity.h>

#include <atomic>
#include <cerrno>
#include <cstring>
#include <fcntl.h>
#include <functional>
#include <mutex>
#include <netdb.h>
#include <netinet/tcp.h>
#include <string>
#include <sys/socket.h>
#include <unistd.h>
#include <vector>

#include "freertos/task.h"
#include "../../src/syslog_client.h"
#include "../../src/logs.h"
#include "latchkey_util/rate_limit.h"
#include "latchkey_util/syslog.h"

static int64_t timeMs = 0;
static bool taskAllowed = true;
static esp_err_t saveError = ESP_OK;
static size_t created = 0;
static size_t saved = 0;
static size_t notifications = 0;
static store::cfg::Syslog persisted;
static std::vector<uint32_t> waits;
static size_t connected = 0;
static uint32_t idleWakeMs = 30000;
static bool peerClosed = false;
static bool sendFails = false;
static std::vector<std::string> sent;
static uint8_t ringStorage[4096];
static latchkey_util::LogRing ring(ringStorage, sizeof(ringStorage));
static std::function<void()> duringSave;

enum eNotifyAction { eSetBits };
BaseType_t xTaskNotify(TaskHandle_t, uint32_t, eNotifyAction) { ++notifications; return pdPASS; }
BaseType_t xTaskNotifyWait(uint32_t, uint32_t, uint32_t* bits, TickType_t ticks) {
    *bits = 0;
    waits.push_back(ticks);
    timeMs += ticks == 30000 ? idleWakeMs : ticks;
    return pdPASS;
}
TickType_t xTaskGetTickCount() { return timeMs; }
BaseType_t xTaskCreate(void (*)(void*), const char*, uint32_t, void*, UBaseType_t, TaskHandle_t* out) {
    ++created;
    if (!taskAllowed) return 0;
    *out = reinterpret_cast<void*>(1);
    return pdPASS;
}
uint32_t uxTaskGetStackHighWaterMark(TaskHandle_t) { return 1024; }
int64_t esp_timer_get_time() { return timeMs * 1000; }

static int fixtureResolve(const char*, const char*, const addrinfo*, addrinfo** result) {
    static sockaddr_in address{};
    static addrinfo found{};
    found.ai_addr = reinterpret_cast<sockaddr*>(&address);
    *result = &found;
    return 0;
}
static void fixtureFreeAddress(addrinfo*) {}
static int fixtureSocket(int, int, int) { return 42; }
static int fixtureConnect(int, const sockaddr*, socklen_t) { ++connected; return 0; }
static int fixtureClose(int) { return 0; }
static int fixtureFcntl(int, int, ...) { return 0; }
static int fixtureSetSockOpt(int, int, int, const void*, socklen_t) { return 0; }
static ssize_t fixtureSend(int, const void* bytes, size_t size, int) {
    if (sendFails) { errno = EPIPE; return -1; }
    sent.emplace_back(static_cast<const char*>(bytes), size);
    return size;
}
static ssize_t fixtureReceive(int, void*, size_t, int) {
    if (peerClosed) return 0;
    errno = EAGAIN;
    return -1;
}

#define getaddrinfo fixtureResolve
#define freeaddrinfo fixtureFreeAddress
#define socket fixtureSocket
#define connect fixtureConnect
#define close fixtureClose
#define fcntl fixtureFcntl
#define setsockopt fixtureSetSockOpt
#define send fixtureSend
#define recv fixtureReceive
#ifndef TCP_KEEPIDLE
#define TCP_KEEPIDLE TCP_KEEPALIVE
#endif
#include "../../src/syslog_client.cpp"
#undef getaddrinfo
#undef freeaddrinfo
#undef socket
#undef connect
#undef close
#undef fcntl
#undef setsockopt
#undef send
#undef recv

namespace store::cfg {
esp_err_t loadSyslog(Syslog& out) { out = persisted; return ESP_OK; }
esp_err_t saveSyslog(const Syslog& settings) {
    ++saved;
    if (duringSave) duringSave();
    if (saveError != ESP_OK) return saveError;
    persisted = settings;
    return ESP_OK;
}
}
namespace wifi {
uint32_t address() { return 1; }
}
namespace board {
const char* name() { return "fixture"; }
}
namespace logs {
Cursor oldestCursor() { return ring.oldestCursor(); }
Cursor after(uint32_t seq) { return ring.after(seq); }
bool read(Cursor& cursor, latchkey_util::LogLevel threshold, latchkey_util::LogEntry& out, uint32_t& skipped) {
    skipped = 0;
    return ring.read(cursor, threshold, out);
}
latchkey_util::LogTimes timesOf(const latchkey_util::LogEntry& entry) { return {entry.upMs, std::nullopt}; }
}

void setUp() {
    timeMs = 0;
    idleWakeMs = 30000;
    taskAllowed = true;
    saveError = ESP_OK;
    created = saved = notifications = connected = 0;
    persisted = {};
    waits.clear();
    sent.clear();
    peerClosed = sendFails = false;
    duringSave = {};
    ring = latchkey_util::LogRing(ringStorage, sizeof(ringStorage));
    syslog_client::s_settings = {};
    syslog_client::s_generation = 0;
    syslog_client::s_task = nullptr;
    syslog_client::s_wakeTarget = nullptr;
    syslog_client::s_connected = false;
    syslog_client::s_sent = syslog_client::s_dropped = syslog_client::s_errors = 0;
}
void tearDown() {}

static store::cfg::Syslog enabled() {
    store::cfg::Syslog settings;
    settings.enabled = true;
    settings.tcp = true;
    settings.host = "collector.example";
    return settings;
}

static void test_task_creation_failure_keeps_settings_disabled_without_persistence() {
    taskAllowed = false;
    TEST_ASSERT_EQUAL(ESP_ERR_NO_MEM, syslog_client::apply(enabled()));
    TEST_ASSERT_EQUAL_UINT(0, saved);
    TEST_ASSERT_FALSE(syslog_client::settings().enabled);
    TEST_ASSERT_FALSE(persisted.enabled);
}

static void test_persistence_requires_task_readiness_and_publishes_only_after_success() {
    duringSave = [] {
        TEST_ASSERT_EQUAL_UINT(1, created);
        TEST_ASSERT_FALSE(syslog_client::s_settings.enabled);
    };
    saveError = ESP_FAIL;
    TEST_ASSERT_EQUAL(ESP_FAIL, syslog_client::apply(enabled()));
    TEST_ASSERT_FALSE(syslog_client::settings().enabled);
    TEST_ASSERT_FALSE(persisted.enabled);
    saveError = ESP_OK;
    TEST_ASSERT_EQUAL(ESP_OK, syslog_client::apply(enabled()));
    TEST_ASSERT_EQUAL_UINT(1, created);
    TEST_ASSERT_TRUE(syslog_client::settings().enabled);
    TEST_ASSERT_TRUE(persisted.enabled);
}

static void appendLine() {
    ring.append(timeMs, {latchkey_util::LogLevel::Info, "fixture", "a diagnostic line"});
}

static void test_a_local_send_does_not_reset_reconnect_backoff() {
    idleWakeMs = 1;
    TEST_ASSERT_EQUAL(ESP_OK, syslog_client::apply(enabled()));
    syslog_client::Sender sender;
    for (uint32_t delay : {1000u, 2000u, 4000u, 8000u, 16000u, 32000u, 64000u, 120000u, 120000u}) {
        sender.poll();
        appendLine();
        sendFails = false;
        sender.poll();
        appendLine();
        sendFails = true;
        sender.poll();
        const size_t connections = connected;
        sender.poll();
        TEST_ASSERT_EQUAL_UINT(delay, waits.back());
        TEST_ASSERT_EQUAL_UINT(connections, connected);
    }
}

static void test_peer_closure_counts_as_failure_and_waits_before_reconnect() {
    TEST_ASSERT_EQUAL(ESP_OK, syslog_client::apply(enabled()));
    syslog_client::Sender sender;
    sender.poll();
    appendLine();
    peerClosed = true;
    sender.poll();
    TEST_ASSERT_FALSE(syslog_client::status().connected);
    TEST_ASSERT_EQUAL_UINT(1, syslog_client::status().errors);
    sender.poll();
    TEST_ASSERT_EQUAL_UINT(1000, waits.back());
    TEST_ASSERT_EQUAL_UINT(1, connected);
}

static void test_a_stable_connection_resets_backoff_after_shipping() {
    TEST_ASSERT_EQUAL(ESP_OK, syslog_client::apply(enabled()));
    syslog_client::Sender sender;
    for (uint32_t delay : {1000u, 2000u}) {
        sender.poll();
        appendLine();
        sendFails = true;
        sender.poll();
        sender.poll();
        TEST_ASSERT_EQUAL_UINT(delay, waits.back());
    }
    sender.poll();
    sendFails = false;
    sender.poll();
    appendLine();
    sendFails = true;
    sender.poll();
    sender.poll();
    TEST_ASSERT_EQUAL_UINT(1000, waits.back());
}

static void test_configuration_change_clears_backoff() {
    TEST_ASSERT_EQUAL(ESP_OK, syslog_client::apply(enabled()));
    syslog_client::Sender sender;
    sender.poll();
    appendLine();
    sendFails = true;
    sender.poll();
    auto settings = enabled();
    settings.host = "new-collector.example";
    TEST_ASSERT_EQUAL(ESP_OK, syslog_client::apply(settings));
    sender.poll();
    TEST_ASSERT_EQUAL_UINT(2, connected);
    TEST_ASSERT_TRUE(waits.empty());
}

static void test_a_failed_send_is_retried_without_skipping_the_line() {
    TEST_ASSERT_EQUAL(ESP_OK, syslog_client::apply(enabled()));
    syslog_client::Sender sender;
    sender.poll();
    appendLine();
    sendFails = true;
    sender.poll();
    TEST_ASSERT_TRUE(sent.empty());
    sender.poll();
    sender.poll();
    sendFails = false;
    sender.poll();
    TEST_ASSERT_EQUAL_UINT(1, sent.size());
    TEST_ASSERT_TRUE(sent[0].find("a diagnostic line") != std::string::npos);
    TEST_ASSERT_EQUAL_UINT(1, syslog_client::status().sent);
}

static void test_a_rejected_reconfiguration_preserves_the_active_destination() {
    TEST_ASSERT_EQUAL(ESP_OK, syslog_client::apply(enabled()));
    const size_t previousNotifications = notifications;
    auto settings = enabled();
    settings.host = "rejected-collector.example";
    saveError = ESP_FAIL;
    TEST_ASSERT_EQUAL(ESP_FAIL, syslog_client::apply(settings));
    TEST_ASSERT_EQUAL_STRING("collector.example", syslog_client::settings().host.c_str());
    TEST_ASSERT_EQUAL_STRING("collector.example", persisted.host.c_str());
    TEST_ASSERT_EQUAL_UINT(previousNotifications, notifications);
}

int main() {
    UNITY_BEGIN();
    RUN_TEST(test_task_creation_failure_keeps_settings_disabled_without_persistence);
    RUN_TEST(test_persistence_requires_task_readiness_and_publishes_only_after_success);
    RUN_TEST(test_a_local_send_does_not_reset_reconnect_backoff);
    RUN_TEST(test_peer_closure_counts_as_failure_and_waits_before_reconnect);
    RUN_TEST(test_a_stable_connection_resets_backoff_after_shipping);
    RUN_TEST(test_configuration_change_clears_backoff);
    RUN_TEST(test_a_failed_send_is_retried_without_skipping_the_line);
    RUN_TEST(test_a_rejected_reconfiguration_preserves_the_active_destination);
    return UNITY_END();
}
