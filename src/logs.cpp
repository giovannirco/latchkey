// SPDX-License-Identifier: GPL-3.0-or-later
#include "logs.h"

#include <mutex>
#include <optional>
#include <string_view>
#include <sys/time.h>

#include "esp_attr.h"
#include "esp_timer.h"
#include "freertos/FreeRTOS.h"
#include "sdkconfig.h"

#include "clock.h"
#include "latchkey_util/secret_pattern.h"
#include "syslog_client.h"

namespace logs {

namespace {

constexpr std::string_view kWithheld = "line withheld: it matched a secret pattern";

#if CONFIG_IDF_TARGET_ESP32
constexpr size_t kRingBytes = 6144;
RTC_NOINIT_ATTR uint8_t s_storage[kRingBytes];
#else
constexpr size_t kRingBytes = 32768;
uint8_t s_storage[kRingBytes];
#endif

std::mutex s_mutex;
latchkey_util::LogRing s_ring(s_storage, kRingBytes);
uint32_t s_withheld = 0;

uint64_t uptimeMs() { return static_cast<uint64_t>(esp_timer_get_time() / 1000); }

std::optional<int64_t> utcMs() {
    if (!wallclock::synced()) {
        return std::nullopt;
    }
    struct timeval now {};
    gettimeofday(&now, nullptr);
    return static_cast<int64_t>(now.tv_sec) * 1000 + now.tv_usec / 1000;
}

}

void capture(const char* text, size_t length) {
    if (xPortInIsrContext()) {
        return;
    }
    const std::string_view raw(text, length);
    latchkey_util::LogLine line = latchkey_util::parseLogLine(raw);
    const bool secret = latchkey_util::holdsSecretPattern(raw);
    if (secret) {
        line.message = kWithheld;
    }
    const auto up = static_cast<uint32_t>(uptimeMs());
    {
        std::lock_guard<std::mutex> lock(s_mutex);
        s_ring.append(up, line);
        if (secret) {
            ++s_withheld;
        }
    }
    syslog_client::wake();
}

Cursor oldestCursor() {
    std::lock_guard<std::mutex> lock(s_mutex);
    return s_ring.oldestCursor();
}

Cursor after(uint32_t seq) {
    std::lock_guard<std::mutex> lock(s_mutex);
    return s_ring.after(seq);
}

Cursor newest(size_t count, latchkey_util::LogLevel threshold) {
    std::lock_guard<std::mutex> lock(s_mutex);
    return s_ring.newest(count, threshold);
}

bool read(Cursor& cursor, latchkey_util::LogLevel threshold, latchkey_util::LogEntry& out, uint32_t& skipped) {
    std::lock_guard<std::mutex> lock(s_mutex);
    const uint32_t oldest = s_ring.oldest();
    skipped = cursor.seq < oldest ? oldest - cursor.seq : 0;
    return s_ring.read(cursor, threshold, out);
}

uint32_t oldest() {
    std::lock_guard<std::mutex> lock(s_mutex);
    return s_ring.oldest();
}

Stats stats() {
    std::lock_guard<std::mutex> lock(s_mutex);
    return {s_ring.count(), kRingBytes, s_withheld};
}

latchkey_util::LogTimes timesOf(const latchkey_util::LogEntry& entry) {
    return latchkey_util::logTimes(entry.upMs, uptimeMs(), utcMs());
}

}
