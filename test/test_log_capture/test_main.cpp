// SPDX-License-Identifier: GPL-3.0-or-later
#include <unity.h>

#include <string>

bool xPortInIsrContext() { return false; }
#include "../../src/logs.cpp"

static uintptr_t writer = 1;
static size_t wakes = 0;

TaskHandle_t xTaskGetCurrentTaskHandle() { return reinterpret_cast<void*>(writer); }
int64_t esp_timer_get_time() { return 1000000; }
namespace wallclock {
bool synced() { return false; }
}
namespace syslog_client {
void wake() { ++wakes; }
}

void setUp() {
    logs::s_ring = latchkey_util::LogRing(logs::s_storage, sizeof(logs::s_storage));
    logs::s_joiner = {};
    logs::s_withheld = 0;
    writer = 1;
    wakes = 0;
}
void tearDown() {}

static void capture(const std::string& text, bool cut = false) {
    logs::capture(text.data(), text.size(), cut);
}

static std::string readMessage(logs::Cursor& cursor) {
    latchkey_util::LogEntry entry;
    uint32_t skipped = 0;
    TEST_ASSERT_TRUE(logs::read(cursor, latchkey_util::LogLevel::Verbose, entry, skipped));
    TEST_ASSERT_TRUE(entry.tagText().empty());
    return std::string(entry.messageText());
}

static void test_console_cut_withholds_partial_secret_and_preserves_next_line() {
    capture("I (1) t: " + std::string(225, 'x') + std::string(21, 'a'), true);
    capture("next line\n");
    auto cursor = logs::oldestCursor();
    TEST_ASSERT_EQUAL_STRING("line withheld: incomplete log line", readMessage(cursor).c_str());
    TEST_ASSERT_EQUAL_STRING("next line", readMessage(cursor).c_str());
    TEST_ASSERT_EQUAL_UINT(1, logs::stats().withheld);
}

static void test_buffer_overflow_and_interruption_are_counted_as_withheld() {
    capture("I (1) t: " + std::string(220, 'x'));
    capture(std::string(32, 'a') + "\n");
    capture("I (2) t: sec");
    writer = 2;
    capture("I (3) u:");
    capture(" fine\n");
    writer = 1;
    capture("ret=synthetic\n");
    TEST_ASSERT_EQUAL_UINT(3, logs::stats().withheld);
}

static void test_secret_in_tag_is_withheld_together_with_message() {
    capture("I (1) lk_session=synthetic: ordinary message\n");
    auto cursor = logs::oldestCursor();
    TEST_ASSERT_EQUAL_STRING("line withheld: it matched a secret pattern", readMessage(cursor).c_str());
    TEST_ASSERT_EQUAL_UINT(1, logs::stats().withheld);
}

static void test_secret_patterns_crossing_capture_boundaries_never_reach_the_ring() {
    for (const std::string secret : {std::string(32, 'a'), std::string(32, 'Q'),
                                    std::string("\"password\":\"synthetic-value\"")}) {
        for (size_t prefix = 210; prefix <= 260; ++prefix) {
            setUp();
            capture("I (1) t: " + std::string(prefix, 'x'));
            capture(secret + "\n");
            auto cursor = logs::oldestCursor();
            const std::string message = readMessage(cursor);
            TEST_ASSERT_TRUE(message.starts_with("line withheld:"));
            TEST_ASSERT_EQUAL_UINT(1, logs::stats().withheld);
        }
    }
}

int main() {
    UNITY_BEGIN();
    RUN_TEST(test_console_cut_withholds_partial_secret_and_preserves_next_line);
    RUN_TEST(test_buffer_overflow_and_interruption_are_counted_as_withheld);
    RUN_TEST(test_secret_in_tag_is_withheld_together_with_message);
    RUN_TEST(test_secret_patterns_crossing_capture_boundaries_never_reach_the_ring);
    return UNITY_END();
}
