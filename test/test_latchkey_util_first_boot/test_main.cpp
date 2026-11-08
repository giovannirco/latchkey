// SPDX-License-Identifier: GPL-3.0-or-later
#include <unity.h>

#include "latchkey_util/first_boot.h"

void setUp() {}

void tearDown() {}

namespace {

using latchkey_util::FirstBootSignals;
using latchkey_util::FirstBootVerdict;
using latchkey_util::judgeFirstBoot;

constexpr uint32_t kSettle = latchkey_util::kFirstBootSettleSeconds;
constexpr uint32_t kDeadline = latchkey_util::kFirstBootDeadlineSeconds;

FirstBootSignals online() {
    FirstBootSignals signals;
    signals.storageReadable = true;
    signals.consoleRunning = true;
    signals.wifiConfigured = true;
    signals.wifiStarted = true;
    signals.wifiConnected = true;
    signals.webServing = true;
    return signals;
}

}

static void test_the_settle_time_is_shorter_than_the_deadline() { TEST_ASSERT_TRUE(kSettle < kDeadline); }

static void test_a_healthy_image_waits_for_the_settle_time() {
    TEST_ASSERT_EQUAL(FirstBootVerdict::Wait, judgeFirstBoot(online(), 0));
    TEST_ASSERT_EQUAL(FirstBootVerdict::Wait, judgeFirstBoot(online(), kSettle - 1));
    TEST_ASSERT_EQUAL(FirstBootVerdict::Healthy, judgeFirstBoot(online(), kSettle));
}

static void test_wifi_still_retrying_counts_as_healthy() {
    FirstBootSignals signals = online();
    signals.wifiConnected = false;
    signals.webServing = false;
    TEST_ASSERT_EQUAL(FirstBootVerdict::Healthy, judgeFirstBoot(signals, kSettle));
}

static void test_a_connected_board_waits_for_its_web_server_until_the_deadline() {
    FirstBootSignals signals = online();
    signals.webServing = false;
    TEST_ASSERT_EQUAL(FirstBootVerdict::Wait, judgeFirstBoot(signals, kSettle));
    TEST_ASSERT_EQUAL(FirstBootVerdict::Wait, judgeFirstBoot(signals, kDeadline - 1));
    TEST_ASSERT_EQUAL(FirstBootVerdict::Unhealthy, judgeFirstBoot(signals, kDeadline));
}

static void test_each_missing_check_fails_at_the_deadline() {
    bool FirstBootSignals::*checks[] = {&FirstBootSignals::storageReadable, &FirstBootSignals::consoleRunning,
                                        &FirstBootSignals::wifiConfigured, &FirstBootSignals::wifiStarted};
    for (bool FirstBootSignals::*check : checks) {
        FirstBootSignals signals = online();
        signals.*check = false;
        TEST_ASSERT_EQUAL(FirstBootVerdict::Wait, judgeFirstBoot(signals, kSettle));
        TEST_ASSERT_EQUAL(FirstBootVerdict::Unhealthy, judgeFirstBoot(signals, kDeadline));
        TEST_ASSERT_EQUAL(FirstBootVerdict::Unhealthy, judgeFirstBoot(signals, kDeadline + 600));
    }
}

static void test_a_recovery_before_the_deadline_is_healthy() {
    FirstBootSignals signals = online();
    signals.wifiStarted = false;
    TEST_ASSERT_EQUAL(FirstBootVerdict::Wait, judgeFirstBoot(signals, kDeadline - 10));
    signals.wifiStarted = true;
    TEST_ASSERT_EQUAL(FirstBootVerdict::Healthy, judgeFirstBoot(signals, kDeadline - 9));
}

static void test_the_problem_names_the_first_failing_check() {
    FirstBootSignals signals = online();
    TEST_ASSERT_NULL(latchkey_util::firstBootProblem(signals));
    signals.webServing = false;
    TEST_ASSERT_EQUAL_STRING("the web server is not running", latchkey_util::firstBootProblem(signals));
    signals.wifiStarted = false;
    TEST_ASSERT_EQUAL_STRING("Wi-Fi did not start", latchkey_util::firstBootProblem(signals));
    signals.wifiConfigured = false;
    TEST_ASSERT_EQUAL_STRING("Wi-Fi is not configured", latchkey_util::firstBootProblem(signals));
    signals.consoleRunning = false;
    TEST_ASSERT_EQUAL_STRING("the console is not running", latchkey_util::firstBootProblem(signals));
    signals.storageReadable = false;
    TEST_ASSERT_EQUAL_STRING("NVS cannot be read", latchkey_util::firstBootProblem(signals));
}

static void test_web_server_matters_only_while_connected() {
    FirstBootSignals signals = online();
    signals.wifiConnected = false;
    signals.webServing = false;
    TEST_ASSERT_NULL(latchkey_util::firstBootProblem(signals));
}

int main() {
    UNITY_BEGIN();
    RUN_TEST(test_the_settle_time_is_shorter_than_the_deadline);
    RUN_TEST(test_a_healthy_image_waits_for_the_settle_time);
    RUN_TEST(test_wifi_still_retrying_counts_as_healthy);
    RUN_TEST(test_a_connected_board_waits_for_its_web_server_until_the_deadline);
    RUN_TEST(test_each_missing_check_fails_at_the_deadline);
    RUN_TEST(test_a_recovery_before_the_deadline_is_healthy);
    RUN_TEST(test_the_problem_names_the_first_failing_check);
    RUN_TEST(test_web_server_matters_only_while_connected);
    return UNITY_END();
}
