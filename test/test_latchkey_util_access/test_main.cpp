// SPDX-License-Identifier: GPL-3.0-or-later
#include <unity.h>

#include "latchkey_util/access.h"

using latchkey_util::AccessDecision;
using latchkey_util::AccessRule;

void setUp() {}

void tearDown() {}

static constexpr bool kSerial = true;
static constexpr bool kWeb = false;

static AccessRule rule(bool needsSession, bool needsButton, bool serialOnly, bool job = false) {
    AccessRule value;
    value.needsSession = needsSession;
    value.needsButton = needsButton;
    value.serialOnly = serialOnly;
    value.job = job;
    return value;
}

static void assertAllowed(const AccessDecision& decision) {
    TEST_ASSERT_NULL(decision.error);
    TEST_ASSERT_TRUE(decision.audited);
}

static void assertInline(const AccessDecision& decision) {
    assertAllowed(decision);
    TEST_ASSERT_FALSE(decision.confirm);
    TEST_ASSERT_FALSE(decision.job);
}

static void assertRefused(const AccessDecision& decision, const char* error, bool audited) {
    TEST_ASSERT_NOT_NULL(decision.error);
    TEST_ASSERT_EQUAL_STRING(error, decision.error);
    TEST_ASSERT_NOT_NULL(decision.message);
    TEST_ASSERT_EQUAL(audited, decision.audited);
    TEST_ASSERT_FALSE(decision.confirm);
    TEST_ASSERT_FALSE(decision.job);
}

static void test_serial_is_always_allowed_and_runs_inline() {
    for (int flags = 0; flags < 16; ++flags) {
        const AccessRule access = rule(flags & 1, flags & 2, flags & 4, flags & 8);
        assertInline(latchkey_util::decideAccess(access, kSerial, false));
        assertInline(latchkey_util::decideAccess(access, kSerial, true));
    }
}

static void test_the_web_cannot_call_serial_only_methods() {
    assertRefused(latchkey_util::decideAccess(rule(false, false, true), kWeb, false), "forbidden", false);
    assertRefused(latchkey_util::decideAccess(rule(true, false, true), kWeb, true), "forbidden", true);
    TEST_ASSERT_EQUAL_STRING("serial console only",
                             latchkey_util::decideAccess(rule(true, false, true), kWeb, true).message);
}

static void test_serial_only_is_checked_before_the_session() {
    assertRefused(latchkey_util::decideAccess(rule(true, false, true), kWeb, false), "forbidden", false);
}

static void test_a_web_call_without_a_session_is_unauthorized_and_not_audited() {
    const AccessDecision decision = latchkey_util::decideAccess(rule(true, false, false), kWeb, false);
    assertRefused(decision, "unauthorized", false);
    TEST_ASSERT_EQUAL_STRING("sign in first", decision.message);
    assertRefused(latchkey_util::decideAccess(rule(true, true, false), kWeb, false), "unauthorized", false);
}

static void test_a_web_call_with_a_session_is_allowed() {
    assertInline(latchkey_util::decideAccess(rule(true, false, false), kWeb, true));
}

static void test_button_methods_from_the_web_wait_for_the_press_in_a_job() {
    const AccessDecision decision = latchkey_util::decideAccess(rule(true, true, false), kWeb, true);
    assertAllowed(decision);
    TEST_ASSERT_TRUE(decision.confirm);
    TEST_ASSERT_TRUE(decision.job);
    const AccessDecision open = latchkey_util::decideAccess(rule(false, true, false), kWeb, false);
    assertAllowed(open);
    TEST_ASSERT_TRUE(open.confirm);
    TEST_ASSERT_TRUE(open.job);
}

static void test_job_methods_from_the_web_run_as_jobs_without_the_press() {
    const AccessDecision decision = latchkey_util::decideAccess(rule(true, false, false, true), kWeb, true);
    assertAllowed(decision);
    TEST_ASSERT_FALSE(decision.confirm);
    TEST_ASSERT_TRUE(decision.job);
    assertRefused(latchkey_util::decideAccess(rule(true, false, false, true), kWeb, false), "unauthorized", false);
}

static void test_open_methods_need_no_session() {
    assertInline(latchkey_util::decideAccess(rule(false, false, false), kWeb, false));
    assertInline(latchkey_util::decideAccess(rule(false, false, false), kWeb, true));
}

int main() {
    UNITY_BEGIN();
    RUN_TEST(test_serial_is_always_allowed_and_runs_inline);
    RUN_TEST(test_the_web_cannot_call_serial_only_methods);
    RUN_TEST(test_serial_only_is_checked_before_the_session);
    RUN_TEST(test_a_web_call_without_a_session_is_unauthorized_and_not_audited);
    RUN_TEST(test_a_web_call_with_a_session_is_allowed);
    RUN_TEST(test_button_methods_from_the_web_wait_for_the_press_in_a_job);
    RUN_TEST(test_job_methods_from_the_web_run_as_jobs_without_the_press);
    RUN_TEST(test_open_methods_need_no_session);
    return UNITY_END();
}
