// SPDX-License-Identifier: GPL-3.0-or-later
#include <unity.h>

#include "latchkey_util/pair_wait.h"

void setUp() {}

void tearDown() {}

static void test_a_pairing_over_usb_waits_30_s_for_the_lock() {
    TEST_ASSERT_EQUAL_UINT32(30, latchkey_util::defaultPairWaitSeconds(true));
}

static void test_a_pairing_from_the_web_waits_120_s_within_the_cap() {
    TEST_ASSERT_EQUAL_UINT32(120, latchkey_util::defaultPairWaitSeconds(false));
    TEST_ASSERT_TRUE(latchkey_util::defaultPairWaitSeconds(false) <= latchkey_util::kMaxPairWaitSeconds);
}

int main() {
    UNITY_BEGIN();
    RUN_TEST(test_a_pairing_over_usb_waits_30_s_for_the_lock);
    RUN_TEST(test_a_pairing_from_the_web_waits_120_s_within_the_cap);
    return UNITY_END();
}
