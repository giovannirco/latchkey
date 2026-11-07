// SPDX-License-Identifier: GPL-3.0-or-later
#include <unity.h>

#include "ttlock/version.h"

void setUp() {}

void tearDown() {}

static void test_library_version_is_0_1_0() {
    TEST_ASSERT_EQUAL_STRING("0.1.0", ttlock::libraryVersion());
}

int main() {
    UNITY_BEGIN();
    RUN_TEST(test_library_version_is_0_1_0);
    return UNITY_END();
}
