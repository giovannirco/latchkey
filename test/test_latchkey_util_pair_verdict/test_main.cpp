// SPDX-License-Identifier: GPL-3.0-or-later
#include <unity.h>

#include "latchkey_util/pair_verdict.h"

using latchkey_util::judgePairing;
using latchkey_util::PairEnd;
using latchkey_util::PairVerdict;

void setUp() {}

void tearDown() {}

static void assertVerdict(PairVerdict expected, PairVerdict actual) {
    TEST_ASSERT_EQUAL_UINT8(static_cast<uint8_t>(expected), static_cast<uint8_t>(actual));
}

static void test_a_pairing_whose_result_was_stored_is_paired() {
    assertVerdict(PairVerdict::Paired, judgePairing(PairEnd::Paired, true, true));
    assertVerdict(PairVerdict::Paired, judgePairing(PairEnd::Paired, false, true));
}

static void test_a_paired_lock_with_keys_but_no_stored_result_is_incomplete() {
    assertVerdict(PairVerdict::Incomplete, judgePairing(PairEnd::Paired, true, false));
}

static void test_a_paired_lock_with_nothing_stored_has_lost_its_keys() {
    assertVerdict(PairVerdict::KeysNotStored, judgePairing(PairEnd::Paired, false, false));
}

static void test_an_incomplete_pairing_keeps_the_keys_it_stored() {
    assertVerdict(PairVerdict::Incomplete, judgePairing(PairEnd::Incomplete, true, false));
    assertVerdict(PairVerdict::Incomplete, judgePairing(PairEnd::Incomplete, true, true));
}

static void test_an_incomplete_pairing_that_stored_nothing_has_lost_its_keys() {
    assertVerdict(PairVerdict::KeysNotStored, judgePairing(PairEnd::Incomplete, false, false));
    assertVerdict(PairVerdict::KeysNotStored, judgePairing(PairEnd::Incomplete, false, true));
}

static void test_a_pairing_that_failed_before_the_keys_stays_failed() {
    assertVerdict(PairVerdict::Failed, judgePairing(PairEnd::Failed, false, false));
    assertVerdict(PairVerdict::Failed, judgePairing(PairEnd::Failed, true, true));
}

int main() {
    UNITY_BEGIN();
    RUN_TEST(test_a_pairing_whose_result_was_stored_is_paired);
    RUN_TEST(test_a_paired_lock_with_keys_but_no_stored_result_is_incomplete);
    RUN_TEST(test_a_paired_lock_with_nothing_stored_has_lost_its_keys);
    RUN_TEST(test_an_incomplete_pairing_keeps_the_keys_it_stored);
    RUN_TEST(test_an_incomplete_pairing_that_stored_nothing_has_lost_its_keys);
    RUN_TEST(test_a_pairing_that_failed_before_the_keys_stays_failed);
    return UNITY_END();
}
