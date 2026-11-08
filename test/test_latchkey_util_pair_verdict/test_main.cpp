// SPDX-License-Identifier: GPL-3.0-or-later
#include <unity.h>

#include <string>

#include "latchkey_util/pair_verdict.h"
#include "ttlock/frame.h"
#include "ttlock/status.h"

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

static void test_unsupported_after_a_new_mismatch_means_another_lock_type() {
    TEST_ASSERT_TRUE(latchkey_util::answeredAsAnotherLockType(ttlock::Status::Unsupported, 0, 1));
    TEST_ASSERT_TRUE(latchkey_util::answeredAsAnotherLockType(ttlock::Status::Unsupported, 2, 5));
    TEST_ASSERT_FALSE(latchkey_util::answeredAsAnotherLockType(ttlock::Status::Unsupported, 2, 2));
    TEST_ASSERT_FALSE(latchkey_util::answeredAsAnotherLockType(ttlock::Status::Unsupported, 0, 0));
    TEST_ASSERT_FALSE(latchkey_util::answeredAsAnotherLockType(ttlock::Status::Timeout, 0, 1));
    TEST_ASSERT_FALSE(latchkey_util::answeredAsAnotherLockType(ttlock::Status::PairIncomplete, 0, 1));
}

static void test_the_mismatch_message_names_both_lock_types() {
    const std::string text =
        latchkey_util::lockTypeMismatch(ttlock::LockVersion{5, 4, 2, 1, 1}, ttlock::LockVersion{5, 3, 1, 1, 1});
    TEST_ASSERT_EQUAL_STRING("the lock answered as lock type 5.4 scene 2, but its advert said 5.3 scene 1: this "
                             "board only pairs the lock type it advertises",
                             text.c_str());
}

int main() {
    UNITY_BEGIN();
    RUN_TEST(test_a_pairing_whose_result_was_stored_is_paired);
    RUN_TEST(test_a_paired_lock_with_keys_but_no_stored_result_is_incomplete);
    RUN_TEST(test_a_paired_lock_with_nothing_stored_has_lost_its_keys);
    RUN_TEST(test_an_incomplete_pairing_keeps_the_keys_it_stored);
    RUN_TEST(test_an_incomplete_pairing_that_stored_nothing_has_lost_its_keys);
    RUN_TEST(test_a_pairing_that_failed_before_the_keys_stays_failed);
    RUN_TEST(test_unsupported_after_a_new_mismatch_means_another_lock_type);
    RUN_TEST(test_the_mismatch_message_names_both_lock_types);
    return UNITY_END();
}
