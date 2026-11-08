// SPDX-License-Identifier: GPL-3.0-or-later
#include <unity.h>

#include <cstddef>

#include "latchkey_util/storage_budget.h"

using latchkey_util::StorageNeeds;

void setUp() {}

void tearDown() {}

static void test_a_blob_takes_an_index_a_chunk_header_and_its_32_byte_entries() {
    TEST_ASSERT_EQUAL_UINT(32, latchkey_util::kNvsEntryBytes);
    TEST_ASSERT_EQUAL_UINT(2, latchkey_util::nvsBlobEntries(0));
    TEST_ASSERT_EQUAL_UINT(3, latchkey_util::nvsBlobEntries(1));
    TEST_ASSERT_EQUAL_UINT(3, latchkey_util::nvsBlobEntries(32));
    TEST_ASSERT_EQUAL_UINT(4, latchkey_util::nvsBlobEntries(33));
    TEST_ASSERT_EQUAL_UINT(5, latchkey_util::nvsBlobEntries(88));
    TEST_ASSERT_EQUAL_UINT(12, latchkey_util::nvsBlobEntries(304));
    TEST_ASSERT_EQUAL_UINT(61, latchkey_util::nvsBlobEntries(1858));
}

static void test_audit_records_still_to_come_follow_the_ring() {
    TEST_ASSERT_EQUAL_UINT(200, latchkey_util::auditRecordsLeft(1, 200));
    TEST_ASSERT_EQUAL_UINT(150, latchkey_util::auditRecordsLeft(51, 200));
    TEST_ASSERT_EQUAL_UINT(1, latchkey_util::auditRecordsLeft(200, 200));
    TEST_ASSERT_EQUAL_UINT(0, latchkey_util::auditRecordsLeft(201, 200));
    TEST_ASSERT_EQUAL_UINT(0, latchkey_util::auditRecordsLeft(5000, 200));
    TEST_ASSERT_EQUAL_UINT(200, latchkey_util::auditRecordsLeft(0, 200));
}

static void test_the_reserve_holds_the_rest_of_the_audit_ring_one_pairing_and_a_spare() {
    StorageNeeds needs;
    needs.auditRecordsLeft = 200;
    needs.auditRecordBytes = 88;
    needs.lockRecordBytes = 304;
    needs.seedTableBytes = 104;
    needs.spareEntries = 40;
    TEST_ASSERT_EQUAL_UINT(200 * 5 + 1 + 2 * 12 + 2 * 6 + 40, latchkey_util::reservedEntries(needs));
    needs.auditRecordsLeft = 0;
    TEST_ASSERT_EQUAL_UINT(1 + 2 * 12 + 2 * 6 + 40, latchkey_util::reservedEntries(needs));
}

static void test_a_write_must_leave_the_reserve_untouched() {
    TEST_ASSERT_TRUE(latchkey_util::fitsAboveReserve(100, 88, 95));
    TEST_ASSERT_TRUE(latchkey_util::fitsAboveReserve(100, 96, 95));
    TEST_ASSERT_FALSE(latchkey_util::fitsAboveReserve(100, 97, 95));
    TEST_ASSERT_TRUE(latchkey_util::fitsAboveReserve(1318, 1858, 1077));
    TEST_ASSERT_FALSE(latchkey_util::fitsAboveReserve(1100, 1858, 1077));
    TEST_ASSERT_FALSE(latchkey_util::fitsAboveReserve(10, 0, 20));
    TEST_ASSERT_FALSE(latchkey_util::fitsAboveReserve(0, 0, 0));
}

int main(int, char**) {
    UNITY_BEGIN();
    RUN_TEST(test_a_blob_takes_an_index_a_chunk_header_and_its_32_byte_entries);
    RUN_TEST(test_audit_records_still_to_come_follow_the_ring);
    RUN_TEST(test_the_reserve_holds_the_rest_of_the_audit_ring_one_pairing_and_a_spare);
    RUN_TEST(test_a_write_must_leave_the_reserve_untouched);
    return UNITY_END();
}
