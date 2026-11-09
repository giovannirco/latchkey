// SPDX-License-Identifier: GPL-3.0-or-later
#include <unity.h>

#include <cstring>
#include <string>
#include <type_traits>

#include "../reference/allocation_failure.h"
#include "latchkey_util/rpc_text.h"

using latchkey_util::RpcText;

void setUp() { allocation_failure::reset(); }
void tearDown() { allocation_failure::resume(); }

static void test_storage_is_on_demand_bounded_and_move_only() {
    static_assert(!std::is_copy_constructible_v<RpcText>);
    RpcText text;
    TEST_ASSERT_EQUAL_UINT(0, text.capacity());
    TEST_ASSERT_TRUE(text.assign("fixture request"));
    const auto* pointer = text.data();
    RpcText moved(std::move(text));
    TEST_ASSERT_EQUAL_UINT(0, text.capacity());
    TEST_ASSERT_EQUAL_PTR(pointer, moved.data());
    TEST_ASSERT_TRUE(moved.view() == "fixture request");
    TEST_ASSERT_FALSE(moved.resize(latchkey_util::kMaxRpcText + 1));
    TEST_ASSERT_TRUE(moved.view() == "fixture request");
}

static void test_full_request_capacity_is_accepted_with_a_terminator() {
    RpcText text;
    TEST_ASSERT_TRUE(text.resize(latchkey_util::kMaxRpcText));
    std::memset(text.data(), 'x', text.size());
    TEST_ASSERT_EQUAL_UINT8(0, text.data()[text.size()]);
    TEST_ASSERT_FALSE(text.append('x'));
    TEST_ASSERT_EQUAL_UINT(latchkey_util::kMaxRpcText, text.size());
}

static void test_growth_failure_preserves_the_original_and_wipes_on_release() {
    RpcText text;
    TEST_ASSERT_TRUE(text.assign("fixture secret"));
    const auto* pointer = text.data();
    allocation_failure::expectWiped(reinterpret_cast<const uint8_t*>(text.data()), text.capacity() + 1);
    allocation_failure::failNext();
    const bool grown = text.resize(16384);
    allocation_failure::resume();
    TEST_ASSERT_FALSE(grown);
    TEST_ASSERT_EQUAL_PTR(pointer, text.data());
    TEST_ASSERT_TRUE(text.view() == "fixture secret");
    text.clear();
    TEST_ASSERT_EQUAL_UINT(1, allocation_failure::checkedWipes);
    TEST_ASSERT_TRUE(allocation_failure::wiped);
}

static void test_shrink_erases_the_old_suffix_without_allocating() {
    RpcText text;
    TEST_ASSERT_TRUE(text.assign("fixture secret"));
    const auto capacity = text.capacity();
    allocation_failure::failNext();
    TEST_ASSERT_TRUE(text.resize(3));
    allocation_failure::resume();
    TEST_ASSERT_EQUAL_UINT(0, allocation_failure::attempts);
    for (size_t i = 3; i <= capacity; ++i) TEST_ASSERT_EQUAL_UINT8(0, text.data()[i]);
}

int main() {
    UNITY_BEGIN();
    RUN_TEST(test_storage_is_on_demand_bounded_and_move_only);
    RUN_TEST(test_full_request_capacity_is_accepted_with_a_terminator);
    RUN_TEST(test_growth_failure_preserves_the_original_and_wipes_on_release);
    RUN_TEST(test_shrink_erases_the_old_suffix_without_allocating);
    return UNITY_END();
}
