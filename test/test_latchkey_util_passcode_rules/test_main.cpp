// SPDX-License-Identifier: GPL-3.0-or-later
#include <unity.h>

#include <cstddef>
#include <cstdint>
#include <optional>
#include <string>
#include <vector>

#include "latchkey_util/label_table.h"
#include "latchkey_util/passcode_rules.h"

using latchkey_util::Label;
using latchkey_util::LabelTable;
using latchkey_util::ListedCode;
using latchkey_util::NewCode;
using latchkey_util::Target;

void setUp() {}

void tearDown() {}

static const std::vector<ListedCode> kListed{{0x11, "1234"}, {0x22, "567890"}};
static constexpr const char* kAdmin = "7654321";

static void assertNewCode(NewCode expected, NewCode actual) {
    TEST_ASSERT_EQUAL_UINT8(static_cast<uint8_t>(expected), static_cast<uint8_t>(actual));
}

static void assertTarget(Target expected, Target actual) {
    TEST_ASSERT_EQUAL_UINT8(static_cast<uint8_t>(expected), static_cast<uint8_t>(actual));
}

static Label label(uint64_t id, bool managed, const std::string& name) {
    Label entry;
    entry.id = id;
    entry.managed = managed;
    entry.name = name;
    return entry;
}

static void test_a_new_code_must_be_free_on_the_lock() {
    assertNewCode(NewCode::Free, latchkey_util::checkNewCode(kListed, kAdmin, "999999", 0x33, std::nullopt));
    assertNewCode(NewCode::InUse, latchkey_util::checkNewCode(kListed, kAdmin, "1234", 0x33, std::nullopt));
    assertNewCode(NewCode::Free, latchkey_util::checkNewCode(kListed, "", "999999", 0x33, std::nullopt));
}

static void test_the_admin_passcode_counts_as_in_use_with_no_other_answer() {
    assertNewCode(NewCode::InUse, latchkey_util::checkNewCode(kListed, kAdmin, kAdmin, 0x44, std::nullopt));
    assertNewCode(latchkey_util::checkNewCode(kListed, kAdmin, "1234", 0x33, std::nullopt),
                  latchkey_util::checkNewCode(kListed, kAdmin, kAdmin, 0x44, std::nullopt));
}

static void test_a_code_whose_id_collides_with_another_passcode_is_refused() {
    assertNewCode(NewCode::IdTaken, latchkey_util::checkNewCode(kListed, kAdmin, "999999", 0x22, std::nullopt));
    assertNewCode(NewCode::IdTaken, latchkey_util::checkNewCode(kListed, kAdmin, "999999", 0x22, size_t{0}));
}

static void test_the_passcode_being_changed_does_not_count_against_itself() {
    assertNewCode(NewCode::Free, latchkey_util::checkNewCode(kListed, kAdmin, "999999", 0x11, size_t{0}));
    assertNewCode(NewCode::InUse, latchkey_util::checkNewCode(kListed, kAdmin, "567890", 0x22, size_t{0}));
    assertNewCode(NewCode::InUse, latchkey_util::checkNewCode(kListed, kAdmin, kAdmin, 0x55, size_t{0}));
}

static void test_a_target_is_found_by_its_id_once() {
    size_t index = 99;
    assertTarget(Target::Found, latchkey_util::findTarget(kListed, kAdmin, 0x22, index));
    TEST_ASSERT_EQUAL_UINT(1, index);
    assertTarget(Target::Missing, latchkey_util::findTarget(kListed, kAdmin, 0x99, index));
    const std::vector<ListedCode> twice{{0x11, "1234"}, {0x11, "5678"}};
    assertTarget(Target::Ambiguous, latchkey_util::findTarget(twice, kAdmin, 0x11, index));
    const std::vector<ListedCode> withAdmin{{0x11, "1234"}, {0x77, kAdmin}};
    assertTarget(Target::AdminCode, latchkey_util::findTarget(withAdmin, kAdmin, 0x77, index));
    assertTarget(Target::Found, latchkey_util::findTarget(withAdmin, "", 0x77, index));
}

static void test_an_admin_passcode_may_not_be_a_user_passcode() {
    TEST_ASSERT_TRUE(latchkey_util::isListedCode(kListed, "567890"));
    TEST_ASSERT_FALSE(latchkey_util::isListedCode(kListed, "000000"));
    TEST_ASSERT_FALSE(latchkey_util::isListedCode({}, "1234"));
}

static void test_a_recoded_passcode_takes_its_label_to_the_new_id() {
    LabelTable labels;
    TEST_ASSERT_TRUE(labels.put(label(0x11, true, "Guest")));
    TEST_ASSERT_TRUE(latchkey_util::relabel(labels, 0x11, 0x33, std::nullopt));
    TEST_ASSERT_NULL(labels.find(0x11));
    TEST_ASSERT_NOT_NULL(labels.find(0x33));
    TEST_ASSERT_TRUE(labels.find(0x33)->managed);
    TEST_ASSERT_EQUAL_STRING("Guest", labels.find(0x33)->name.c_str());
    TEST_ASSERT_TRUE(latchkey_util::relabel(labels, 0x33, 0x33, std::string("Cleaner")));
    TEST_ASSERT_EQUAL_STRING("Cleaner", labels.find(0x33)->name.c_str());
    TEST_ASSERT_TRUE(labels.find(0x33)->managed);
}

static void test_relabelling_an_unnamed_passcode_stores_only_what_says_something() {
    LabelTable labels;
    TEST_ASSERT_TRUE(latchkey_util::relabel(labels, 0x11, 0x33, std::nullopt));
    TEST_ASSERT_EQUAL_UINT(0, labels.size());
    TEST_ASSERT_TRUE(latchkey_util::relabel(labels, 0x11, 0x33, std::string("Named")));
    TEST_ASSERT_FALSE(labels.find(0x33)->managed);
    TEST_ASSERT_TRUE(latchkey_util::relabel(labels, 0x33, 0x33, std::string("")));
    TEST_ASSERT_EQUAL_UINT(0, labels.size());
}

static void test_a_full_table_refuses_a_new_name_and_stays_as_it_was() {
    LabelTable labels;
    for (uint64_t id = 1; id <= latchkey_util::kMaxLabels; ++id) {
        TEST_ASSERT_TRUE(labels.put(label(id, true, "")));
    }
    TEST_ASSERT_FALSE(latchkey_util::relabel(labels, 0x99, 0x98, std::string("New")));
    TEST_ASSERT_EQUAL_UINT(latchkey_util::kMaxLabels, labels.size());
    TEST_ASSERT_NULL(labels.find(0x98));
    TEST_ASSERT_TRUE(latchkey_util::relabel(labels, 5, 0x98, std::string("Moved")));
    TEST_ASSERT_NULL(labels.find(5));
    TEST_ASSERT_EQUAL_STRING("Moved", labels.find(0x98)->name.c_str());
}

static void test_easy_codes_are_spotted() {
    for (const char* code : {"123456", "1234", "000000", "1111", "999999999", "654321", "9876", "23456789", "3210"}) {
        TEST_ASSERT_TRUE_MESSAGE(latchkey_util::isEasyCode(code), code);
    }
    for (const char* code : {"582961", "1357", "112233", "8402917", "123457", "0987", "135792468"}) {
        TEST_ASSERT_FALSE_MESSAGE(latchkey_util::isEasyCode(code), code);
    }
}

int main(int, char**) {
    UNITY_BEGIN();
    RUN_TEST(test_a_new_code_must_be_free_on_the_lock);
    RUN_TEST(test_the_admin_passcode_counts_as_in_use_with_no_other_answer);
    RUN_TEST(test_a_code_whose_id_collides_with_another_passcode_is_refused);
    RUN_TEST(test_the_passcode_being_changed_does_not_count_against_itself);
    RUN_TEST(test_a_target_is_found_by_its_id_once);
    RUN_TEST(test_an_admin_passcode_may_not_be_a_user_passcode);
    RUN_TEST(test_a_recoded_passcode_takes_its_label_to_the_new_id);
    RUN_TEST(test_relabelling_an_unnamed_passcode_stores_only_what_says_something);
    RUN_TEST(test_a_full_table_refuses_a_new_name_and_stays_as_it_was);
    RUN_TEST(test_easy_codes_are_spotted);
    return UNITY_END();
}
