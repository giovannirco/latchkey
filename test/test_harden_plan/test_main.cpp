// SPDX-License-Identifier: GPL-3.0-or-later
#include <unity.h>
#include "latchkey_util/harden_plan.h"

using namespace latchkey_util;
static LockMetadata metadata;
static LabelTable labels;
static constexpr std::string_view oldCode = "1357924";
static constexpr std::string_view nextCode = "2468135";
void setUp() {
    metadata = {};
    metadata.lifecycle = kBackupBackedUp;
    metadata.provenance = AdminProvenance::PairingGenerated;
    labels = {};
}
void tearDown() {}
static void test_managed_and_admin_codes_are_preserved_but_unmanaged_cyclic_codes_are_deleted() {
    labels.put({1, true, "Managed", {}});
    labels.put({5, false, "Weekly", WeeklyWindow{1, 60, 120}});
    std::copy(nextCode.begin(), nextCode.end(), metadata.pendingAdminPasscode.begin());
    metadata.pendingProvenance = AdminProvenance::HardeningGenerated;
    const HardenPasscode codes[]{
        {1, "1000001", ttlock::PasscodeType::Permanent}, {2, oldCode, ttlock::PasscodeType::Permanent},
        {3, nextCode, ttlock::PasscodeType::Permanent}, {4, "3000004", ttlock::PasscodeType::Permanent},
        {5, "3000005", ttlock::PasscodeType::Permanent}, {6, "3000006", ttlock::PasscodeType::Cyclic},
        {7, "3000007", static_cast<ttlock::PasscodeType>(255)}, {8, "3000008", ttlock::PasscodeType::Permanent}};
    const auto plan = planHardening(codes, labels, metadata, oldCode, true, "3000004");
    TEST_ASSERT_EQUAL_UINT(8, plan.passcodes.size());
    for (size_t i = 0; i < 4; ++i) TEST_ASSERT_FALSE(plan.passcodes[i].remove);
    TEST_ASSERT_TRUE(plan.passcodes[4].remove);
    TEST_ASSERT_TRUE(plan.passcodes[5].remove);
    TEST_ASSERT_FALSE(plan.passcodes[6].remove);
    TEST_ASSERT_TRUE(plan.passcodes[7].remove);
    TEST_ASSERT_EQUAL_INT(static_cast<int>(HardenAdmin::Unresolved), static_cast<int>(plan.admin));
    TEST_ASSERT_FALSE(plan.executable);
}
static void test_only_confirmed_pairing_generated_code_can_rotate() {
    for (const auto source : {AdminProvenance::LegacyUnknown, AdminProvenance::Owner,
                              AdminProvenance::PairingGenerated, AdminProvenance::HardeningGenerated}) {
        metadata.provenance = source;
        const auto plan = planHardening({}, labels, metadata, oldCode, true, oldCode);
        TEST_ASSERT_EQUAL_INT(source == AdminProvenance::PairingGenerated, plan.admin == HardenAdmin::Rotate);
        TEST_ASSERT_TRUE(plan.executable);
    }
    metadata.provenance = AdminProvenance::PairingGenerated;
    TEST_ASSERT_EQUAL_INT(static_cast<int>(HardenAdmin::Unresolved),
        static_cast<int>(planHardening({}, labels, metadata, oldCode, false, oldCode).admin));
}
static void test_pending_candidate_or_old_verdict_never_plans_another_rotation() {
    std::copy(nextCode.begin(), nextCode.end(), metadata.pendingAdminPasscode.begin());
    metadata.pendingProvenance = AdminProvenance::HardeningGenerated;
    const auto accepted = planHardening({}, labels, metadata, oldCode, true, nextCode);
    const auto rejected = planHardening({}, labels, metadata, oldCode, true, oldCode);
    TEST_ASSERT_EQUAL_INT(static_cast<int>(HardenAdmin::ConfirmCandidate), static_cast<int>(accepted.admin));
    TEST_ASSERT_EQUAL_INT(static_cast<int>(HardenAdmin::ConfirmPrevious), static_cast<int>(rejected.admin));
    TEST_ASSERT_TRUE(accepted.executable && rejected.executable);
}
static void test_backup_and_authenticated_current_code_are_execution_prerequisites() {
    metadata.lifecycle = 0;
    TEST_ASSERT_FALSE(planHardening({}, labels, metadata, oldCode, true, oldCode).executable);
    metadata.lifecycle = kBackupBackedUp;
    const HardenPasscode codes[]{{1, "3000001", ttlock::PasscodeType::Permanent}};
    const auto unknown = planHardening(codes, labels, metadata, oldCode, true, {});
    TEST_ASSERT_FALSE(unknown.executable);
    TEST_ASSERT_FALSE(unknown.passcodes[0].remove);
    TEST_ASSERT_FALSE(planHardening({}, labels, metadata, oldCode, true, nextCode).executable);
}
int main() {
    UNITY_BEGIN();
    RUN_TEST(test_managed_and_admin_codes_are_preserved_but_unmanaged_cyclic_codes_are_deleted);
    RUN_TEST(test_only_confirmed_pairing_generated_code_can_rotate);
    RUN_TEST(test_pending_candidate_or_old_verdict_never_plans_another_rotation);
    RUN_TEST(test_backup_and_authenticated_current_code_are_execution_prerequisites);
    return UNITY_END();
}
