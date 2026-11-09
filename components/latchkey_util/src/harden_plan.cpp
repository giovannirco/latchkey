// SPDX-License-Identifier: GPL-3.0-or-later
#include "latchkey_util/harden_plan.h"

namespace latchkey_util {
namespace {

HardenAdmin planAdmin(const LockMetadata& metadata, std::string_view confirmed, bool isConfirmed,
                      std::string_view current) {
    if (!ttlock::isPasscode(current)) return HardenAdmin::Unresolved;
    if (metadata.pendingAdminPasscode[0] != 0) {
        if (current == metadata.pendingAdminPasscode.data()) return HardenAdmin::ConfirmCandidate;
        return current == confirmed ? HardenAdmin::ConfirmPrevious : HardenAdmin::Unresolved;
    }
    switch (metadata.provenance) {
        case AdminProvenance::LegacyUnknown: return HardenAdmin::PreserveUnknown;
        case AdminProvenance::Owner: return HardenAdmin::PreserveOwner;
        case AdminProvenance::HardeningGenerated: return HardenAdmin::PreserveHardened;
        case AdminProvenance::PairingGenerated:
            return isConfirmed && current == confirmed ? HardenAdmin::Rotate : HardenAdmin::Unresolved;
    }
    return HardenAdmin::Unresolved;
}

HardenPreservation preserve(const HardenPasscode& code, const LabelTable& labels,
                             const LockMetadata& metadata, std::string_view confirmed,
                             std::string_view current) {
    if (code.code == confirmed || code.code == metadata.pendingAdminPasscode.data() || code.code == current) {
        return HardenPreservation::Admin;
    }
    const Label* label = labels.find(code.id);
    if (label != nullptr && label->managed) return HardenPreservation::Managed;
    if (!ttlock::isPasscode(current) || !ttlock::isPasscode(code.code)) return HardenPreservation::Unknown;
    switch (code.type) {
        case ttlock::PasscodeType::Permanent:
        case ttlock::PasscodeType::Count:
        case ttlock::PasscodeType::Period:
        case ttlock::PasscodeType::Cyclic: return HardenPreservation::Unmanaged;
        default: return HardenPreservation::Unknown;
    }
}

}

HardenPlan planHardening(std::span<const HardenPasscode> codes, const LabelTable& labels,
                         const LockMetadata& metadata, std::string_view confirmed, bool isConfirmed,
                         std::string_view current) {
    HardenPlan plan;
    plan.admin = planAdmin(metadata, confirmed, isConfirmed, current);
    plan.executable = (metadata.lifecycle & kBackupBackedUp) != 0 && plan.admin != HardenAdmin::Unresolved;
    plan.passcodes.reserve(codes.size());
    for (const auto& code : codes) {
        const auto reason = preserve(code, labels, metadata, confirmed, current);
        plan.passcodes.push_back({code.id, reason == HardenPreservation::Unmanaged, reason});
    }
    return plan;
}

}
