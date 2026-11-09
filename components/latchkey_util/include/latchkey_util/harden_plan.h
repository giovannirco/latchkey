// SPDX-License-Identifier: GPL-3.0-or-later
#pragma once

#include <span>
#include <string_view>
#include <vector>

#include "latchkey_util/key_restore.h"
#include "latchkey_util/label_table.h"
#include "ttlock/types.h"

namespace latchkey_util {

struct HardenPasscode {
    uint64_t id;
    std::string_view code;
    ttlock::PasscodeType type;
};

enum class HardenAdmin { PreserveUnknown, PreserveOwner, PreserveHardened, Rotate,
                         ConfirmCandidate, ConfirmPrevious, Unresolved };
enum class HardenPreservation { Unmanaged, Managed, Admin, Unknown };
struct HardenPasscodePlan {
    uint64_t id;
    bool remove;
    HardenPreservation reason;
};
struct HardenPlan {
    std::vector<HardenPasscodePlan> passcodes;
    HardenAdmin admin = HardenAdmin::Unresolved;
    bool executable = false;
};

HardenPlan planHardening(std::span<const HardenPasscode> codes, const LabelTable& labels,
                         const LockMetadata& metadata, std::string_view confirmed, bool isConfirmed,
                         std::string_view current);

}
