// SPDX-License-Identifier: GPL-3.0-or-later
#include "latchkey_util/passcode_type.h"

namespace latchkey_util {

namespace {

struct TypeName {
    ttlock::PasscodeType type;
    const char* name;
};

constexpr TypeName kTypeNames[] = {
    {ttlock::PasscodeType::Permanent, "permanent"},
    {ttlock::PasscodeType::Count, "one_time"},
    {ttlock::PasscodeType::Period, "timed"},
    {ttlock::PasscodeType::Cyclic, "cyclic"},
};

}

const char* passcodeTypeName(ttlock::PasscodeType type) {
    for (const TypeName& entry : kTypeNames) {
        if (entry.type == type) {
            return entry.name;
        }
    }
    return "unknown";
}

bool passcodeTypeOf(std::string_view name, ttlock::PasscodeType& out) {
    for (const TypeName& entry : kTypeNames) {
        if (name == entry.name) {
            out = entry.type;
            return true;
        }
    }
    return false;
}

}
