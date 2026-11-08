// SPDX-License-Identifier: GPL-3.0-or-later
#include "latchkey_util/passcode_rules.h"

#include <utility>

namespace latchkey_util {

namespace {

bool isStep(std::string_view code, int step) {
    for (size_t i = 1; i < code.size(); ++i) {
        if (code[i] - code[i - 1] != step) {
            return false;
        }
    }
    return true;
}

}

NewCode checkNewCode(const std::vector<ListedCode>& listed, std::string_view adminCode, std::string_view code,
                     uint64_t id, std::optional<size_t> replacing) {
    if (!adminCode.empty() && code == adminCode) {
        return NewCode::InUse;
    }
    NewCode verdict = NewCode::Free;
    for (size_t i = 0; i < listed.size(); ++i) {
        if (replacing.has_value() && *replacing == i) {
            continue;
        }
        if (listed[i].code == code) {
            return NewCode::InUse;
        }
        if (listed[i].id == id) {
            verdict = NewCode::IdTaken;
        }
    }
    return verdict;
}

Target findTarget(const std::vector<ListedCode>& listed, std::string_view adminCode, uint64_t id, size_t& index) {
    std::optional<size_t> found;
    for (size_t i = 0; i < listed.size(); ++i) {
        if (listed[i].id != id) {
            continue;
        }
        if (found.has_value()) {
            return Target::Ambiguous;
        }
        found = i;
    }
    if (!found.has_value()) {
        return Target::Missing;
    }
    index = *found;
    return !adminCode.empty() && listed[*found].code == adminCode ? Target::AdminCode : Target::Found;
}

bool isListedCode(const std::vector<ListedCode>& listed, std::string_view code) {
    for (const ListedCode& entry : listed) {
        if (entry.code == code) {
            return true;
        }
    }
    return false;
}

bool relabel(LabelTable& labels, uint64_t from, uint64_t to, const std::optional<std::string>& name) {
    const Label* old = labels.find(from);
    Label label = old != nullptr ? *old : Label{};
    const bool existed = old != nullptr;
    label.id = to;
    if (name.has_value()) {
        label.name = *name;
    }
    const bool saysSomething = label.managed || !label.name.empty() || label.cycle.has_value();
    if (saysSomething && !existed && !labels.hasRoomFor(to)) {
        return false;
    }
    LabelTable changed = labels;
    changed.remove(from);
    if (!changed.put(std::move(label))) {
        return false;
    }
    labels = std::move(changed);
    return true;
}

bool isEasyCode(std::string_view code) {
    if (code.empty()) {
        return false;
    }
    return isStep(code, 0) || isStep(code, 1) || isStep(code, -1);
}

}
