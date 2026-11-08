// SPDX-License-Identifier: GPL-3.0-or-later
#pragma once

#include <cstddef>
#include <cstdint>
#include <optional>
#include <string>
#include <string_view>

#include "latchkey_util/weekly_window.h"

namespace latchkey_util {

inline constexpr size_t kListHeadroomBytes = 16384;
inline constexpr size_t kListCopies = 3;

struct UtcWindow {
    int64_t start = 0;
    int64_t end = 0;
};

struct PasscodeView {
    std::string_view id;
    std::string_view type;
    std::string_view name;
    std::optional<UtcWindow> window;
    bool managed = false;
    std::string_view code;
};

struct CredentialView {
    uint64_t id = 0;
    std::string_view name;
    std::optional<UtcWindow> window;
    std::optional<WeeklyWindow> cycle;
};

void appendJsonString(std::string& out, std::string_view value);

void appendPasscodeJson(std::string& out, const PasscodeView& view);

void appendCredentialJson(std::string& out, const CredentialView& view);

size_t passcodeJsonBound(size_t nameBytes);

size_t credentialJsonBound(size_t nameBytes);

bool listFitsInHeap(size_t textBytes, size_t freeBytes, size_t largestBlock);

}
