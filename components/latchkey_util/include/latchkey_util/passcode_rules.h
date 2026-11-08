// SPDX-License-Identifier: GPL-3.0-or-later
#pragma once

#include <cstddef>
#include <cstdint>
#include <optional>
#include <string>
#include <string_view>
#include <vector>

#include "latchkey_util/label_table.h"

namespace latchkey_util {

struct ListedCode {
    uint64_t id = 0;
    std::string_view code;
};

enum class NewCode : uint8_t {
    Free,
    InUse,
    IdTaken,
};

enum class Target : uint8_t {
    Found,
    Missing,
    Ambiguous,
    AdminCode,
};

NewCode checkNewCode(const std::vector<ListedCode>& listed, std::string_view adminCode, std::string_view code,
                     uint64_t id, std::optional<size_t> replacing);

Target findTarget(const std::vector<ListedCode>& listed, std::string_view adminCode, uint64_t id, size_t& index);

bool isListedCode(const std::vector<ListedCode>& listed, std::string_view code);

bool relabel(LabelTable& labels, uint64_t from, uint64_t to, const std::optional<std::string>& name);

bool isEasyCode(std::string_view code);

}
