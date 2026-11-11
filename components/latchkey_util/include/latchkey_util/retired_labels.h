// SPDX-License-Identifier: GPL-3.0-or-later
#pragma once

#include <cstddef>
#include <cstdint>
#include <string>
#include <string_view>
#include <vector>

#include "latchkey_util/label_table.h"

namespace latchkey_util {

inline constexpr size_t kMaxRetiredLabels = 16;
inline constexpr size_t kRetiredLabelsBytes = 2 + kMaxRetiredLabels * (10 + kMaxLabelNameBytes);

struct RetiredLabel {
    char kind = 0;
    uint64_t id = 0;
    std::string name;
};

class RetiredLabels {
public:
    const RetiredLabel* find(char kind, uint64_t id) const;
    bool remember(char kind, uint64_t id, std::string_view name);
    bool remove(char kind, uint64_t id);
    std::vector<uint8_t> encode() const;
    static bool decode(const uint8_t* data, size_t size, RetiredLabels& out);

private:
    std::vector<RetiredLabel> entries_;
};

}
