// SPDX-License-Identifier: GPL-3.0-or-later
#pragma once

#include <cstddef>
#include <cstdint>
#include <optional>
#include <string>
#include <vector>

#include "latchkey_util/weekly_window.h"

namespace latchkey_util {

inline constexpr size_t kMaxLabels = 32;
inline constexpr size_t kMaxLabelNameCodePoints = 24;
inline constexpr size_t kMaxLabelNameBytes = 48;

struct Label {
    uint64_t id = 0;
    bool managed = false;
    std::string name;
    std::optional<WeeklyWindow> cycle;
};

class LabelTable {
public:
    const Label* find(uint64_t id) const;
    bool hasRoomFor(uint64_t id) const;
    bool put(Label label);
    bool remove(uint64_t id);
    bool keepOnly(const std::vector<uint64_t>& ids);
    size_t size() const;
    const std::vector<Label>& entries() const;
    std::vector<uint8_t> encode() const;
    static bool decode(const uint8_t* data, size_t size, LabelTable& out);

private:
    std::vector<Label> labels_;
};

}
