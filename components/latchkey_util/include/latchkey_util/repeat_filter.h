// SPDX-License-Identifier: GPL-3.0-or-later
#pragma once

#include <cstdint>
#include <string>
#include <string_view>

namespace latchkey_util {

class RepeatFilter {
public:
    explicit RepeatFilter(uint32_t windowMs);

    void note(std::string_view key, uint32_t nowMs);

    bool repeats(std::string_view key, uint32_t nowMs) const;

private:
    uint32_t windowMs_;
    std::string key_;
    uint32_t notedMs_ = 0;
    bool noted_ = false;
};

}
