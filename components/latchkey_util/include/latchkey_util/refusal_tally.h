// SPDX-License-Identifier: GPL-3.0-or-later
#pragma once

#include <cstdint>
#include <string>
#include <string_view>
#include <vector>

namespace latchkey_util {

struct RefusalCount {
    std::string kind;
    uint32_t count = 0;
};

class RefusalTally {
public:
    explicit RefusalTally(int64_t windowMs);

    void note(std::string_view kind, uint32_t count = 1);

    std::vector<RefusalCount> due(int64_t nowMs);

private:
    struct Entry {
        std::string kind;
        uint32_t pending = 0;
        bool reported = false;
        int64_t reportedMs = 0;
    };

    int64_t windowMs_;
    std::vector<Entry> entries_;
};

}
