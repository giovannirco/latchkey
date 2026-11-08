// SPDX-License-Identifier: GPL-3.0-or-later
#pragma once

#include <cstddef>
#include <functional>
#include <string>
#include <string_view>

namespace latchkey_util {

class LineBuffer {
public:
    using LineHandler = std::function<void(std::string_view line)>;
    using OverflowHandler = std::function<void()>;

    LineBuffer(size_t maxLength, LineHandler onLine, OverflowHandler onOverflow);

    void feed(const char* data, size_t length);

private:
    size_t maxLength_;
    LineHandler onLine_;
    OverflowHandler onOverflow_;
    std::string line_;
    bool overflowing_ = false;
};

}
