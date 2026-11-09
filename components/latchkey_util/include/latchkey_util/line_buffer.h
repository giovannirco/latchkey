// SPDX-License-Identifier: GPL-3.0-or-later
#pragma once

#include <cstddef>
#include <functional>
#include <optional>

#include "latchkey_util/rpc_text.h"

namespace latchkey_util {

class LineBuffer {
public:
    enum class Error { TooLong, NoMemory };
    using LineHandler = std::function<void(RpcText line)>;
    using OverflowHandler = std::function<void(Error)>;

    LineBuffer(size_t maxLength, LineHandler onLine, OverflowHandler onOverflow);

    void consume(char* data, size_t length);

private:
    size_t maxLength_;
    LineHandler onLine_;
    OverflowHandler onOverflow_;
    RpcText line_;
    std::optional<Error> error_;
};

}
