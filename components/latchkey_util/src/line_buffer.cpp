// SPDX-License-Identifier: GPL-3.0-or-later
#include "latchkey_util/line_buffer.h"

#include <utility>

namespace latchkey_util {

LineBuffer::LineBuffer(size_t maxLength, LineHandler onLine, OverflowHandler onOverflow)
    : maxLength_(maxLength), onLine_(std::move(onLine)), onOverflow_(std::move(onOverflow)) {
    line_.reserve(maxLength_);
}

void LineBuffer::feed(const char* data, size_t length) {
    for (size_t i = 0; i < length; ++i) {
        const char c = data[i];
        if (c == '\n' || c == '\r') {
            if (overflowing_) {
                overflowing_ = false;
                onOverflow_();
            } else if (!line_.empty()) {
                onLine_(line_);
            }
            line_.clear();
            continue;
        }
        if (overflowing_) {
            continue;
        }
        if (line_.size() == maxLength_) {
            overflowing_ = true;
            line_.clear();
            continue;
        }
        line_ += c;
    }
}

}
