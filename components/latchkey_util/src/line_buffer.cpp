// SPDX-License-Identifier: GPL-3.0-or-later
#include "latchkey_util/line_buffer.h"

#include <utility>

namespace latchkey_util {

LineBuffer::LineBuffer(size_t maxLength, LineHandler onLine, OverflowHandler onOverflow)
    : maxLength_(maxLength), onLine_(std::move(onLine)), onOverflow_(std::move(onOverflow)) {}

void LineBuffer::consume(char* data, size_t length) {
    for (size_t i = 0; i < length; ++i) {
        const char c = data[i];
        static_cast<volatile char*>(data)[i] = 0;
        if (c == '\n' || c == '\r') {
            if (error_.has_value()) {
                const Error error = *error_;
                error_.reset();
                onOverflow_(error);
            } else if (!line_.empty()) {
                onLine_(std::move(line_));
            }
            line_.clear();
            continue;
        }
        if (error_.has_value()) {
            continue;
        }
        if (line_.size() == maxLength_) {
            error_ = Error::TooLong;
            line_.clear();
            continue;
        }
        if (!line_.append(c)) {
            error_ = Error::NoMemory;
            line_.clear();
        }
    }
}

}
