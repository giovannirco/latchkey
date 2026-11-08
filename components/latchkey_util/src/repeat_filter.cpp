// SPDX-License-Identifier: GPL-3.0-or-later
#include "latchkey_util/repeat_filter.h"

namespace latchkey_util {

RepeatFilter::RepeatFilter(uint32_t windowMs) : windowMs_(windowMs) {}

void RepeatFilter::note(std::string_view key, uint32_t nowMs) {
    key_.assign(key.data(), key.size());
    notedMs_ = nowMs;
    noted_ = true;
}

bool RepeatFilter::repeats(std::string_view key, uint32_t nowMs) const {
    return noted_ && key == key_ && static_cast<uint32_t>(nowMs - notedMs_) <= windowMs_;
}

}
