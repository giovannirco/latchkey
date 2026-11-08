// SPDX-License-Identifier: GPL-3.0-or-later
#pragma once

#include <algorithm>
#include <cstddef>
#include <deque>
#include <optional>
#include <utility>

namespace latchkey_util {

template <typename T, typename Disposable>
std::optional<T> pushBounded(std::deque<T>& queue, T item, size_t capacity, Disposable disposable) {
    std::optional<T> dropped;
    if (!queue.empty() && queue.size() >= capacity) {
        auto victim = std::find_if(queue.begin(), queue.end(), disposable);
        if (victim == queue.end()) {
            victim = queue.begin();
        }
        dropped = std::move(*victim);
        queue.erase(victim);
    }
    queue.push_back(std::move(item));
    return dropped;
}

}
