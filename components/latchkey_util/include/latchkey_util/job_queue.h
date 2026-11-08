// SPDX-License-Identifier: GPL-3.0-or-later
#pragma once

#include <cstddef>
#include <cstdint>
#include <deque>
#include <optional>
#include <utility>
#include <vector>

namespace latchkey_util {

template <typename Job>
class JobQueue {
public:
    static constexpr uint32_t kWaitLimitMs = 60000;
    static constexpr size_t kDefaultCapacity = 8;

    explicit JobQueue(size_t capacity = kDefaultCapacity) : capacity_(capacity) {}

    bool push(Job job, uint32_t nowMs) {
        if (entries_.size() >= capacity_) {
            return false;
        }
        entries_.push_back(Entry{std::move(job), nowMs});
        return true;
    }

    std::optional<Job> pop(uint32_t nowMs) {
        for (auto entry = entries_.begin(); entry != entries_.end(); ++entry) {
            if (!expired(*entry, nowMs)) {
                std::optional<Job> job(std::move(entry->job));
                entries_.erase(entry);
                return job;
            }
        }
        return std::nullopt;
    }

    std::vector<Job> expire(uint32_t nowMs) {
        std::vector<Job> late;
        for (auto entry = entries_.begin(); entry != entries_.end();) {
            if (expired(*entry, nowMs)) {
                late.push_back(std::move(entry->job));
                entry = entries_.erase(entry);
            } else {
                ++entry;
            }
        }
        return late;
    }

    size_t size() const { return entries_.size(); }

    bool empty() const { return entries_.empty(); }

private:
    struct Entry {
        Job job;
        uint32_t enqueuedMs;
    };

    static bool expired(const Entry& entry, uint32_t nowMs) {
        return static_cast<uint32_t>(nowMs - entry.enqueuedMs) > kWaitLimitMs;
    }

    std::deque<Entry> entries_;
    size_t capacity_;
};

}
