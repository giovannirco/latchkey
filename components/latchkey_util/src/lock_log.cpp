// SPDX-License-Identifier: GPL-3.0-or-later
#include "latchkey_util/lock_log.h"

#include <algorithm>
#include <cstdio>

#include "latchkey_util/lock_time.h"

namespace latchkey_util {

namespace {

void appendNumber(std::string& out, long long value) {
    char text[24];
    std::snprintf(text, sizeof(text), "%lld", value);
    out += text;
}

void appendEntry(std::string& out, const ttlock::LogEntry& entry, int32_t lockUtcOffsetSeconds) {
    out += "{\"seq\":";
    appendNumber(out, entry.recordNumber);
    out += ",\"time\":";
    int64_t local = 0;
    if (localSecondsOf(entry.time, local)) {
        appendNumber(out, local - lockUtcOffsetSeconds);
    } else {
        out += "null";
    }
    out += ",\"type\":";
    appendNumber(out, entry.type);
    out += ",\"battery\":";
    appendNumber(out, entry.battery);
    out += '}';
}

bool utcOf(const ttlock::LogEntry& entry, int32_t lockUtcOffsetSeconds, int64_t& out) {
    int64_t local = 0;
    if (!localSecondsOf(entry.time, local)) {
        return false;
    }
    out = local - lockUtcOffsetSeconds;
    return true;
}

}

std::string logEntriesJson(const std::vector<ttlock::LogEntry>& entries, int32_t lockUtcOffsetSeconds) {
    return logEntriesJson(entries, WatchState{}, lockUtcOffsetSeconds);
}

std::string logEntriesJson(const std::vector<ttlock::LogEntry>& entries, const WatchState& state,
                           int32_t unknownOffset) {
    std::string out = "[";
    for (size_t i = 0; i < entries.size(); ++i) {
        if (i > 0) {
            out += ',';
        }
        appendEntry(out, entries[i], recordOffset(state, entries[i].recordNumber, unknownOffset));
    }
    out += ']';
    return out;
}

LogStep stepLog(const WatchState& state, const ttlock::LogPage& page, int32_t lockUtcOffsetSeconds) {
    LogStep step;
    step.state = state;
    uint32_t newest = state.lastUtc;
    uint16_t highest = 0;
    for (size_t i = 0; i < page.entries.size(); ++i) {
        const ttlock::LogEntry& entry = page.entries[i];
        int64_t utc = 0;
        const bool datable = utcOf(entry, recordOffset(state, entry.recordNumber, lockUtcOffsetSeconds), utc);
        const bool restarted = datable && utc > static_cast<int64_t>(state.lastUtc);
        if (entry.recordNumber < state.cursor && !restarted) {
            continue;
        }
        step.fresh.push_back(i);
        highest = std::max(highest, entry.recordNumber);
        if (datable && utc > static_cast<int64_t>(newest)) {
            newest = static_cast<uint32_t>(utc);
        }
    }
    if (step.fresh.empty()) {
        return step;
    }
    step.state.cursor = page.sequence != 0 ? page.sequence : static_cast<uint16_t>(highest + 1);
    step.state.lastUtc = newest;
    step.more = page.sequence != 0;
    return step;
}

bool LogEndSearch::done() const { return low_ > high_; }

uint16_t LogEndSearch::slot() const { return static_cast<uint16_t>((low_ + high_) / 2); }

void LogEndSearch::read(const ttlock::LogPage& page, int32_t lockUtcOffsetSeconds) {
    const uint16_t asked = slot();
    ++reads_;
    const ttlock::LogEntry* found = nullptr;
    for (const ttlock::LogEntry& entry : page.entries) {
        if (entry.recordNumber >= asked && (found == nullptr || entry.recordNumber > found->recordNumber)) {
            found = &entry;
        }
    }
    if (found == nullptr) {
        high_ = asked - 1;
        return;
    }
    cursor_ = page.sequence > found->recordNumber ? page.sequence : static_cast<uint16_t>(found->recordNumber + 1);
    int64_t utc = 0;
    lastUtc_ = utcOf(*found, lockUtcOffsetSeconds, utc) && utc > 0 ? static_cast<uint32_t>(utc) : 0;
    low_ = asked + 1;
}

WatchState LogEndSearch::baseline(const WatchState& state) const {
    WatchState out = state;
    out.baselined = true;
    out.cursor = cursor_;
    out.lastUtc = lastUtc_;
    return out;
}

size_t LogEndSearch::reads() const { return reads_; }

}
