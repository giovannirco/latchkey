// SPDX-License-Identifier: GPL-3.0-or-later
#pragma once

#include <cstddef>
#include <cstdint>

#include "latchkey_util/log_ring.h"

namespace logs {

using Cursor = latchkey_util::LogRing::Cursor;

struct Stats {
    size_t lines = 0;
    size_t capacity = 0;
    uint32_t withheld = 0;
};

void capture(const char* text, size_t length, bool cut);

Cursor oldestCursor();

Cursor after(uint32_t seq);

Cursor newest(size_t count, latchkey_util::LogLevel threshold);

bool read(Cursor& cursor, latchkey_util::LogLevel threshold, latchkey_util::LogEntry& out, uint32_t& skipped);

uint32_t oldest();

Stats stats();

latchkey_util::LogTimes timesOf(const latchkey_util::LogEntry& entry);

}
