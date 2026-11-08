// SPDX-License-Identifier: GPL-3.0-or-later
#pragma once

#include <cstdint>
#include <functional>

#include "ttlock/types.h"

namespace latchkey_util {

using UtcOffsetAt = std::function<int32_t(int64_t utcSeconds)>;

bool localSecondsOf(const ttlock::LockTime& time, int64_t& out);

ttlock::LockTime lockTimeAt(int64_t utcSeconds, const UtcOffsetAt& offsetAt);

bool utcOfLockTime(const ttlock::LockTime& time, const UtcOffsetAt& offsetAt, int64_t& out);

bool lockValidity(int64_t startUtc, int64_t endUtc, const UtcOffsetAt& offsetAt, ttlock::Validity& out);

bool isPermanent(const ttlock::Validity& validity);

}
