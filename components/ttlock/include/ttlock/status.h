// SPDX-License-Identifier: GPL-3.0-or-later
#pragma once

#include <cstdint>

namespace ttlock {

enum class Status : uint8_t {
    Ok,
    Timeout,
    Disconnected,
    BadResponse,
    BadCrc,
    LockError,
    Unsupported,
    NotPaired,
    PairIncomplete,
    Busy,
    InvalidArgument,
    TimeUnsynced,
};

const char* toString(Status status);

}
