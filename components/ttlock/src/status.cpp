// SPDX-License-Identifier: GPL-3.0-or-later
#include "ttlock/status.h"

namespace ttlock {

const char* toString(Status status) {
    switch (status) {
        case Status::Ok:
            return "ok";
        case Status::Timeout:
            return "timeout";
        case Status::Disconnected:
            return "disconnected";
        case Status::BadResponse:
            return "bad_response";
        case Status::BadCrc:
            return "bad_crc";
        case Status::LockError:
            return "lock_error";
        case Status::Unsupported:
            return "unsupported";
        case Status::NotPaired:
            return "not_paired";
        case Status::PairIncomplete:
            return "pair_incomplete";
        case Status::Busy:
            return "busy";
        case Status::InvalidArgument:
            return "invalid_argument";
        case Status::TimeUnsynced:
            return "time_unsynced";
    }
    return "unknown";
}

}
