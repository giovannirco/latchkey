// SPDX-License-Identifier: GPL-3.0-or-later
#pragma once

#include <string>

#include "ttlock/bytes.h"
#include "ttlock/frame.h"

namespace ttlock {

struct Advert {
    LockVersion version;
    bool paired = false;
    bool locked = false;
    bool hasLockState = false;
    int battery = -1;
    std::string mac;
};

bool parseAdvert(const Bytes& manufacturerData, Advert& out);

}
