// SPDX-License-Identifier: GPL-3.0-or-later
#pragma once

#include <cstdint>

struct ip_event_got_ip_t {
    struct { struct { uint32_t addr; } ip; } ip_info;
};
