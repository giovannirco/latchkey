// SPDX-License-Identifier: GPL-3.0-or-later
#pragma once

#include <cstdint>
#include <string_view>

namespace latchkey_util {

bool parseIpv4(std::string_view text, uint32_t& address);

bool isNetmask(uint32_t mask);

bool isStaticIpv4(uint32_t address, uint32_t gateway, uint32_t netmask);

}
