// SPDX-License-Identifier: GPL-3.0-or-later
#pragma once

#include <cstddef>

inline void mbedtls_platform_zeroize(void* data, size_t length) {
    auto* bytes = static_cast<volatile unsigned char*>(data);
    while (length-- > 0) *bytes++ = 0;
}
