// SPDX-License-Identifier: GPL-3.0-or-later
#pragma once

#include <cstddef>

namespace zeroize_fixture {
inline void (*observe)(void*, size_t) = nullptr;
}

inline void mbedtls_platform_zeroize(void* data, size_t length) {
    if (zeroize_fixture::observe != nullptr) zeroize_fixture::observe(data, length);
    auto* bytes = static_cast<volatile unsigned char*>(data);
    while (length-- > 0) *bytes++ = 0;
}
