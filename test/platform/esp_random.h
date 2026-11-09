// SPDX-License-Identifier: GPL-3.0-or-later
#pragma once

#include <cstdint>
#include <cstddef>

inline uint32_t esp_random() { return 1; }
inline void esp_fill_random(void* output, size_t size) {
    auto* bytes = static_cast<uint8_t*>(output);
    for (size_t i = 0; i < size; ++i) bytes[i] = static_cast<uint8_t>(i + 1);
}
