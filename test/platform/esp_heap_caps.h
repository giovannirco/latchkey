// SPDX-License-Identifier: GPL-3.0-or-later
#pragma once

#include <cstddef>
#include <cstdint>

inline constexpr uint32_t MALLOC_CAP_8BIT = 4;
void* heap_caps_malloc(size_t size, uint32_t capabilities);
void heap_caps_free(void* pointer);
