// SPDX-License-Identifier: GPL-3.0-or-later
#pragma once

#include <cstddef>
#include <cstdint>

inline constexpr uint32_t MALLOC_CAP_8BIT = 4;
inline constexpr uint32_t MALLOC_CAP_INTERNAL = 1;
void* heap_caps_malloc(size_t size, uint32_t capabilities);
void heap_caps_free(void* pointer);
size_t heap_caps_get_free_size(uint32_t capabilities);
size_t heap_caps_get_largest_free_block(uint32_t capabilities);
