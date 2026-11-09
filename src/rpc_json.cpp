// SPDX-License-Identifier: GPL-3.0-or-later
#include "rpc.h"

#include <cstddef>
#include <limits>

#include "esp_heap_caps.h"

namespace rpc {
namespace {

struct alignas(std::max_align_t) JsonAllocation { size_t size; };

void* allocateJsonBytes(size_t size) {
    if (size > std::numeric_limits<size_t>::max() - sizeof(JsonAllocation)) return nullptr;
    auto* allocation = static_cast<JsonAllocation*>(heap_caps_malloc(sizeof(JsonAllocation) + size, MALLOC_CAP_8BIT));
    if (allocation == nullptr) return nullptr;
    allocation->size = size;
    return allocation + 1;
}

void freeJsonBytes(void* pointer) {
    if (pointer == nullptr) return;
    auto* allocation = static_cast<JsonAllocation*>(pointer) - 1;
    const size_t size = sizeof(JsonAllocation) + allocation->size;
    auto* bytes = reinterpret_cast<volatile unsigned char*>(allocation);
    for (size_t i = 0; i < size; ++i) bytes[i] = 0;
    heap_caps_free(allocation);
}

}

void init() {
    cJSON_Hooks hooks{allocateJsonBytes, freeJsonBytes};
    cJSON_InitHooks(&hooks);
}

}
