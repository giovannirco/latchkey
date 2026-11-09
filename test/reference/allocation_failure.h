// SPDX-License-Identifier: GPL-3.0-or-later
#pragma once

#include <array>
#include <cstddef>
#include <cstdint>
#include <cstdlib>
#include <new>

namespace allocation_failure {

struct Allocation {
    void* data = nullptr;
    size_t size = 0;
};

struct WipeCheck {
    const uint8_t* data = nullptr;
    size_t size = 0;
};

inline std::array<Allocation, 64> allocations{};
inline std::array<WipeCheck, 16> wipeChecks{};
inline size_t failAt = 0;
inline size_t attempts = 0;
inline size_t checkedWipes = 0;
inline bool wiped = true;
inline void (*onChange)() = nullptr;

inline void reset() {
    failAt = attempts = checkedWipes = 0;
    wipeChecks = {};
    wiped = true;
    onChange = nullptr;
}

inline void failNext() {
    attempts = 0;
    failAt = 1;
}

inline void resume() { failAt = 0; }

inline size_t live() {
    size_t count = 0;
    for (const auto& allocation : allocations) if (allocation.data != nullptr) ++count;
    return count;
}

inline void expectWiped(const uint8_t* data, size_t size) {
    for (auto& check : wipeChecks) {
        if (check.data == nullptr) {
            check = {data, size};
            return;
        }
    }
    std::abort();
}

inline void* allocate(size_t size) noexcept {
    if (++attempts == failAt) return nullptr;
#ifdef LATCHKEY_TRACK_SCALAR_ALLOCATIONS
    void* data = std::malloc(size);
#else
    void* data = ::operator new(size, std::nothrow);
#endif
    if (data == nullptr) return nullptr;
    for (auto& allocation : allocations) {
        if (allocation.data == nullptr) {
            allocation = {data, size};
            if (onChange) onChange();
            return data;
        }
    }
    std::abort();
}

inline void release(void* data) noexcept {
    for (auto& allocation : allocations) {
        if (allocation.data != data || data == nullptr) continue;
        const auto address = reinterpret_cast<uintptr_t>(data);
        for (auto& check : wipeChecks) {
            const auto checked = reinterpret_cast<uintptr_t>(check.data);
            if (check.data == nullptr || checked < address || checked - address > allocation.size ||
                check.size > allocation.size - (checked - address)) continue;
            for (size_t i = 0; i < check.size; ++i) wiped = wiped && check.data[i] == 0;
            ++checkedWipes;
            check = {};
        }
        allocation = {};
        if (onChange) onChange();
        break;
    }
#ifdef LATCHKEY_TRACK_SCALAR_ALLOCATIONS
    std::free(data);
#else
    ::operator delete(data);
#endif
}

}

#ifdef LATCHKEY_TRACK_SCALAR_ALLOCATIONS
void* operator new(size_t size, const std::nothrow_t&) noexcept { return allocation_failure::allocate(size); }
void operator delete(void* data) noexcept { allocation_failure::release(data); }
void operator delete(void* data, size_t) noexcept { allocation_failure::release(data); }
void operator delete(void* data, const std::nothrow_t&) noexcept { allocation_failure::release(data); }
#endif

void* operator new[](size_t size) { return ::operator new(size); }

void* operator new[](size_t size, const std::nothrow_t&) noexcept { return allocation_failure::allocate(size); }

void operator delete[](void* data) noexcept { allocation_failure::release(data); }

void operator delete[](void* data, size_t) noexcept { allocation_failure::release(data); }

void operator delete[](void* data, const std::nothrow_t&) noexcept { allocation_failure::release(data); }
