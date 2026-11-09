// SPDX-License-Identifier: GPL-3.0-or-later
#pragma once

#include <array>
#include <cstddef>
#include <cstdint>

#include "ttlock/types.h"

namespace latchkey_util {

inline constexpr size_t kSeedTableSize = 4 + ttlock::kCodeSecretCount * 10;

struct SeedTable {
    ~SeedTable();
    uint16_t year = 0;
    bool confirmed = false;
    std::array<ttlock::CodeSecret, ttlock::kCodeSecretCount> seeds{};
};

std::array<uint8_t, kSeedTableSize> encodeSeedTable(const SeedTable& table);

bool decodeSeedTable(const uint8_t* data, size_t size, SeedTable& out);

}
