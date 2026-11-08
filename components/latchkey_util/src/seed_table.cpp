// SPDX-License-Identifier: GPL-3.0-or-later
#include "latchkey_util/seed_table.h"

namespace latchkey_util {

namespace {

constexpr uint8_t kVersion = 1;
constexpr size_t kHeaderSize = 4;
constexpr size_t kSeedSize = 10;

void writeBe(uint8_t* out, uint64_t value, size_t width) {
    for (size_t i = 0; i < width; ++i) {
        out[i] = static_cast<uint8_t>(value >> (8 * (width - 1 - i)));
    }
}

uint64_t readBe(const uint8_t* data, size_t width) {
    uint64_t value = 0;
    for (size_t i = 0; i < width; ++i) {
        value = value << 8 | data[i];
    }
    return value;
}

}

std::array<uint8_t, kSeedTableSize> encodeSeedTable(const SeedTable& table) {
    std::array<uint8_t, kSeedTableSize> out{};
    out[0] = kVersion;
    out[1] = table.confirmed ? 1 : 0;
    writeBe(out.data() + 2, table.year, 2);
    for (size_t i = 0; i < table.seeds.size(); ++i) {
        uint8_t* seed = out.data() + kHeaderSize + i * kSeedSize;
        writeBe(seed, table.seeds[i].code, 2);
        writeBe(seed + 2, table.seeds[i].secret, 8);
    }
    return out;
}

bool decodeSeedTable(const uint8_t* data, size_t size, SeedTable& out) {
    if (data == nullptr || size != kSeedTableSize || data[0] != kVersion || data[1] > 1) {
        return false;
    }
    SeedTable table;
    table.confirmed = data[1] == 1;
    table.year = static_cast<uint16_t>(readBe(data + 2, 2));
    for (size_t i = 0; i < table.seeds.size(); ++i) {
        const uint8_t* seed = data + kHeaderSize + i * kSeedSize;
        table.seeds[i].code = static_cast<uint16_t>(readBe(seed, 2));
        table.seeds[i].secret = readBe(seed + 2, 8);
    }
    out = table;
    return true;
}

}
