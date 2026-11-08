// SPDX-License-Identifier: GPL-3.0-or-later
#include "latchkey_util/seed_table.h"

#include "big_endian.h"

namespace latchkey_util {

namespace {

constexpr uint8_t kVersion = 1;
constexpr size_t kHeaderSize = 4;
constexpr size_t kSeedSize = 10;

}

std::array<uint8_t, kSeedTableSize> encodeSeedTable(const SeedTable& table) {
    std::array<uint8_t, kSeedTableSize> out{};
    out[0] = kVersion;
    out[1] = table.confirmed ? 1 : 0;
    big_endian::write(out.data() + 2, table.year, 2);
    for (size_t i = 0; i < table.seeds.size(); ++i) {
        uint8_t* seed = out.data() + kHeaderSize + i * kSeedSize;
        big_endian::write(seed, table.seeds[i].code, 2);
        big_endian::write(seed + 2, table.seeds[i].secret, 8);
    }
    return out;
}

bool decodeSeedTable(const uint8_t* data, size_t size, SeedTable& out) {
    if (data == nullptr || size != kSeedTableSize || data[0] != kVersion || data[1] > 1) {
        return false;
    }
    SeedTable table;
    table.confirmed = data[1] == 1;
    table.year = static_cast<uint16_t>(big_endian::read(data + 2, 2));
    for (size_t i = 0; i < table.seeds.size(); ++i) {
        const uint8_t* seed = data + kHeaderSize + i * kSeedSize;
        table.seeds[i].code = static_cast<uint16_t>(big_endian::read(seed, 2));
        table.seeds[i].secret = big_endian::read(seed + 2, 8);
    }
    out = table;
    return true;
}

}
