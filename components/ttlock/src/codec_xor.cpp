// SPDX-License-Identifier: GPL-3.0-or-later
// Ported from kind3r/ttlock-sdk-js (GPL-3.0) src/util/CodecUtils.ts, with the lock CRC table.
#include "ttlock/codec_xor.h"

#include "ttlock/crc8.h"

namespace ttlock {

Bytes xorCodec(const Bytes& data, uint8_t seed) {
    const uint8_t lengthByte = static_cast<uint8_t>(data.size());
    const uint8_t mask = seed ^ crc8(&lengthByte, 1);
    Bytes out(data);
    for (uint8_t& byte : out) {
        byte ^= mask;
    }
    return out;
}

}
