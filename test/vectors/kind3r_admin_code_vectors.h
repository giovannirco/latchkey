// SPDX-License-Identifier: GPL-3.0-or-later
// What kind3r/ttlock-sdk-js 8c84cda's GetAdminCodeCommand.processData (src/api/Commands/GetAdminCodeCommand.ts:11-23)
// returns for these synthetic 0x65 reply bodies, run under Deno 2.9.8. Written by hand while tools/vectors/ belonged
// to another branch; to be folded into tools/vectors/kind3r_vectors.ts.
#pragma once

#include <cstdint>

namespace vectors::kind3r_admin {

inline constexpr uint8_t kAdminCodeEmpty[] = {0x5a, 0x00};
inline constexpr const char* kAdminCodeEmptyKind3r = "";

inline constexpr uint8_t kAdminCodeTrailed[] = {0x5a, 0x07, 0x33, 0x31, 0x34, 0x31, 0x35, 0x39, 0x32, 0x00, 0x00};
inline constexpr const char* kAdminCodeTrailedKind3r = "3141592";

inline constexpr uint8_t kAdminCodeExact[] = {0x5a, 0x07, 0x33, 0x31, 0x34, 0x31, 0x35, 0x39, 0x32};
inline constexpr const char* kAdminCodeExactKind3r = "31415";

}
