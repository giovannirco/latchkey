// SPDX-License-Identifier: GPL-3.0-or-later
#pragma once

#include <cstddef>
#include <cstdint>
#include <string>
#include <string_view>

namespace latchkey_util {

inline constexpr size_t kAppImageHeadBytes = 288;
inline constexpr size_t kMinAppImageBytes = 64 * 1024;

enum class UploadSize : uint8_t {
    Fits,
    TooSmall,
    TooLarge,
};

UploadSize checkUploadSize(size_t imageBytes, size_t slotBytes);

struct AppImageHead {
    uint16_t chipId = 0;
    std::string project;
    std::string version;
    std::string elfSha256;
};

enum class ImageHeadVerdict : uint8_t {
    Ok,
    NotAnImage,
    OtherChip,
    OtherProject,
};

ImageHeadVerdict checkAppImageHead(const uint8_t* data, size_t size, uint16_t chipId, std::string_view project,
                                   AppImageHead& head);

const char* chipName(uint16_t chipId);

std::string appImageProblem(ImageHeadVerdict verdict, const AppImageHead& head, uint16_t boardChipId);

}
