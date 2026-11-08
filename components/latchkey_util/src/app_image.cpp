// SPDX-License-Identifier: GPL-3.0-or-later
#include "latchkey_util/app_image.h"

#include <cstdio>
#include <cstring>

namespace latchkey_util {

namespace {

constexpr uint8_t kImageMagic = 0xE9;
constexpr uint8_t kMaxSegments = 16;
constexpr size_t kSegmentCountAt = 1;
constexpr size_t kChipIdAt = 12;
constexpr size_t kDescriptionAt = 32;
constexpr uint32_t kDescriptionMagic = 0xABCD5432;
constexpr size_t kVersionAt = kDescriptionAt + 16;
constexpr size_t kProjectAt = kDescriptionAt + 48;
constexpr size_t kTextField = 32;

struct Chip {
    uint16_t id;
    const char* name;
};

constexpr Chip kChips[] = {
    {0x0000, "esp32"},   {0x0002, "esp32s2"}, {0x0005, "esp32c3"},  {0x0009, "esp32s3"}, {0x000C, "esp32c2"},
    {0x000D, "esp32c6"}, {0x0010, "esp32h2"}, {0x0012, "esp32p4"}, {0x0014, "esp32c61"}, {0x0017, "esp32c5"},
};

uint32_t littleEndian32(const uint8_t* data) {
    return static_cast<uint32_t>(data[0]) | static_cast<uint32_t>(data[1]) << 8 |
           static_cast<uint32_t>(data[2]) << 16 | static_cast<uint32_t>(data[3]) << 24;
}

std::string printable(const uint8_t* field) {
    const auto* text = reinterpret_cast<const char*>(field);
    std::string out(text, strnlen(text, kTextField));
    for (char& c : out) {
        if (c < 0x20 || c > 0x7E) {
            c = '?';
        }
    }
    return out;
}

std::string chipText(uint16_t chipId) {
    const char* name = chipName(chipId);
    if (name != nullptr) {
        return std::string("the ") + name;
    }
    char text[16];
    std::snprintf(text, sizeof(text), "chip 0x%04x", chipId);
    return text;
}

std::string boardText(uint16_t chipId) {
    const char* name = chipName(chipId);
    if (name != nullptr) {
        return std::string("an ") + name;
    }
    char text[16];
    std::snprintf(text, sizeof(text), "chip 0x%04x", chipId);
    return text;
}

}

UploadSize checkUploadSize(size_t imageBytes, size_t slotBytes) {
    if (imageBytes < kMinAppImageBytes) {
        return UploadSize::TooSmall;
    }
    return imageBytes > slotBytes ? UploadSize::TooLarge : UploadSize::Fits;
}

ImageHeadVerdict checkAppImageHead(const uint8_t* data, size_t size, uint16_t chipId, std::string_view project,
                                   AppImageHead& head) {
    if (size < kAppImageHeadBytes || data[0] != kImageMagic || data[kSegmentCountAt] == 0 ||
        data[kSegmentCountAt] > kMaxSegments || littleEndian32(data + kDescriptionAt) != kDescriptionMagic) {
        return ImageHeadVerdict::NotAnImage;
    }
    head.chipId = static_cast<uint16_t>(data[kChipIdAt] | data[kChipIdAt + 1] << 8);
    head.project = printable(data + kProjectAt);
    head.version = printable(data + kVersionAt);
    if (head.chipId != chipId) {
        return ImageHeadVerdict::OtherChip;
    }
    return head.project == project ? ImageHeadVerdict::Ok : ImageHeadVerdict::OtherProject;
}

const char* chipName(uint16_t chipId) {
    for (const Chip& chip : kChips) {
        if (chip.id == chipId) {
            return chip.name;
        }
    }
    return nullptr;
}

std::string appImageProblem(ImageHeadVerdict verdict, const AppImageHead& head, uint16_t boardChipId) {
    switch (verdict) {
        case ImageHeadVerdict::Ok:
            return {};
        case ImageHeadVerdict::NotAnImage:
            return "not an ESP32 app image";
        case ImageHeadVerdict::OtherChip:
            return "this image is for " + chipText(head.chipId) + ", and this board is " + boardText(boardChipId);
        case ImageHeadVerdict::OtherProject:
            return "this image is not Latchkey firmware";
    }
    return {};
}

}
