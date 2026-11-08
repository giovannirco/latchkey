// SPDX-License-Identifier: GPL-3.0-or-later
#include <unity.h>

#include <array>
#include <cstdint>
#include <cstring>
#include <string>

#include "latchkey_util/app_image.h"

void setUp() {}

void tearDown() {}

namespace {

constexpr uint16_t kEsp32 = 0x0000;
constexpr uint16_t kEsp32s3 = 0x0009;
constexpr size_t kSlot = 0x1E0000;

using Head = std::array<uint8_t, latchkey_util::kAppImageHeadBytes>;

Head head(uint16_t chip, const char* project, const char* version) {
    Head bytes{};
    bytes[0] = 0xE9;
    bytes[1] = 6;
    bytes[12] = static_cast<uint8_t>(chip & 0xFF);
    bytes[13] = static_cast<uint8_t>(chip >> 8);
    const uint8_t magic[] = {0x32, 0x54, 0xCD, 0xAB};
    std::memcpy(bytes.data() + 32, magic, sizeof(magic));
    std::memcpy(bytes.data() + 48, version, std::strlen(version));
    std::memcpy(bytes.data() + 80, project, std::strlen(project));
    return bytes;
}

latchkey_util::ImageHeadVerdict check(const Head& bytes, latchkey_util::AppImageHead& parsed,
                                      size_t size = latchkey_util::kAppImageHeadBytes) {
    return latchkey_util::checkAppImageHead(bytes.data(), size, kEsp32, "latchkey", parsed);
}

}

static void test_an_upload_must_hold_at_least_64_kib() {
    TEST_ASSERT_EQUAL(latchkey_util::UploadSize::TooSmall, latchkey_util::checkUploadSize(0, kSlot));
    TEST_ASSERT_EQUAL(latchkey_util::UploadSize::TooSmall, latchkey_util::checkUploadSize(64 * 1024 - 1, kSlot));
    TEST_ASSERT_EQUAL(latchkey_util::UploadSize::Fits, latchkey_util::checkUploadSize(64 * 1024, kSlot));
}

static void test_an_upload_must_fit_the_slot() {
    TEST_ASSERT_EQUAL(latchkey_util::UploadSize::Fits, latchkey_util::checkUploadSize(kSlot, kSlot));
    TEST_ASSERT_EQUAL(latchkey_util::UploadSize::TooLarge, latchkey_util::checkUploadSize(kSlot + 1, kSlot));
}

static void test_a_latchkey_head_for_this_chip_passes_and_names_its_version() {
    latchkey_util::AppImageHead parsed;
    TEST_ASSERT_EQUAL(latchkey_util::ImageHeadVerdict::Ok, check(head(kEsp32, "latchkey", "0.2.0"), parsed));
    TEST_ASSERT_EQUAL_UINT16(kEsp32, parsed.chipId);
    TEST_ASSERT_EQUAL_STRING("latchkey", parsed.project.c_str());
    TEST_ASSERT_EQUAL_STRING("0.2.0", parsed.version.c_str());
}

static void test_fewer_bytes_than_the_head_are_not_an_image() {
    latchkey_util::AppImageHead parsed;
    const Head bytes = head(kEsp32, "latchkey", "0.2.0");
    TEST_ASSERT_EQUAL(latchkey_util::ImageHeadVerdict::NotAnImage,
                      check(bytes, parsed, latchkey_util::kAppImageHeadBytes - 1));
}

static void test_a_wrong_magic_byte_is_not_an_image() {
    latchkey_util::AppImageHead parsed;
    Head bytes = head(kEsp32, "latchkey", "0.2.0");
    bytes[0] = 0x50;
    TEST_ASSERT_EQUAL(latchkey_util::ImageHeadVerdict::NotAnImage, check(bytes, parsed));
}

static void test_a_segment_count_outside_1_to_16_is_not_an_image() {
    latchkey_util::AppImageHead parsed;
    Head bytes = head(kEsp32, "latchkey", "0.2.0");
    bytes[1] = 0;
    TEST_ASSERT_EQUAL(latchkey_util::ImageHeadVerdict::NotAnImage, check(bytes, parsed));
    bytes[1] = 17;
    TEST_ASSERT_EQUAL(latchkey_util::ImageHeadVerdict::NotAnImage, check(bytes, parsed));
    bytes[1] = 16;
    TEST_ASSERT_EQUAL(latchkey_util::ImageHeadVerdict::Ok, check(bytes, parsed));
}

static void test_a_head_without_an_app_description_is_not_an_image() {
    latchkey_util::AppImageHead parsed;
    Head bytes = head(kEsp32, "latchkey", "0.2.0");
    bytes[35] = 0xAC;
    TEST_ASSERT_EQUAL(latchkey_util::ImageHeadVerdict::NotAnImage, check(bytes, parsed));
}

static void test_an_image_for_another_chip_is_refused() {
    latchkey_util::AppImageHead parsed;
    TEST_ASSERT_EQUAL(latchkey_util::ImageHeadVerdict::OtherChip, check(head(kEsp32s3, "latchkey", "0.2.0"), parsed));
    TEST_ASSERT_EQUAL_UINT16(kEsp32s3, parsed.chipId);
}

static void test_another_project_is_refused() {
    latchkey_util::AppImageHead parsed;
    TEST_ASSERT_EQUAL(latchkey_util::ImageHeadVerdict::OtherProject, check(head(kEsp32, "other", "1.0.0"), parsed));
    TEST_ASSERT_EQUAL(latchkey_util::ImageHeadVerdict::OtherProject,
                      check(head(kEsp32, "latchkey-fork", "1.0.0"), parsed));
}

static void test_the_chip_check_comes_before_the_project_check() {
    latchkey_util::AppImageHead parsed;
    TEST_ASSERT_EQUAL(latchkey_util::ImageHeadVerdict::OtherChip, check(head(kEsp32s3, "other", "1.0.0"), parsed));
}

static void test_a_version_filling_its_field_is_read_whole() {
    latchkey_util::AppImageHead parsed;
    const char* full = "0123456789abcdef0123456789abcdef";
    TEST_ASSERT_EQUAL(latchkey_util::ImageHeadVerdict::Ok, check(head(kEsp32, "latchkey", full), parsed));
    TEST_ASSERT_EQUAL_STRING(full, parsed.version.c_str());
}

static void test_unprintable_version_bytes_are_replaced() {
    latchkey_util::AppImageHead parsed;
    Head bytes = head(kEsp32, "latchkey", "0.2.0");
    bytes[50] = 0x07;
    bytes[51] = 0xC3;
    TEST_ASSERT_EQUAL(latchkey_util::ImageHeadVerdict::Ok, check(bytes, parsed));
    TEST_ASSERT_EQUAL_STRING("0.??0", parsed.version.c_str());
}

static void test_chip_names() {
    TEST_ASSERT_EQUAL_STRING("esp32", latchkey_util::chipName(kEsp32));
    TEST_ASSERT_EQUAL_STRING("esp32s3", latchkey_util::chipName(kEsp32s3));
    TEST_ASSERT_EQUAL_STRING("esp32c3", latchkey_util::chipName(0x0005));
    TEST_ASSERT_NULL(latchkey_util::chipName(0x1234));
}

static void test_problems_say_what_is_wrong() {
    latchkey_util::AppImageHead parsed;
    TEST_ASSERT_EQUAL_STRING(
        "not an ESP32 app image",
        latchkey_util::appImageProblem(latchkey_util::ImageHeadVerdict::NotAnImage, parsed, kEsp32).c_str());
    parsed.chipId = kEsp32s3;
    TEST_ASSERT_EQUAL_STRING(
        "this image is for the esp32s3, and this board is an esp32",
        latchkey_util::appImageProblem(latchkey_util::ImageHeadVerdict::OtherChip, parsed, kEsp32).c_str());
    parsed.chipId = 0x1234;
    TEST_ASSERT_EQUAL_STRING(
        "this image is for chip 0x1234, and this board is an esp32s3",
        latchkey_util::appImageProblem(latchkey_util::ImageHeadVerdict::OtherChip, parsed, kEsp32s3).c_str());
    TEST_ASSERT_EQUAL_STRING(
        "this image is not Latchkey firmware",
        latchkey_util::appImageProblem(latchkey_util::ImageHeadVerdict::OtherProject, parsed, kEsp32).c_str());
}

int main() {
    UNITY_BEGIN();
    RUN_TEST(test_an_upload_must_hold_at_least_64_kib);
    RUN_TEST(test_an_upload_must_fit_the_slot);
    RUN_TEST(test_a_latchkey_head_for_this_chip_passes_and_names_its_version);
    RUN_TEST(test_fewer_bytes_than_the_head_are_not_an_image);
    RUN_TEST(test_a_wrong_magic_byte_is_not_an_image);
    RUN_TEST(test_a_segment_count_outside_1_to_16_is_not_an_image);
    RUN_TEST(test_a_head_without_an_app_description_is_not_an_image);
    RUN_TEST(test_an_image_for_another_chip_is_refused);
    RUN_TEST(test_another_project_is_refused);
    RUN_TEST(test_the_chip_check_comes_before_the_project_check);
    RUN_TEST(test_a_version_filling_its_field_is_read_whole);
    RUN_TEST(test_unprintable_version_bytes_are_replaced);
    RUN_TEST(test_chip_names);
    RUN_TEST(test_problems_say_what_is_wrong);
    return UNITY_END();
}
