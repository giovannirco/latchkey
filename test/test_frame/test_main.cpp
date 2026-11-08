// SPDX-License-Identifier: GPL-3.0-or-later
#include <unity.h>

#include <algorithm>
#include <cstddef>
#include <cstdint>
#include <vector>

#include "../vectors/frame_vectors.h"
#include "ttlock/aes.h"
#include "ttlock/crc8.h"
#include "ttlock/frame.h"
#include "ttlock/status.h"

using ttlock::Bytes;
using ttlock::Status;
using vectors::frame::FrameCase;
using vectors::frame::kFrames;

void setUp() {}

void tearDown() {}

static ttlock::AesKey toKey(const uint8_t* bytes) {
    ttlock::AesKey key{};
    std::copy(bytes, bytes + key.size(), key.begin());
    return key;
}

static Bytes toBytes(const uint8_t* data, size_t size) {
    return size == 0 ? Bytes{} : Bytes(data, data + size);
}

static void assertBytes(const uint8_t* expected, size_t expectedSize, const Bytes& actual, const char* name) {
    TEST_ASSERT_EQUAL_UINT_MESSAGE(expectedSize, actual.size(), name);
    if (expectedSize > 0) {
        TEST_ASSERT_EQUAL_HEX8_ARRAY_MESSAGE(expected, actual.data(), expectedSize, name);
    }
}

static void assertStatus(Status expected, Status actual, const char* name) {
    TEST_ASSERT_EQUAL_STRING_MESSAGE(ttlock::toString(expected), ttlock::toString(actual), name);
}

static ttlock::LockVersion versionOf(const FrameCase& c) {
    return ttlock::LockVersion{c.protocolType, c.protocolVersion, c.scene, c.groupId, c.orgId};
}

static Bytes wireOf(const FrameCase& c) {
    return toBytes(c.wire, c.wireSize);
}

static Bytes rawOf(const FrameCase& c) {
    return toBytes(c.wire, c.wireSize - 2);
}

static Bytes withCrc(Bytes body) {
    body.push_back(ttlock::crc8(body.data(), body.size()));
    return body;
}

static Status decode(const Bytes& raw, const ttlock::AesKey& key = ttlock::kDefaultAesKey) {
    ttlock::DecodedFrame decoded;
    return ttlock::decodeFrame(raw, key, decoded);
}

static const FrameCase& frameNamed(size_t index, const char* name) {
    TEST_ASSERT_EQUAL_STRING(name, kFrames[index].name);
    return kFrames[index];
}

static void test_encode_matches_ttlock_ble() {
    for (const auto& c : kFrames) {
        const Bytes wire = ttlock::encodeFrame(versionOf(c), c.command, toBytes(c.payload, c.payloadSize), toKey(c.key));
        assertBytes(c.wire, c.wireSize, wire, c.name);
    }
}

static void test_encode_empty_payload_sends_length_zero_without_encryption() {
    const FrameCase& init = frameNamed(0, "initialization");
    const Bytes wire = ttlock::encodeFrame(versionOf(init), init.command, Bytes{}, ttlock::kDefaultAesKey);
    TEST_ASSERT_EQUAL_UINT(15, wire.size());
    TEST_ASSERT_EQUAL_HEX8(0x00, wire[11]);
}

static void test_encode_writes_header_fields_in_order_and_big_endian() {
    const ttlock::LockVersion version{0x05, 0x04, 0x07, 0x1234, 0xABCD};
    const Bytes wire = ttlock::encodeFrame(version, 0x47, Bytes{}, ttlock::kDefaultAesKey);
    const uint8_t header[] = {0x7F, 0x5A, 0x05, 0x04, 0x07, 0x12, 0x34, 0xAB, 0xCD, 0x47, 0xAA, 0x00};
    TEST_ASSERT_EQUAL_UINT(15, wire.size());
    TEST_ASSERT_EQUAL_HEX8_ARRAY(header, wire.data(), sizeof(header));
    TEST_ASSERT_EQUAL_HEX8(ttlock::crc8(wire.data(), sizeof(header)), wire[12]);
    TEST_ASSERT_EQUAL_HEX8(0x0D, wire[13]);
    TEST_ASSERT_EQUAL_HEX8(0x0A, wire[14]);
}

static void test_encode_rejects_payload_over_the_limit() {
    const ttlock::LockVersion version{5, 3, 1, 1, 1};
    TEST_ASSERT_EQUAL_UINT(239, ttlock::kMaxFramePayload);
    TEST_ASSERT_EQUAL_UINT(255, ttlock::encodeFrame(version, 0x03, Bytes(239), ttlock::kDefaultAesKey).size());
    TEST_ASSERT_TRUE(ttlock::encodeFrame(version, 0x03, Bytes(240), ttlock::kDefaultAesKey).empty());
}

static void assertVersion(const ttlock::LockVersion& expected, const ttlock::LockVersion& actual, const char* name) {
    TEST_ASSERT_EQUAL_UINT8_MESSAGE(expected.protocolType, actual.protocolType, name);
    TEST_ASSERT_EQUAL_UINT8_MESSAGE(expected.protocolVersion, actual.protocolVersion, name);
    TEST_ASSERT_EQUAL_UINT8_MESSAGE(expected.scene, actual.scene, name);
    TEST_ASSERT_EQUAL_UINT16_MESSAGE(expected.groupId, actual.groupId, name);
    TEST_ASSERT_EQUAL_UINT16_MESSAGE(expected.orgId, actual.orgId, name);
}

static void test_decode_round_trips_every_vector() {
    for (const auto& c : kFrames) {
        ttlock::DecodedFrame decoded;
        assertStatus(Status::Ok, ttlock::decodeFrame(rawOf(c), toKey(c.key), decoded), c.name);
        TEST_ASSERT_EQUAL_HEX8_MESSAGE(c.command, decoded.command, c.name);
        TEST_ASSERT_TRUE_MESSAGE(decoded.crcOk, c.name);
        assertBytes(c.payload, c.payloadSize, decoded.payload, c.name);
        assertVersion(versionOf(c), decoded.version, c.name);
    }
}

static void test_decode_reports_every_header_field_of_the_version() {
    const ttlock::LockVersion version{0x05, 0x04, 0x07, 0x1234, 0xABCD};
    const Bytes wire = ttlock::encodeFrame(version, 0x54, Bytes{0x01, 0x02}, ttlock::kDefaultAesKey);
    ttlock::DecodedFrame decoded;
    assertStatus(Status::Ok, ttlock::decodeFrame(Bytes(wire.begin(), wire.end() - 2), ttlock::kDefaultAesKey, decoded),
                 "distinct header fields");
    assertVersion(version, decoded.version, "distinct header fields");
}

static void test_decode_with_corrupted_crc_still_decodes_with_crc_ok_false() {
    for (const auto& c : kFrames) {
        Bytes raw = rawOf(c);
        raw.back() ^= 0xFF;
        ttlock::DecodedFrame decoded;
        assertStatus(Status::Ok, ttlock::decodeFrame(raw, toKey(c.key), decoded), c.name);
        TEST_ASSERT_FALSE_MESSAGE(decoded.crcOk, c.name);
        TEST_ASSERT_EQUAL_HEX8_MESSAGE(c.command, decoded.command, c.name);
        assertBytes(c.payload, c.payloadSize, decoded.payload, c.name);
    }
}

static void test_decode_accepts_protocol_type_zero_as_the_v3_layout() {
    const ttlock::LockVersion version{0, 0, 0, 0, 0};
    const Bytes wire = ttlock::encodeFrame(version, 0x45, Bytes{0x01}, ttlock::kDefaultAesKey);
    ttlock::DecodedFrame decoded;
    assertStatus(Status::Ok, ttlock::decodeFrame(Bytes(wire.begin(), wire.end() - 2), ttlock::kDefaultAesKey, decoded),
                 "protocol type 0");
    TEST_ASSERT_EQUAL_UINT(1, decoded.payload.size());
}

static void test_decode_truncated_frame_is_bad_response() {
    const Bytes raw = rawOf(frameNamed(2, "aes_key_response"));
    Bytes missingCipherByte = raw;
    missingCipherByte.erase(missingCipherByte.end() - 2);
    assertStatus(Status::BadResponse, decode(missingCipherByte), "missing ciphertext byte");
    assertStatus(Status::BadResponse, decode(Bytes(raw.begin(), raw.end() - 1)), "missing crc");
    assertStatus(Status::BadResponse, decode(Bytes(raw.begin(), raw.begin() + 12)), "header only");
    assertStatus(Status::BadResponse, decode(Bytes(raw.begin(), raw.begin() + 11)), "partial header");
}

static void test_decode_oversized_frame_is_bad_response() {
    const Bytes raw = rawOf(frameNamed(2, "aes_key_response"));
    Bytes extraCipherByte = raw;
    extraCipherByte.insert(extraCipherByte.end() - 1, 0x00);
    assertStatus(Status::BadResponse, decode(extraCipherByte), "extra ciphertext byte");
    Bytes trailingByte = raw;
    trailingByte.push_back(0x00);
    assertStatus(Status::BadResponse, decode(trailingByte), "byte after crc");
}

static void test_decode_bad_header_is_bad_response() {
    const Bytes raw = rawOf(frameNamed(1, "get_aes_key"));
    Bytes wrongSecond = raw;
    wrongSecond[1] = 0x5B;
    assertStatus(Status::BadResponse, decode(wrongSecond), "7f 5b");
    Bytes wrongFirst = raw;
    wrongFirst[0] = 0x00;
    assertStatus(Status::BadResponse, decode(wrongFirst), "00 5a");
}

static void test_decode_short_input_is_bad_response() {
    assertStatus(Status::BadResponse, decode(Bytes{}), "empty");
    assertStatus(Status::BadResponse, decode(Bytes{0x7F, 0x5A}), "two bytes");
    assertStatus(Status::BadResponse, decode(Bytes{0x7F, 0x5A, 0x05}), "three bytes");
}

static void test_decode_legacy_layout_is_unsupported() {
    assertStatus(Status::Unsupported, decode(withCrc(Bytes{0x7F, 0x5A, 0x03, 0x45, 0xAA, 0x00})), "protocol type 3");
}

static void test_decode_bad_padding_is_bad_response() {
    const Bytes raw(vectors::frame::kWireBadPadding,
                    vectors::frame::kWireBadPadding + sizeof(vectors::frame::kWireBadPadding) - 2);
    assertStatus(Status::BadResponse, decode(raw), "bad padding");
}

static void test_decode_unaligned_ciphertext_is_bad_response() {
    Bytes body{0x7F, 0x5A, 0x05, 0x03, 0x02, 0x00, 0x01, 0x00, 0x01, 0x54, 0xAA, 0x0F};
    body.insert(body.end(), 15, 0x42);
    assertStatus(Status::BadResponse, decode(withCrc(body)), "15 ciphertext bytes");
}

static void test_decode_with_the_wrong_key_does_not_yield_the_payload() {
    const FrameCase& c = frameNamed(3, "synthetic_key_64_bytes");
    ttlock::DecodedFrame decoded;
    const Status status = ttlock::decodeFrame(rawOf(c), ttlock::kDefaultAesKey, decoded);
    const bool samePayload = decoded.payload == toBytes(c.payload, c.payloadSize);
    TEST_ASSERT_TRUE(status != Status::Ok || !samePayload);
}

static void test_failed_decode_leaves_output_untouched() {
    const ttlock::LockVersion untouched{9, 9, 9, 9, 9};
    ttlock::DecodedFrame decoded{0x99, Bytes{0x01, 0x02}, true, untouched};
    assertStatus(Status::BadResponse, ttlock::decodeFrame(Bytes{}, ttlock::kDefaultAesKey, decoded), "empty");
    const Bytes badPadding(vectors::frame::kWireBadPadding,
                           vectors::frame::kWireBadPadding + sizeof(vectors::frame::kWireBadPadding) - 2);
    assertStatus(Status::BadResponse, ttlock::decodeFrame(badPadding, ttlock::kDefaultAesKey, decoded), "padding");
    TEST_ASSERT_EQUAL_HEX8(0x99, decoded.command);
    TEST_ASSERT_EQUAL_UINT(2, decoded.payload.size());
    TEST_ASSERT_TRUE(decoded.crcOk);
    assertVersion(untouched, decoded.version, "untouched");
}

static void test_chunk_splits_into_20_byte_notifications() {
    const FrameCase& c = frameNamed(2, "aes_key_response");
    const std::vector<Bytes> chunks = ttlock::chunk(wireOf(c));
    TEST_ASSERT_EQUAL_UINT(47, c.wireSize);
    TEST_ASSERT_EQUAL_UINT(3, chunks.size());
    TEST_ASSERT_EQUAL_UINT(20, chunks[0].size());
    TEST_ASSERT_EQUAL_UINT(20, chunks[1].size());
    TEST_ASSERT_EQUAL_UINT(7, chunks[2].size());
    Bytes joined;
    for (const auto& piece : chunks) {
        joined.insert(joined.end(), piece.begin(), piece.end());
    }
    assertBytes(c.wire, c.wireSize, joined, c.name);
}

static void test_chunk_handles_exact_multiples_and_other_mtus() {
    const Bytes forty(40, 0x33);
    const std::vector<Bytes> two = ttlock::chunk(forty);
    TEST_ASSERT_EQUAL_UINT(2, two.size());
    TEST_ASSERT_EQUAL_UINT(20, two[1].size());
    const Bytes wire = wireOf(frameNamed(2, "aes_key_response"));
    TEST_ASSERT_EQUAL_UINT(1, ttlock::chunk(wire, 100).size());
    TEST_ASSERT_EQUAL_UINT(47, ttlock::chunk(wire, 1).size());
}

static void test_chunk_of_empty_frame_or_zero_mtu_is_empty() {
    TEST_ASSERT_TRUE(ttlock::chunk(Bytes{}).empty());
    TEST_ASSERT_TRUE(ttlock::chunk(Bytes(10, 0x01), 0).empty());
}

static void test_reassembles_every_vector_from_20_byte_notifications() {
    for (const auto& c : kFrames) {
        ttlock::Reassembler reassembler;
        const std::vector<Bytes> chunks = ttlock::chunk(wireOf(c));
        Bytes frame;
        for (size_t i = 0; i < chunks.size(); ++i) {
            const bool complete = reassembler.feed(chunks[i].data(), chunks[i].size(), frame);
            TEST_ASSERT_EQUAL_MESSAGE(i + 1 == chunks.size(), complete, c.name);
            assertStatus(Status::Ok, reassembler.status(), c.name);
        }
        assertBytes(c.wire, c.wireSize - 2, frame, c.name);
    }
}

static void test_crlf_inside_ciphertext_at_a_notification_boundary_does_not_end_the_frame() {
    const FrameCase& c = frameNamed(vectors::frame::kCrlfAtNotificationBoundaryIndex, "crlf_at_notification_boundary");
    const std::vector<Bytes> chunks = ttlock::chunk(wireOf(c));
    TEST_ASSERT_EQUAL_UINT(2, chunks.size());
    TEST_ASSERT_EQUAL_HEX8(0x0D, chunks[0][18]);
    TEST_ASSERT_EQUAL_HEX8(0x0A, chunks[0][19]);
    ttlock::Reassembler reassembler;
    Bytes frame;
    TEST_ASSERT_FALSE(reassembler.feed(chunks[0].data(), chunks[0].size(), frame));
    assertStatus(Status::Ok, reassembler.status(), c.name);
    TEST_ASSERT_TRUE(reassembler.feed(chunks[1].data(), chunks[1].size(), frame));
    assertBytes(c.wire, c.wireSize - 2, frame, c.name);
    ttlock::DecodedFrame decoded;
    assertStatus(Status::Ok, ttlock::decodeFrame(frame, toKey(c.key), decoded), c.name);
    assertBytes(c.payload, c.payloadSize, decoded.payload, c.name);
}

static void test_frame_split_at_every_offset_reassembles_once() {
    const FrameCase& c = frameNamed(2, "aes_key_response");
    for (size_t split = 1; split < c.wireSize; ++split) {
        ttlock::Reassembler reassembler;
        Bytes frame;
        TEST_ASSERT_FALSE(reassembler.feed(c.wire, split, frame));
        TEST_ASSERT_TRUE(reassembler.feed(c.wire + split, c.wireSize - split, frame));
        assertBytes(c.wire, c.wireSize - 2, frame, c.name);
    }
}

static void test_overflow_resets_and_reports_bad_response() {
    TEST_ASSERT_EQUAL_UINT(512, ttlock::kMaxFrameBytes);
    ttlock::Reassembler reassembler;
    const Bytes zeros(20, 0x00);
    Bytes frame;
    for (int i = 0; i < 25; ++i) {
        TEST_ASSERT_FALSE(reassembler.feed(zeros.data(), zeros.size(), frame));
        assertStatus(Status::Ok, reassembler.status(), "within 512 bytes");
    }
    TEST_ASSERT_FALSE(reassembler.feed(zeros.data(), zeros.size(), frame));
    assertStatus(Status::BadResponse, reassembler.status(), "past 512 bytes");
    const FrameCase& c = frameNamed(1, "get_aes_key");
    const std::vector<Bytes> chunks = ttlock::chunk(wireOf(c));
    bool complete = false;
    for (const auto& piece : chunks) {
        complete = reassembler.feed(piece.data(), piece.size(), frame);
    }
    TEST_ASSERT_TRUE(complete);
    assertStatus(Status::Ok, reassembler.status(), "after overflow");
    assertBytes(c.wire, c.wireSize - 2, frame, c.name);
}

static void test_limit_is_512_bytes_including_crlf() {
    Bytes atLimit(510, 0x00);
    atLimit.push_back(0x0D);
    atLimit.push_back(0x0A);
    ttlock::Reassembler reassembler;
    Bytes frame;
    TEST_ASSERT_TRUE(reassembler.feed(atLimit.data(), atLimit.size(), frame));
    TEST_ASSERT_EQUAL_UINT(510, frame.size());
    Bytes overLimit(511, 0x00);
    overLimit.push_back(0x0D);
    overLimit.push_back(0x0A);
    TEST_ASSERT_FALSE(reassembler.feed(overLimit.data(), overLimit.size(), frame));
    assertStatus(Status::BadResponse, reassembler.status(), "513 bytes");
}

static void test_reset_discards_a_partial_frame() {
    const std::vector<Bytes> partial = ttlock::chunk(wireOf(frameNamed(2, "aes_key_response")));
    const FrameCase& next = frameNamed(1, "get_aes_key");
    ttlock::Reassembler reassembler;
    Bytes frame;
    TEST_ASSERT_FALSE(reassembler.feed(partial[0].data(), partial[0].size(), frame));
    reassembler.reset();
    bool complete = false;
    for (const auto& piece : ttlock::chunk(wireOf(next))) {
        complete = reassembler.feed(piece.data(), piece.size(), frame);
    }
    TEST_ASSERT_TRUE(complete);
    assertBytes(next.wire, next.wireSize - 2, frame, next.name);
}

static void test_status_strings_are_the_rpc_error_codes() {
    TEST_ASSERT_EQUAL_STRING("ok", ttlock::toString(Status::Ok));
    TEST_ASSERT_EQUAL_STRING("timeout", ttlock::toString(Status::Timeout));
    TEST_ASSERT_EQUAL_STRING("disconnected", ttlock::toString(Status::Disconnected));
    TEST_ASSERT_EQUAL_STRING("bad_response", ttlock::toString(Status::BadResponse));
    TEST_ASSERT_EQUAL_STRING("bad_crc", ttlock::toString(Status::BadCrc));
    TEST_ASSERT_EQUAL_STRING("lock_error", ttlock::toString(Status::LockError));
    TEST_ASSERT_EQUAL_STRING("unsupported", ttlock::toString(Status::Unsupported));
    TEST_ASSERT_EQUAL_STRING("not_paired", ttlock::toString(Status::NotPaired));
    TEST_ASSERT_EQUAL_STRING("pair_incomplete", ttlock::toString(Status::PairIncomplete));
    TEST_ASSERT_EQUAL_STRING("busy", ttlock::toString(Status::Busy));
    TEST_ASSERT_EQUAL_STRING("invalid_argument", ttlock::toString(Status::InvalidArgument));
    TEST_ASSERT_EQUAL_STRING("time_unsynced", ttlock::toString(Status::TimeUnsynced));
}

static void test_status_values_keep_their_order() {
    TEST_ASSERT_EQUAL_UINT8(0, static_cast<uint8_t>(Status::Ok));
    TEST_ASSERT_EQUAL_UINT8(11, static_cast<uint8_t>(Status::TimeUnsynced));
}

static void test_out_of_range_status_is_unknown() {
    TEST_ASSERT_EQUAL_STRING("unknown", ttlock::toString(static_cast<Status>(0xFF)));
}

int main() {
    UNITY_BEGIN();
    RUN_TEST(test_encode_matches_ttlock_ble);
    RUN_TEST(test_encode_empty_payload_sends_length_zero_without_encryption);
    RUN_TEST(test_encode_writes_header_fields_in_order_and_big_endian);
    RUN_TEST(test_encode_rejects_payload_over_the_limit);
    RUN_TEST(test_decode_round_trips_every_vector);
    RUN_TEST(test_decode_reports_every_header_field_of_the_version);
    RUN_TEST(test_decode_with_corrupted_crc_still_decodes_with_crc_ok_false);
    RUN_TEST(test_decode_accepts_protocol_type_zero_as_the_v3_layout);
    RUN_TEST(test_decode_truncated_frame_is_bad_response);
    RUN_TEST(test_decode_oversized_frame_is_bad_response);
    RUN_TEST(test_decode_bad_header_is_bad_response);
    RUN_TEST(test_decode_short_input_is_bad_response);
    RUN_TEST(test_decode_legacy_layout_is_unsupported);
    RUN_TEST(test_decode_bad_padding_is_bad_response);
    RUN_TEST(test_decode_unaligned_ciphertext_is_bad_response);
    RUN_TEST(test_decode_with_the_wrong_key_does_not_yield_the_payload);
    RUN_TEST(test_failed_decode_leaves_output_untouched);
    RUN_TEST(test_chunk_splits_into_20_byte_notifications);
    RUN_TEST(test_chunk_handles_exact_multiples_and_other_mtus);
    RUN_TEST(test_chunk_of_empty_frame_or_zero_mtu_is_empty);
    RUN_TEST(test_reassembles_every_vector_from_20_byte_notifications);
    RUN_TEST(test_crlf_inside_ciphertext_at_a_notification_boundary_does_not_end_the_frame);
    RUN_TEST(test_frame_split_at_every_offset_reassembles_once);
    RUN_TEST(test_overflow_resets_and_reports_bad_response);
    RUN_TEST(test_limit_is_512_bytes_including_crlf);
    RUN_TEST(test_reset_discards_a_partial_frame);
    RUN_TEST(test_status_strings_are_the_rpc_error_codes);
    RUN_TEST(test_status_values_keep_their_order);
    RUN_TEST(test_out_of_range_status_is_unknown);
    return UNITY_END();
}
