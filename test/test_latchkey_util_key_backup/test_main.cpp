// SPDX-License-Identifier: GPL-3.0-or-later
#include <unity.h>

#include <array>
#include <cstring>
#include <new>
#include <string>
#include <type_traits>
#include <vector>

#include "../reference/aes256_gcm.h"
#include "../reference/hmac_sha256.h"
#include "latchkey_util/key_backup.h"
#include "latchkey_util/label_table.h"
#include "latchkey_util/pbkdf2.h"
#include "latchkey_util/seed_table.h"

using namespace latchkey_util;

void setUp() {}
void tearDown() {}

static const std::array<uint8_t, 16> kKey{0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15};
static const std::array<uint8_t, 2> kEmptyLabels{1, 0};

static BackupLock lockView() {
    BackupLock lock;
    lock.flags = 7;
    lock.lifecycle = 1;
    lock.address = {0x01, 0x53, 0x00, 0x5E, 0x00, 0x00};
    lock.mac = "00:00:5E:00:53:01";
    lock.protocol = {5, 3, 1, 1, 1};
    lock.aesKey = kKey;
    lock.adminPs = 0x12345678;
    lock.unlockKey = 0x87654321;
    lock.lockFlagPos = 0x01020304;
    lock.features = 0x0102030405060708ULL;
    lock.adminPasscode = "876543210";
    lock.provenance = AdminProvenance::Owner;
    lock.name = "Front door";
    for (auto& labels : lock.labels) {
        labels = kEmptyLabels;
    }
    return lock;
}

static SensitiveBuffer encode(const BackupLock& lock) {
    SensitiveBuffer out;
    TEST_ASSERT_EQUAL_INT(static_cast<int>(BackupStatus::Ok), static_cast<int>(encodeBackup({&lock, 1}, out)));
    return out;
}

static SensitiveBuffer copyBytes(const uint8_t* data, size_t size) {
    SensitiveBuffer out;
    TEST_ASSERT_TRUE(out.allocate(size));
    std::memcpy(out.data(), data, size);
    return out;
}

static void test_full_record_roundtrip_and_move_owned_views() {
    LabelTable labels;
    TEST_ASSERT_TRUE(labels.put({9, true, "Entry", WeeklyWindow{0x1F, 480, 1080}}));
    const auto labelBytes = labels.encode();
    SeedTable seeds;
    seeds.year = 2026;
    seeds.confirmed = true;
    for (size_t i = 0; i < seeds.seeds.size(); ++i) {
        seeds.seeds[i] = {static_cast<uint16_t>(i + 1), 0x1234567890ABCDEFULL + i};
    }
    const auto seedBytes = encodeSeedTable(seeds);
    auto source = lockView();
    source.pendingAdminPasscode = "123456789";
    source.pendingProvenance = AdminProvenance::PairingGenerated;
    source.model = "Model";
    source.hardware = "Hardware";
    source.firmware = "Firmware";
    source.manufactureDate = "2026-01-01";
    source.labels.fill(labelBytes);
    source.seeds = seedBytes;
    auto bytes = encode(source);
    const auto* allocation = bytes.data();
    DecodedBackup decoded;
    TEST_ASSERT_EQUAL_INT(static_cast<int>(BackupStatus::Ok), static_cast<int>(decodeBackup(std::move(bytes), decoded)));
    TEST_ASSERT_NULL(bytes.data());
    TEST_ASSERT_EQUAL_UINT(0, bytes.size());
    DecodedBackup moved(std::move(decoded));
    DecodedBackup assigned;
    assigned = std::move(moved);
    TEST_ASSERT_EQUAL_UINT(0, decoded.locks().size());
    TEST_ASSERT_EQUAL_UINT(0, moved.locks().size());
    TEST_ASSERT_EQUAL_UINT(1, assigned.locks().size());
    const auto& restored = assigned.locks()[0];
    TEST_ASSERT_TRUE(restored.aesKey.data() >= allocation);
    TEST_ASSERT_EQUAL_MEMORY(kKey.data(), restored.aesKey.data(), kKey.size());
    TEST_ASSERT_TRUE(restored.mac == source.mac);
    TEST_ASSERT_TRUE(restored.name == source.name);
    TEST_ASSERT_TRUE(restored.adminPasscode == source.adminPasscode);
    TEST_ASSERT_TRUE(restored.pendingAdminPasscode == source.pendingAdminPasscode);
    TEST_ASSERT_EQUAL_INT(static_cast<int>(source.provenance), static_cast<int>(restored.provenance));
    TEST_ASSERT_EQUAL_INT(static_cast<int>(source.pendingProvenance), static_cast<int>(restored.pendingProvenance));
    TEST_ASSERT_TRUE(restored.model == source.model);
    TEST_ASSERT_TRUE(restored.hardware == source.hardware);
    TEST_ASSERT_TRUE(restored.firmware == source.firmware);
    TEST_ASSERT_TRUE(restored.manufactureDate == source.manufactureDate);
    TEST_ASSERT_EQUAL_UINT32(source.adminPs, restored.adminPs);
    TEST_ASSERT_EQUAL_UINT32(source.unlockKey, restored.unlockKey);
    TEST_ASSERT_EQUAL_UINT32(source.lockFlagPos, restored.lockFlagPos);
    TEST_ASSERT_EQUAL_UINT64(source.features, restored.features);
    TEST_ASSERT_EQUAL_UINT8(source.flags, restored.flags);
    TEST_ASSERT_EQUAL_UINT8(source.lifecycle, restored.lifecycle);
    for (const auto table : restored.labels) {
        TEST_ASSERT_EQUAL_MEMORY(labelBytes.data(), table.data(), table.size());
    }
    TEST_ASSERT_EQUAL_MEMORY(seedBytes.data(), restored.seeds.data(), restored.seeds.size());
    auto encodedAgain = encode(restored);
    TEST_ASSERT_EQUAL_MEMORY(allocation, encodedAgain.data(), encodedAgain.size());
}

static void test_minimal_record_has_explicit_fixed_wire_bytes() {
    auto lock = lockView();
    lock.flags = 0;
    lock.lifecycle = 0;
    lock.provenance = AdminProvenance::LegacyUnknown;
    lock.name = {};
    lock.adminPasscode = {};
    const auto bytes = encode(lock);
    const uint8_t expected[] = {
        1, 1, 0, 92, 0, 0, 0, 0, 0,
        0x01, 0x53, 0, 0x5E, 0, 0,
        '0', '0', ':', '0', '0', ':', '5', 'E', ':', '0', '0', ':', '5', '3', ':', '0', '1',
        5, 3, 1, 0, 1, 0, 1,
        0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15,
        0x12, 0x34, 0x56, 0x78, 0x87, 0x65, 0x43, 0x21, 1, 2, 3, 4,
        1, 2, 3, 4, 5, 6, 7, 8,
        0, 0, 0, 0, 0, 0, 0,
        0, 2, 1, 0, 0, 2, 1, 0, 0, 2, 1, 0, 0, 0,
    };
    TEST_ASSERT_EQUAL_UINT(sizeof(expected), bytes.size());
    TEST_ASSERT_EQUAL_MEMORY(expected, bytes.data(), bytes.size());
}

static void test_maximum_single_lock_fits_and_oversized_export_is_atomic() {
    LabelTable table;
    std::string labelName;
    for (size_t i = 0; i < 24; ++i) labelName += "\xC3\xA9";
    for (size_t i = 0; i < kMaxLabels; ++i) {
        TEST_ASSERT_TRUE(table.put({i + 1, true, labelName, WeeklyWindow{0x7F, 0, 1440}}));
    }
    const auto labels = table.encode();
    SeedTable seeds;
    seeds.year = 2099;
    const auto seedBytes = encodeSeedTable(seeds);
    const std::string name(99, 'N');
    const std::string metadata(31, 'M');
    const std::string date(15, 'D');
    auto lock = lockView();
    lock.name = name;
    lock.model = lock.hardware = lock.firmware = metadata;
    lock.manufactureDate = date;
    lock.pendingAdminPasscode = "123456789";
    lock.pendingProvenance = AdminProvenance::PairingGenerated;
    lock.labels.fill(labels);
    lock.seeds = seedBytes;
    const auto bytes = encode(lock);
    TEST_ASSERT_LESS_OR_EQUAL_UINT(kMaxBackupPlaintext, bytes.size());
    DecodedBackup decoded;
    TEST_ASSERT_EQUAL_INT(static_cast<int>(BackupStatus::Ok),
                          static_cast<int>(decodeBackup(copyBytes(bytes.data(), bytes.size()), decoded)));
    auto second = lock;
    second.mac = "00:00:5E:00:53:02";
    second.address[0] = 2;
    const std::array locks{lock, second};
    auto unchanged = copyBytes(reinterpret_cast<const uint8_t*>("keep"), 4);
    TEST_ASSERT_EQUAL_INT(static_cast<int>(BackupStatus::TooLarge),
                          static_cast<int>(encodeBackup(locks, unchanged)));
    TEST_ASSERT_EQUAL_MEMORY("keep", unchanged.data(), 4);
}

static void test_truncation_lengths_and_trailing_bytes_leave_output_unchanged() {
    const auto original = encode(lockView());
    DecodedBackup out;
    TEST_ASSERT_EQUAL_INT(static_cast<int>(BackupStatus::Ok),
                          static_cast<int>(decodeBackup(copyBytes(original.data(), original.size()), out)));
    const auto* heldKey = out.locks()[0].aesKey.data();
    for (size_t length = 0; length < original.size(); ++length) {
        auto truncated = copyBytes(original.data(), length);
        TEST_ASSERT_NOT_EQUAL(static_cast<int>(BackupStatus::Ok),
                              static_cast<int>(decodeBackup(std::move(truncated), out)));
        TEST_ASSERT_NULL(truncated.data());
        TEST_ASSERT_EQUAL_PTR(heldKey, out.locks()[0].aesKey.data());
    }
    auto malformed = copyBytes(original.data(), original.size());
    malformed.data()[2] = 0xFF;
    TEST_ASSERT_EQUAL_INT(static_cast<int>(BackupStatus::Invalid),
                          static_cast<int>(decodeBackup(std::move(malformed), out)));
    SensitiveBuffer trailing;
    TEST_ASSERT_TRUE(trailing.allocate(original.size() + 1));
    std::memcpy(trailing.data(), original.data(), original.size());
    TEST_ASSERT_EQUAL_INT(static_cast<int>(BackupStatus::Invalid),
                          static_cast<int>(decodeBackup(std::move(trailing), out)));
    TEST_ASSERT_EQUAL_PTR(heldKey, out.locks()[0].aesKey.data());
}

static void test_invalid_fields_and_nested_records_are_rejected() {
    const auto good = encode(lockView());
    for (const size_t at : {size_t{0}, size_t{4}, size_t{5}, size_t{6}, size_t{7}, size_t{8}, size_t{32}}) {
        auto broken = copyBytes(good.data(), good.size());
        broken.data()[at] = 0xFF;
        DecodedBackup out;
        TEST_ASSERT_EQUAL_INT(static_cast<int>(BackupStatus::Invalid),
                              static_cast<int>(decodeBackup(std::move(broken), out)));
        TEST_ASSERT_EQUAL_UINT(0, out.locks().size());
    }
    auto lock = lockView();
    SensitiveBuffer out;
    lock.mac = "00:00:5e:00:53:01";
    TEST_ASSERT_EQUAL_INT(static_cast<int>(BackupStatus::Invalid), static_cast<int>(encodeBackup({&lock, 1}, out)));
    lock = lockView();
    lock.name = "\xC0\xAF";
    TEST_ASSERT_EQUAL_INT(static_cast<int>(BackupStatus::Invalid), static_cast<int>(encodeBackup({&lock, 1}, out)));
    lock = lockView();
    lock.adminPasscode = "123x";
    TEST_ASSERT_EQUAL_INT(static_cast<int>(BackupStatus::Invalid), static_cast<int>(encodeBackup({&lock, 1}, out)));
    lock = lockView();
    const uint8_t brokenLabels[] = {1, 1, 0, 0, 0, 0, 0, 0, 0, 1, 0x80, 0};
    lock.labels[0] = brokenLabels;
    TEST_ASSERT_EQUAL_INT(static_cast<int>(BackupStatus::Invalid), static_cast<int>(encodeBackup({&lock, 1}, out)));
    const uint8_t invalidUtf8[] = {1, 1, 0, 0, 0, 0, 0, 0, 0, 1, 1, 2, 0xC0, 0xAF};
    lock.labels[0] = invalidUtf8;
    TEST_ASSERT_EQUAL_INT(static_cast<int>(BackupStatus::Invalid), static_cast<int>(encodeBackup({&lock, 1}, out)));
    lock = lockView();
    std::array<uint8_t, kSeedTableSize> seeds{};
    seeds[0] = 1;
    seeds[1] = 2;
    lock.seeds = seeds;
    TEST_ASSERT_EQUAL_INT(static_cast<int>(BackupStatus::Invalid), static_cast<int>(encodeBackup({&lock, 1}, out)));
}

static void test_identity_and_bluetooth_address_are_preserved_independently() {
    auto lock = lockView();
    lock.addressType = 1;
    lock.address[0] = 9;
    const auto bytes = encode(lock);
    DecodedBackup decoded;
    TEST_ASSERT_EQUAL_INT(static_cast<int>(BackupStatus::Ok),
                          static_cast<int>(decodeBackup(copyBytes(bytes.data(), bytes.size()), decoded)));
    TEST_ASSERT_TRUE(decoded.locks()[0].mac == lock.mac);
    TEST_ASSERT_EQUAL_UINT8(1, decoded.locks()[0].addressType);
    TEST_ASSERT_EQUAL_MEMORY(lock.address.data(), decoded.locks()[0].address.data(), lock.address.size());
}

static void test_duplicate_identities_and_capacity_are_rejected() {
    const std::array duplicates{lockView(), lockView()};
    SensitiveBuffer out;
    TEST_ASSERT_EQUAL_INT(static_cast<int>(BackupStatus::Duplicate), static_cast<int>(encodeBackup(duplicates, out)));
    std::array<BackupLock, 9> locks;
    std::array<std::string, 9> macs;
    for (size_t i = 0; i < locks.size(); ++i) {
        locks[i] = lockView();
        macs[i] = "00:00:5E:00:53:0" + std::to_string(i + 1);
        locks[i].mac = macs[i];
        locks[i].address[0] = static_cast<uint8_t>(i + 1);
    }
    TEST_ASSERT_EQUAL_INT(static_cast<int>(BackupStatus::Ok), static_cast<int>(encodeBackup({locks.data(), 8}, out)));
    DecodedBackup decoded;
    TEST_ASSERT_EQUAL_INT(static_cast<int>(BackupStatus::Ok), static_cast<int>(decodeBackup(std::move(out), decoded)));
    TEST_ASSERT_EQUAL_UINT(8, decoded.locks().size());
    TEST_ASSERT_EQUAL_INT(static_cast<int>(BackupStatus::TooLarge), static_cast<int>(encodeBackup(locks, out)));
    const auto one = encode(lockView());
    SensitiveBuffer duplicateBytes;
    TEST_ASSERT_TRUE(duplicateBytes.allocate(one.size() * 2 - 2));
    std::memcpy(duplicateBytes.data(), one.data(), one.size());
    std::memcpy(duplicateBytes.data() + one.size(), one.data() + 2, one.size() - 2);
    duplicateBytes.data()[1] = 2;
    TEST_ASSERT_EQUAL_INT(static_cast<int>(BackupStatus::Duplicate),
                          static_cast<int>(decodeBackup(std::move(duplicateBytes), decoded)));
    TEST_ASSERT_EQUAL_UINT(8, decoded.locks().size());
}

static void test_sensitive_buffer_moves_and_rejects_unbounded_allocation() {
    static_assert(!std::is_copy_constructible_v<SensitiveBuffer>);
    static_assert(!std::is_copy_constructible_v<DecodedBackup>);
    auto source = copyBytes(reinterpret_cast<const uint8_t*>("private"), 7);
    const auto* pointer = source.data();
    SensitiveBuffer moved(std::move(source));
    TEST_ASSERT_NULL(source.data());
    TEST_ASSERT_EQUAL_UINT(0, source.size());
    SensitiveBuffer destination;
    destination = std::move(moved);
    TEST_ASSERT_NULL(moved.data());
    TEST_ASSERT_EQUAL_PTR(pointer, destination.data());
    TEST_ASSERT_FALSE(destination.allocate(kMaxBackupEnvelope + 1));
    TEST_ASSERT_EQUAL_PTR(pointer, destination.data());
    TEST_ASSERT_TRUE(destination.resize(0));
    TEST_ASSERT_TRUE(destination.resize(7));
    const uint8_t zeros[7]{};
    TEST_ASSERT_EQUAL_MEMORY(zeros, destination.data(), 7);
    destination.clear();
    TEST_ASSERT_NULL(destination.data());
    TEST_ASSERT_EQUAL_UINT(0, destination.size());
}

static void test_record_secret_scalars_are_wiped_on_destruction() {
    alignas(BackupLock) std::array<uint8_t, sizeof(BackupLock)> storage{};
    auto* lock = new (storage.data()) BackupLock(lockView());
    const auto adminOffset = reinterpret_cast<uint8_t*>(&lock->adminPs) - storage.data();
    const auto unlockOffset = reinterpret_cast<uint8_t*>(&lock->unlockKey) - storage.data();
    const auto flagOffset = reinterpret_cast<uint8_t*>(&lock->lockFlagPos) - storage.data();
    lock->~BackupLock();
    const uint8_t zeros[4]{};
    TEST_ASSERT_EQUAL_MEMORY(zeros, storage.data() + adminOffset, 4);
    TEST_ASSERT_EQUAL_MEMORY(zeros, storage.data() + unlockOffset, 4);
    TEST_ASSERT_EQUAL_MEMORY(zeros, storage.data() + flagOffset, 4);
}

static std::vector<uint8_t> fromHex(std::string_view text) {
    std::vector<uint8_t> bytes;
    for (size_t i = 0; i < text.size(); i += 2) {
        const auto digit = [](char value) { return value <= '9' ? value - '0' : value - 'a' + 10; };
        bytes.push_back(static_cast<uint8_t>((digit(text[i]) << 4) | digit(text[i + 1])));
    }
    return bytes;
}

static void test_reference_aes256_gcm_matches_nist_vectors() {
    std::array<uint8_t, 32> zeroKey{};
    std::array<uint8_t, 12> zeroNonce{};
    std::array<uint8_t, 32> zeroBlockAndTag{};
    TEST_ASSERT_TRUE(reference::sealGcm(zeroKey, zeroNonce, {}, zeroBlockAndTag));
    const auto zeroExpected = fromHex("cea7403d4d606b6e074ec5d3baf39d18d0d1c8a799996bf0265b98b5d48ab919");
    TEST_ASSERT_EQUAL_MEMORY(zeroExpected.data(), zeroBlockAndTag.data(), zeroExpected.size());
    TEST_ASSERT_TRUE(reference::openGcm(zeroKey, zeroNonce, {}, zeroBlockAndTag));
    TEST_ASSERT_EQUAL_MEMORY(zeroKey.data(), zeroBlockAndTag.data(), 16);

    const auto key = fromHex("feffe9928665731c6d6a8f9467308308feffe9928665731c6d6a8f9467308308");
    const auto nonce = fromHex("cafebabefacedbaddecaf888");
    const auto aad = fromHex("feedfacedeadbeeffeedfacedeadbeefabaddad2");
    const auto plaintext = fromHex("d9313225f88406e5a55909c5aff5269a86a7a9531534f7da2e4c303d8a318a72"
                                   "1c3c0c95956809532fcf0e2449a6b525b16aedf5aa0de657ba637b39");
    auto sealed = plaintext;
    sealed.resize(plaintext.size() + 16);
    TEST_ASSERT_TRUE(reference::sealGcm(std::span<const uint8_t, 32>(key.data(), 32),
                                       std::span<const uint8_t, 12>(nonce.data(), 12), aad, sealed));
    const auto expected = fromHex("522dc1f099567d07f47f37a32a84427d643a8cdcbfe5c0c97598a2bd2555d1aa"
                                  "8cb08e48590dbb3da7b08b1056828838c5f61e6393ba7a0abcc9f662"
                                  "76fc6ece0f4e1768cddf8853bb2d551b");
    TEST_ASSERT_EQUAL_MEMORY(expected.data(), sealed.data(), expected.size());
    TEST_ASSERT_TRUE(reference::openGcm(std::span<const uint8_t, 32>(key.data(), 32),
                                       std::span<const uint8_t, 12>(nonce.data(), 12), aad, sealed));
    TEST_ASSERT_EQUAL_MEMORY(plaintext.data(), sealed.data(), plaintext.size());
}

class ReferenceCrypto : public BackupCrypto {
public:
    size_t randomCalls = 0;
    size_t derivations = 0;
    size_t yields = 0;
    size_t seals = 0;
    size_t opens = 0;
    unsigned failAt = 0;

    bool random(std::span<uint8_t> bytes) override {
        ++randomCalls;
        for (auto& byte : bytes) byte = next_++;
        return failAt != 1;
    }

    bool deriveKey(std::string_view password, std::span<const uint8_t, 16> salt,
                    std::span<uint8_t, 32> key) override {
        ++derivations;
        const KeyedHmacSha256 hmac = [password](const uint8_t* message, size_t size, uint8_t (&digest)[32]) {
            return reference::hmacSha256(reinterpret_cast<const uint8_t*>(password.data()), password.size(),
                                         message, size, digest);
        };
        const bool result = pbkdf2HmacSha256(hmac, salt.data(), salt.size(), kBackupIterations, 1000,
                                             [this]() { ++yields; }, key.data(), key.size());
        return result && failAt != 2;
    }

    bool seal(std::span<const uint8_t, 32> key, std::span<const uint8_t, 12> nonce,
               std::span<const uint8_t> aad, std::span<uint8_t> bytes) override {
        ++seals;
        return reference::sealGcm(key, nonce, aad, bytes) && failAt != 3;
    }

    bool open(std::span<const uint8_t, 32> key, std::span<const uint8_t, 12> nonce,
               std::span<const uint8_t> aad, std::span<uint8_t> bytes) override {
        ++opens;
        return reference::openGcm(key, nonce, aad, bytes) && failAt != 4;
    }

private:
    uint8_t next_ = 0;
};

static constexpr std::string_view kPassword = "correct horse battery";
static constexpr std::string_view kPlaintext = "authenticated backup bytes";
static constexpr std::string_view kFixture =
    "4c4b42320101000186a0000102030405060708090a0b0c0d0e0f101112131415161718191a1b"
    "5efefc682dd04afc7fca46a9235e940683840aee6c8e8159f44202ef98571d0907651c3de4f1c7e341b5";

static SensitiveBuffer plaintext() {
    SensitiveBuffer buffer;
    TEST_ASSERT_TRUE(buffer.allocate(kPlaintext.size(), kPlaintext.size() + kBackupHeaderSize + kBackupTagSize));
    std::memcpy(buffer.data(), kPlaintext.data(), kPlaintext.size());
    return buffer;
}

static void test_envelope_matches_python_cryptography_aesgcm_fixture_and_reuses_allocation() {
    ReferenceCrypto crypto;
    auto input = plaintext();
    const auto* pointer = input.data();
    SensitiveBuffer sealed;
    TEST_ASSERT_EQUAL_INT(static_cast<int>(BackupStatus::Ok),
                          static_cast<int>(sealBackup(std::move(input), kPassword, crypto, sealed)));
    TEST_ASSERT_NULL(input.data());
    TEST_ASSERT_EQUAL_PTR(pointer, sealed.data());
    const auto expected = fromHex(kFixture);
    TEST_ASSERT_EQUAL_UINT(expected.size(), sealed.size());
    TEST_ASSERT_EQUAL_MEMORY(expected.data(), sealed.data(), sealed.size());
    TEST_ASSERT_EQUAL_UINT(2, crypto.randomCalls);
    TEST_ASSERT_EQUAL_UINT(1, crypto.derivations);
    TEST_ASSERT_EQUAL_UINT(100, crypto.yields);
    TEST_ASSERT_EQUAL_UINT(1, crypto.seals);
    SensitiveBuffer opened;
    TEST_ASSERT_EQUAL_INT(static_cast<int>(BackupStatus::Ok),
                          static_cast<int>(openBackup(std::move(sealed), kPassword, crypto, opened)));
    TEST_ASSERT_NULL(sealed.data());
    TEST_ASSERT_EQUAL_PTR(pointer, opened.data());
    TEST_ASSERT_EQUAL_UINT(kPlaintext.size(), opened.size());
    TEST_ASSERT_EQUAL_MEMORY(kPlaintext.data(), opened.data(), opened.size());
    for (size_t i = opened.size(); i < opened.capacity(); ++i) TEST_ASSERT_EQUAL_UINT8(0, opened.data()[i]);
}

static void test_unsupported_headers_and_sizes_fail_before_derivation() {
    const auto valid = fromHex(kFixture);
    ReferenceCrypto crypto;
    auto output = copyBytes(reinterpret_cast<const uint8_t*>("keep"), 4);
    for (size_t at = 0; at < 10; ++at) {
        auto bad = copyBytes(valid.data(), valid.size());
        bad.data()[at] ^= 0x80;
        TEST_ASSERT_EQUAL_INT(static_cast<int>(BackupStatus::Invalid),
                              static_cast<int>(openBackup(std::move(bad), kPassword, crypto, output)));
        TEST_ASSERT_NULL(bad.data());
    }
    for (size_t length = 0; length < kBackupHeaderSize + kBackupTagSize + 2; ++length) {
        auto bad = copyBytes(valid.data(), length);
        TEST_ASSERT_EQUAL_INT(static_cast<int>(BackupStatus::Invalid),
                              static_cast<int>(openBackup(std::move(bad), kPassword, crypto, output)));
    }
    TEST_ASSERT_EQUAL_UINT(0, crypto.derivations);
    TEST_ASSERT_EQUAL_MEMORY("keep", output.data(), 4);
    BackupHeader header;
    TEST_ASSERT_TRUE(parseBackupHeader({valid.data(), kBackupHeaderSize}, header));
    const auto encoded = encodeBackupHeader(header);
    TEST_ASSERT_EQUAL_MEMORY(valid.data(), encoded.data(), encoded.size());
    const auto original = header;
    TEST_ASSERT_FALSE(parseBackupHeader({valid.data(), kBackupHeaderSize - 1}, header));
    TEST_ASSERT_TRUE(header.salt == original.salt);
    TEST_ASSERT_TRUE(header.nonce == original.nonce);
}

static void test_wrong_password_and_header_ciphertext_tag_tampering_return_no_plaintext() {
    const auto valid = fromHex(kFixture);
    ReferenceCrypto crypto;
    auto output = copyBytes(reinterpret_cast<const uint8_t*>("keep"), 4);
    TEST_ASSERT_EQUAL_INT(static_cast<int>(BackupStatus::CryptoFailed),
                          static_cast<int>(openBackup(copyBytes(valid.data(), valid.size()), "wrong password value",
                                                      crypto, output)));
    for (const size_t at : {size_t{10}, size_t{26}, kBackupHeaderSize, valid.size() - 1}) {
        auto bad = copyBytes(valid.data(), valid.size());
        bad.data()[at] ^= 1;
        TEST_ASSERT_EQUAL_INT(static_cast<int>(BackupStatus::CryptoFailed),
                              static_cast<int>(openBackup(std::move(bad), kPassword, crypto, output)));
        TEST_ASSERT_NULL(bad.data());
        TEST_ASSERT_EQUAL_UINT(4, output.size());
        TEST_ASSERT_EQUAL_MEMORY("keep", output.data(), 4);
    }
    TEST_ASSERT_EQUAL_UINT(5, crypto.opens);
}

static void test_crypto_failures_are_atomic_and_passphrases_are_bounded_utf8() {
    auto output = copyBytes(reinterpret_cast<const uint8_t*>("keep"), 4);
    for (unsigned failure = 1; failure <= 3; ++failure) {
        ReferenceCrypto crypto;
        crypto.failAt = failure;
        TEST_ASSERT_EQUAL_INT(static_cast<int>(BackupStatus::CryptoFailed),
                              static_cast<int>(sealBackup(plaintext(), kPassword, crypto, output)));
        TEST_ASSERT_EQUAL_MEMORY("keep", output.data(), 4);
    }
    ReferenceCrypto crypto;
    crypto.failAt = 4;
    const auto valid = fromHex(kFixture);
    TEST_ASSERT_EQUAL_INT(static_cast<int>(BackupStatus::CryptoFailed),
                          static_cast<int>(openBackup(copyBytes(valid.data(), valid.size()), kPassword, crypto, output)));
    TEST_ASSERT_EQUAL_MEMORY("keep", output.data(), 4);
    ReferenceCrypto unused;
    const std::string longPassword(129, 'x');
    const std::string invalidUtf8 = std::string(12, 'x') + "\xED\xA0\x80";
    for (const auto password : {std::string_view("short"), std::string_view(longPassword), std::string_view(invalidUtf8)}) {
        TEST_ASSERT_EQUAL_INT(static_cast<int>(BackupStatus::Invalid),
                              static_cast<int>(sealBackup(plaintext(), password, unused, output)));
        TEST_ASSERT_EQUAL_INT(static_cast<int>(BackupStatus::Invalid),
                              static_cast<int>(openBackup(copyBytes(valid.data(), valid.size()), password, unused, output)));
    }
    TEST_ASSERT_EQUAL_UINT(0, unused.randomCalls);
    TEST_ASSERT_EQUAL_UINT(0, unused.derivations);
}

static void test_passphrases_preserve_valid_utf8_ascii_controls() {
    std::string password = "backup passphrase\n\t\r";
    password.push_back('\0');
    password.push_back('\x7F');
    ReferenceCrypto crypto;
    SensitiveBuffer sealed;
    TEST_ASSERT_EQUAL_INT(static_cast<int>(BackupStatus::Ok),
                          static_cast<int>(sealBackup(plaintext(), password, crypto, sealed)));
    SensitiveBuffer opened;
    TEST_ASSERT_EQUAL_INT(static_cast<int>(BackupStatus::Ok),
                          static_cast<int>(openBackup(std::move(sealed), password, crypto, opened)));
    TEST_ASSERT_EQUAL_UINT(kPlaintext.size(), opened.size());
    TEST_ASSERT_EQUAL_MEMORY(kPlaintext.data(), opened.data(), opened.size());
}

int main() {
    UNITY_BEGIN();
    RUN_TEST(test_full_record_roundtrip_and_move_owned_views);
    RUN_TEST(test_minimal_record_has_explicit_fixed_wire_bytes);
    RUN_TEST(test_maximum_single_lock_fits_and_oversized_export_is_atomic);
    RUN_TEST(test_truncation_lengths_and_trailing_bytes_leave_output_unchanged);
    RUN_TEST(test_invalid_fields_and_nested_records_are_rejected);
    RUN_TEST(test_identity_and_bluetooth_address_are_preserved_independently);
    RUN_TEST(test_duplicate_identities_and_capacity_are_rejected);
    RUN_TEST(test_sensitive_buffer_moves_and_rejects_unbounded_allocation);
    RUN_TEST(test_record_secret_scalars_are_wiped_on_destruction);
    RUN_TEST(test_reference_aes256_gcm_matches_nist_vectors);
    RUN_TEST(test_envelope_matches_python_cryptography_aesgcm_fixture_and_reuses_allocation);
    RUN_TEST(test_unsupported_headers_and_sizes_fail_before_derivation);
    RUN_TEST(test_wrong_password_and_header_ciphertext_tag_tampering_return_no_plaintext);
    RUN_TEST(test_crypto_failures_are_atomic_and_passphrases_are_bounded_utf8);
    RUN_TEST(test_passphrases_preserve_valid_utf8_ascii_controls);
    return UNITY_END();
}
