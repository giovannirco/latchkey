// SPDX-License-Identifier: GPL-3.0-or-later
#pragma once

#include <unity.h>
#include <array>
#include <cstring>
#include <string>

#include "latchkey_util/key_restore.h"
#include "latchkey_util/label_table.h"
#include "latchkey_util/seed_table.h"

namespace backup_fixture {

inline constexpr std::string_view password = "fixture backup passphrase";

inline latchkey_util::DecodedBackup make(size_t count = 1, bool maximum = false) {
    using namespace latchkey_util;
    std::array<BackupLock, kMaxBackupLocks> locks;
    std::array<std::array<char, 18>, kMaxBackupLocks> identities{};
    const std::array<uint8_t, 16> key{1, 2, 3};
    LabelTable labels;
    std::string label = "Entry";
    if (maximum) {
        label.clear();
        for (size_t i = 0; i < 24; ++i) label += "\xC3\xA9";
    }
    for (size_t i = 0; i < (maximum ? kMaxLabels : 1); ++i) {
        TEST_ASSERT_TRUE(labels.put({i + 1, true, label, WeeklyWindow{0x7F, 0, 1440}}));
    }
    const auto labelBytes = labels.encode();
    SeedTable seeds;
    seeds.year = 2026;
    seeds.confirmed = true;
    seeds.seeds[0] = {7, 0x123456789ULL};
    const auto seedBytes = encodeSeedTable(seeds);
    const std::string name = maximum ? std::string(99, 'N') : "Entry";
    const std::string info = maximum ? std::string(31, 'M') : "Fixture";
    const std::string date = maximum ? std::string(15, 'D') : "2026-01-01";
    TEST_ASSERT_LESS_OR_EQUAL_UINT(kMaxBackupLocks, count);
    for (size_t i = 0; i < count; ++i) {
        std::memcpy(identities[i].data(), "00:00:5E:00:53:01", 18);
        identities[i][16] = static_cast<char>('1' + i);
        auto& lock = locks[i];
        lock.mac = identities[i].data();
        lock.address = {9, 0x53, 0, 0x5E, 0, 0};
        lock.addressType = 1;
        lock.flags = 7;
        lock.lifecycle = kBackupBackedUp | kBackupHardened;
        lock.protocol = {5, 3, 1, 1, 1};
        lock.aesKey = key;
        lock.adminPs = 0x12345678;
        lock.unlockKey = 0x87654321;
        lock.lockFlagPos = 0x01020304;
        lock.features = 1;
        lock.adminPasscode = "123456789";
        lock.pendingAdminPasscode = "987654321";
        lock.provenance = AdminProvenance::Owner;
        lock.pendingProvenance = AdminProvenance::PairingGenerated;
        lock.name = name;
        lock.model = lock.hardware = lock.firmware = info;
        lock.manufactureDate = date;
        lock.labels.fill(labelBytes);
        lock.seeds = seedBytes;
    }
    SensitiveBuffer plaintext;
    TEST_ASSERT_EQUAL_INT(static_cast<int>(BackupStatus::Ok),
                          static_cast<int>(encodeBackup({locks.data(), count}, plaintext)));
    DecodedBackup decoded;
    TEST_ASSERT_EQUAL_INT(static_cast<int>(BackupStatus::Ok),
                          static_cast<int>(decodeBackup(std::move(plaintext), decoded)));
    return decoded;
}

inline latchkey_util::DecodedBackup maximum() {
    using namespace latchkey_util;
    auto baseline = make(kMaxBackupLocks);
    SensitiveBuffer original;
    TEST_ASSERT_EQUAL_INT(static_cast<int>(BackupStatus::Ok), static_cast<int>(encodeBackup(baseline.locks(), original)));
    size_t remaining = kMaxBackupPlaintext - original.size();
    original.clear();
    std::array<BackupLock, kMaxBackupLocks> locks;
    std::copy(baseline.locks().begin(), baseline.locks().end(), locks.begin());
    std::array<std::vector<uint8_t>, 3 * kMaxBackupLocks> bytes;
    for (size_t index = 0; index < bytes.size() && remaining != 0; ++index) {
        auto& labels = locks[index / 3].labels[index % 3];
        const size_t added = std::min(remaining, size_t{2 + kMaxLabels * 63} - labels.size());
        const size_t target = labels.size() + added;
        const size_t count = (target - 2 + 62) / 63;
        size_t names = target - 2 - count * 15;
        LabelTable table;
        for (size_t i = 0; i < count; ++i) {
            const size_t length = std::min(names, size_t{48});
            std::string name;
            for (size_t j = 0; j < length / 2; ++j) name += "\xC3\xA9";
            if (length % 2 != 0) name += 'X';
            TEST_ASSERT_TRUE(table.put({i + 1, true, name, WeeklyWindow{0x7F, 0, 1440}}));
            names -= length;
        }
        bytes[index] = table.encode();
        TEST_ASSERT_EQUAL_UINT(target, bytes[index].size());
        labels = bytes[index];
        remaining -= added;
    }
    TEST_ASSERT_EQUAL_UINT(0, remaining);
    SensitiveBuffer plaintext;
    TEST_ASSERT_EQUAL_INT(static_cast<int>(BackupStatus::Ok), static_cast<int>(encodeBackup(locks, plaintext)));
    TEST_ASSERT_EQUAL_UINT(kMaxBackupPlaintext, plaintext.size());
    DecodedBackup decoded;
    TEST_ASSERT_EQUAL_INT(static_cast<int>(BackupStatus::Ok), static_cast<int>(decodeBackup(std::move(plaintext), decoded)));
    return decoded;
}

}
