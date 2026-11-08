// SPDX-License-Identifier: GPL-3.0-or-later
#pragma once

#include <array>
#include <cstddef>
#include <cstdint>
#include <string>
#include <vector>

#include "esp_err.h"
#include "latchkey_util/certificate.h"
#include "latchkey_util/label_table.h"
#include "latchkey_util/password_record.h"
#include "latchkey_util/seed_table.h"

namespace store {

struct Usage {
    size_t usedEntries = 0;
    size_t availableEntries = 0;
    size_t totalEntries = 0;
};

void init();

esp_err_t usage(Usage& out);

namespace cfg {

struct Wifi {
    std::string ssid;
    std::string password;
    uint32_t ip = 0;
    uint32_t gateway = 0;
    uint32_t netmask = 0;
    uint32_t dns = 0;
};

bool loadWifi(Wifi& out);

esp_err_t saveWifi(const Wifi& wifi);

bool loadTimezone(std::string& out);

esp_err_t saveTimezone(const std::string& timezone);

bool loadTlsIdentity(latchkey_util::TlsIdentity& out);

esp_err_t saveTlsIdentity(const latchkey_util::TlsIdentity& identity);

esp_err_t erase();

}

namespace auth {

using TotpSecret = std::array<uint8_t, 20>;

struct Owner {
    latchkey_util::PasswordRecord password;
    TotpSecret totpSecret{};
};

bool claimed();

bool loadOwner(Owner& out);

esp_err_t saveOwner(const Owner& owner);

esp_err_t savePassword(const latchkey_util::PasswordRecord& password);

esp_err_t saveTotpSecret(const TotpSecret& secret);

struct LoginState {
    uint32_t failures = 0;
    uint64_t lastStep = 0;
};

esp_err_t loadLoginState(LoginState& out);

esp_err_t saveFailures(uint32_t failures);

esp_err_t saveLastStep(uint64_t step);

esp_err_t erase();

}

namespace locks {

inline constexpr size_t kMaxLocks = 8;
inline constexpr uint8_t kRecordVersion = 1;
inline constexpr uint8_t kFlagPairComplete = 0x01;
inline constexpr uint8_t kFlagAdminPasscodeConfirmed = 0x02;
inline constexpr uint8_t kFlagTimeCalibrated = 0x04;

struct Record {
    uint8_t version = kRecordVersion;
    uint8_t flags = 0;
    uint8_t addressType = 0;
    uint8_t address[6] = {};
    char mac[18] = {};
    char name[100] = {};
    uint8_t protocolType = 0;
    uint8_t protocolVersion = 0;
    uint8_t scene = 0;
    uint16_t groupId = 0;
    uint16_t orgId = 0;
    uint8_t aesKey[16] = {};
    uint32_t adminPs = 0;
    uint32_t unlockKey = 0;
    uint32_t lockFlagPos = 0;
    uint64_t features = 0;
    char adminPasscode[16] = {};
    char model[32] = {};
    char hardware[32] = {};
    char firmware[32] = {};
    char manufactureDate[16] = {};
};

esp_err_t list(std::vector<Record>& out);

esp_err_t count(size_t& out);

esp_err_t save(const Record& record);

esp_err_t erase(const char* mac);

esp_err_t eraseAll();

}

namespace labels {

enum class Kind : char {
    Passcodes = 'p',
    Fingerprints = 'f',
    Cards = 'c',
};

esp_err_t load(const char* mac, Kind kind, latchkey_util::LabelTable& out);

esp_err_t save(const char* mac, Kind kind, const latchkey_util::LabelTable& table);

esp_err_t erase(const char* mac);

esp_err_t eraseAll();

}

namespace seeds {

esp_err_t save(const char* mac, const latchkey_util::SeedTable& table);

esp_err_t erase(const char* mac);

esp_err_t eraseAll();

}

namespace audit {

inline constexpr uint32_t kCapacity = 200;

struct Record {
    uint32_t seq;
    uint32_t utc;
    uint8_t origin;
    char method[32];
    char target[24];
    char result[20];
};

uint32_t loadNextSeq();

esp_err_t saveRecord(const Record& record);

bool loadRecord(uint32_t seq, Record& out);

esp_err_t erase();

}

}
