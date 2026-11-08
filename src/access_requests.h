// SPDX-License-Identifier: GPL-3.0-or-later
#pragma once

#include <cstddef>
#include <cstdint>
#include <initializer_list>
#include <optional>
#include <string>
#include <string_view>

#include "cJSON.h"
#include "esp_err.h"
#include "latchkey_util/access_json.h"
#include "latchkey_util/weekly_window.h"
#include "rpc.h"
#include "ttlock/features.h"
#include "ttlock/types.h"

namespace lock_access {

inline constexpr const char* kLockMessage = "lock must be a Bluetooth address like AA:BB:CC:DD:EE:FF";
inline constexpr const char* kNameMessage = "name must be at most 24 characters (at most 48 bytes)";
inline constexpr const char* kCodeMessage = "code must be 4 to 9 digits, or left out for a random one";
inline constexpr const char* kValidityMessage =
    "validity must be {start, end} in UTC seconds, the end after the start, within the lock's years 2000 to 2099";
inline constexpr const char* kCycleMessage =
    "cycle must be {days: weekdays 1 (Monday) to 7 (Sunday), start: \"HH:MM\", end: \"HH:MM\"}, ending after it "
    "starts";
inline constexpr const char* kInUseMessage = "that code is already in use on the lock";
inline constexpr const char* kLabelsFullMessage = "the board keeps names for at most 32 entries of each kind per lock";
inline constexpr const char* kNamesNotStored = "the lock took the change, but the board could not store its names";

void wipe(std::string& text);

class Secret {
public:
    Secret() = default;
    explicit Secret(std::string_view value) : value_(value) {}
    Secret(const Secret& other) : value_(other.value_) {}
    Secret& operator=(const Secret& other);
    ~Secret() { wipe(value_); }

    const std::string& get() const { return value_; }
    bool empty() const { return value_.empty(); }

private:
    std::string value_;
};

rpc::Reply invalid(const char* message);

rpc::Reply withTarget(rpc::Reply reply, const std::string& mac);

const cJSON* member(const cJSON* params, const char* key);

bool absent(const cJSON* item);

bool readLock(const cJSON* params, std::string& out);

bool readName(const cJSON* item, std::string& out);

bool readCode(const cJSON* item, Secret& out);

bool readWindow(const cJSON* item, ttlock::Validity& out);

bool readCycle(const cJSON* item, std::optional<latchkey_util::WeeklyWindow>& out);

bool readCredentialId(const cJSON* item, uint64_t maximum, uint64_t& out);

rpc::Reply gate(const std::string& mac, std::initializer_list<ttlock::Feature> needed);

bool utcWindow(const ttlock::Validity& validity, latchkey_util::UtcWindow& out);

rpc::Reply labelsUnreadable(esp_err_t error);

rpc::Reply storageFull();

bool listFits(size_t textBound);

rpc::Reply tooLarge(size_t entries, const char* noun);

cJSON* rawJson(const std::string& text);

std::string easyCodeWarning(const std::string& code);

void addWarnings(cJSON* result, std::initializer_list<std::string_view> warnings);

}
