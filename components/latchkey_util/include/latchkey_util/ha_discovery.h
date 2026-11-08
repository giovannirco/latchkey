// SPDX-License-Identifier: GPL-3.0-or-later
#pragma once

#include <string>
#include <string_view>
#include <vector>

namespace latchkey_util {

inline constexpr char kHaOnline[] = "online";
inline constexpr char kHaOffline[] = "offline";
inline constexpr char kHaLockCommand[] = "LOCK";
inline constexpr char kHaUnlockCommand[] = "UNLOCK";
inline constexpr char kHaLocked[] = "LOCKED";
inline constexpr char kHaUnlocked[] = "UNLOCKED";
inline constexpr char kHaLinkUp[] = "ON";
inline constexpr char kHaLinkDown[] = "OFF";
inline constexpr char kHaUnexpectedUnlock[] = "unexpected_unlock";

struct HaLock {
    std::string_view discoveryPrefix;
    std::string_view board;
    std::string_view lock;
    std::string_view name;
    std::string_view model;
    std::string_view manufacturer;
    std::string_view firmware;
    std::string_view latchkeyVersion;
};

struct HaLockTopics {
    std::string availability;
    std::string state;
    std::string command;
    std::string battery;
    std::string lastEvent;
    std::string link;
    std::string alert;
};

struct MqttMessage {
    std::string topic;
    std::string payload;
};

bool haLockTopics(std::string_view board, std::string_view lock, HaLockTopics& out);

bool haDiscovery(const HaLock& lock, std::vector<MqttMessage>& out);

}
