// SPDX-License-Identifier: GPL-3.0-or-later
#pragma once

#include <cstdint>
#include <optional>
#include <string>
#include <string_view>

#include "latchkey_util/ha_discovery.h"

namespace latchkey_util {

inline constexpr int64_t kHaLinkWindowSeconds = 120;

enum class HaCommand : uint8_t {
    Lock,
    Unlock,
    Unknown,
    Replayed,
};

HaCommand parseHaCommand(std::string_view payload, bool retained);

std::optional<std::string> haLockState(std::string_view state);

std::optional<std::string> haBattery(int battery);

std::optional<std::string> haEventText(std::string_view action, std::string_view method);

bool haAlert(const HaLockTopics& topics, std::string_view method, int64_t utc, MqttMessage& out);

std::optional<std::string> haLinkState(int64_t lastSeenUtc, int64_t nowUtc, int64_t watchedSinceUtc);

}
