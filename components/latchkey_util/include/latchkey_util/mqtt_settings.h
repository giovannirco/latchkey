// SPDX-License-Identifier: GPL-3.0-or-later
#pragma once

#include <cstddef>
#include <cstdint>
#include <string_view>

namespace latchkey_util {

inline constexpr size_t kMaxMqttHost = 64;
inline constexpr size_t kMaxMqttUsername = 64;
inline constexpr size_t kMaxMqttPassword = 64;
inline constexpr size_t kMaxHaPrefix = 32;
inline constexpr uint16_t kDefaultMqttPort = 1883;
inline constexpr char kDefaultHaPrefix[] = "homeassistant";

struct MqttBroker {
    std::string_view host;
    uint16_t port = kDefaultMqttPort;
    std::string_view username;
};

bool isMqttHost(std::string_view host);

bool keepsPassword(const MqttBroker& stored, const MqttBroker& next);

}
