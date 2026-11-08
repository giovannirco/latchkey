// SPDX-License-Identifier: GPL-3.0-or-later
#pragma once

#include <cstddef>
#include <cstdint>
#include <optional>
#include <string>
#include <string_view>

#include "latchkey_util/log_ring.h"

namespace latchkey_util {

inline constexpr uint16_t kDefaultSyslogPort = 514;
inline constexpr size_t kMaxSyslogAppName = 48;
inline constexpr char kDefaultSyslogAppName[] = "latchkey";
inline constexpr size_t kMaxSyslogUdpMessage = 1024;
inline constexpr size_t kMaxSyslogTcpMessage = 2048;

struct SyslogMessage {
    LogLevel level = LogLevel::Info;
    uint32_t seq = 0;
    uint64_t uptimeMs = 0;
    std::optional<int64_t> utcMs;
    std::string_view hostname;
    std::string_view appName;
    std::string_view tag;
    std::string_view message;
};

uint8_t syslogSeverity(LogLevel level);

void formatSyslog(std::string& out, const SyslogMessage& message, size_t maxBytes);

void frameOctetCounted(std::string& out, std::string_view message);

bool isSyslogAppName(std::string_view name);

}
