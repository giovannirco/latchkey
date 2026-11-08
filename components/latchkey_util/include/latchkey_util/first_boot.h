// SPDX-License-Identifier: GPL-3.0-or-later
#pragma once

#include <cstdint>

namespace latchkey_util {

inline constexpr uint32_t kFirstBootSettleSeconds = 30;
inline constexpr uint32_t kFirstBootDeadlineSeconds = 120;

struct FirstBootSignals {
    bool storageReadable = false;
    bool consoleRunning = false;
    bool wifiConfigured = false;
    bool wifiStarted = false;
    bool wifiConnected = false;
    bool webServing = false;
};

enum class FirstBootVerdict : uint8_t {
    Wait,
    Healthy,
    Unhealthy,
};

FirstBootVerdict judgeFirstBoot(const FirstBootSignals& signals, uint32_t uptimeSeconds);

const char* firstBootProblem(const FirstBootSignals& signals);

}
