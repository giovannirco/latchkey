// SPDX-License-Identifier: GPL-3.0-or-later
#include "latchkey_util/first_boot.h"

namespace latchkey_util {

FirstBootVerdict judgeFirstBoot(const FirstBootSignals& signals, uint32_t uptimeSeconds) {
    if (uptimeSeconds < kFirstBootSettleSeconds) {
        return FirstBootVerdict::Wait;
    }
    if (firstBootProblem(signals) == nullptr) {
        return FirstBootVerdict::Healthy;
    }
    return uptimeSeconds >= kFirstBootDeadlineSeconds ? FirstBootVerdict::Unhealthy : FirstBootVerdict::Wait;
}

const char* firstBootProblem(const FirstBootSignals& signals) {
    if (!signals.storageReadable) {
        return "NVS cannot be read";
    }
    if (!signals.consoleRunning) {
        return "the console is not running";
    }
    if (!signals.wifiConfigured) {
        return "Wi-Fi is not configured";
    }
    if (!signals.wifiStarted) {
        return "Wi-Fi did not start";
    }
    if (signals.wifiConnected && !signals.webServing) {
        return "the web server is not running";
    }
    return nullptr;
}

}
