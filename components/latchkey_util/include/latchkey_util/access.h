// SPDX-License-Identifier: GPL-3.0-or-later
#pragma once

namespace latchkey_util {

struct AccessRule {
    bool needsSession = true;
    bool needsButton = false;
    bool serialOnly = false;
};

struct AccessDecision {
    const char* error = nullptr;
    const char* message = nullptr;
    bool audited = true;
};

AccessDecision decideAccess(const AccessRule& rule, bool serial, bool hasSession);

}
