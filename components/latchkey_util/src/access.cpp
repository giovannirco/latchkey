// SPDX-License-Identifier: GPL-3.0-or-later
#include "latchkey_util/access.h"

namespace latchkey_util {

AccessDecision decideAccess(const AccessRule& rule, bool serial, bool hasSession) {
    AccessDecision decision;
    if (serial) {
        return decision;
    }
    if (rule.serialOnly) {
        decision.error = "forbidden";
        decision.message = "serial console only";
    } else if (rule.needsSession && !hasSession) {
        decision.error = "unauthorized";
        decision.message = "sign in first";
    } else if (rule.needsButton) {
        decision.error = "forbidden";
        decision.message = "this needs a press of the board's button, which the web cannot ask for yet";
    } else {
        return decision;
    }
    decision.audited = hasSession;
    return decision;
}

}
