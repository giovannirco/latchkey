// SPDX-License-Identifier: GPL-3.0-or-later
#include "latchkey_util/mqtt_settings.h"

#include "latchkey_util/hostname.h"

namespace latchkey_util {

bool isMqttHost(std::string_view host) { return isHostname(host); }

bool keepsPassword(const MqttBroker& stored, const MqttBroker& next) {
    return stored.host == next.host && stored.port == next.port && stored.username == next.username;
}

}
