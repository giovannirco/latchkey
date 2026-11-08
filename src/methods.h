// SPDX-License-Identifier: GPL-3.0-or-later
#pragma once

#include "cJSON.h"

namespace methods {

void registerSystem();

void registerLogging();

void addLoggingInfo(cJSON* info);

void registerAuth();

void registerLocks();

void registerPasscodes();

void registerCredentials();

void registerAdminPasscode();

void registerMqtt();

}
