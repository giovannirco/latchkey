// SPDX-License-Identifier: GPL-3.0-or-later
#pragma once

#include <cstdint>
#include <initializer_list>
#include <optional>
#include <string>

#include "ttlock/features.h"

namespace latchkey_util {

std::optional<ttlock::Feature> firstMissingFeature(uint64_t mask, std::initializer_list<ttlock::Feature> needed);

std::string missingFeatureMessage(ttlock::Feature feature);

}
