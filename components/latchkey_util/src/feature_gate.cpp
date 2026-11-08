// SPDX-License-Identifier: GPL-3.0-or-later
#include "latchkey_util/feature_gate.h"

namespace latchkey_util {

std::optional<ttlock::Feature> firstMissingFeature(uint64_t mask, std::initializer_list<ttlock::Feature> needed) {
    for (const ttlock::Feature feature : needed) {
        if (!ttlock::hasFeature(mask, feature)) {
            return feature;
        }
    }
    return std::nullopt;
}

std::string missingFeatureMessage(ttlock::Feature feature) {
    return std::string("the lock does not report ") + ttlock::toString(feature);
}

}
