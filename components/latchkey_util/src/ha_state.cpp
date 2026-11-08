// SPDX-License-Identifier: GPL-3.0-or-later
#include "latchkey_util/ha_state.h"

#include <cstddef>
#include <utility>

namespace latchkey_util {

namespace {

constexpr int kFullBattery = 100;
constexpr size_t kMaxAlertMethod = 16;

struct MethodText {
    std::string_view method;
    std::string_view text;
};

constexpr MethodText kMethodTexts[] = {
    {"app", "from the app"},
    {"passcode", "with a passcode"},
    {"fingerprint", "with a fingerprint"},
    {"card", "with a card"},
    {"key", "with the mechanical key"},
    {"auto", "automatically"},
    {"remote", "remotely"},
    {"button", "with the inside button"},
};

bool isPlainName(std::string_view name) {
    if (name.empty() || name.size() > kMaxAlertMethod) {
        return false;
    }
    for (char c : name) {
        if (!((c >= 'a' && c <= 'z') || c == '_')) {
            return false;
        }
    }
    return true;
}

}

HaCommand parseHaCommand(std::string_view payload, bool retained) {
    if (retained) {
        return HaCommand::Replayed;
    }
    if (payload == kHaLockCommand) {
        return HaCommand::Lock;
    }
    if (payload == kHaUnlockCommand) {
        return HaCommand::Unlock;
    }
    return HaCommand::Unknown;
}

std::optional<std::string> haLockState(std::string_view state) {
    if (state == "locked") {
        return std::string(kHaLocked);
    }
    if (state == "unlocked") {
        return std::string(kHaUnlocked);
    }
    return std::nullopt;
}

std::optional<std::string> haBattery(int battery) {
    if (battery < 0 || battery > kFullBattery) {
        return std::nullopt;
    }
    return std::to_string(battery);
}

std::optional<std::string> haEventText(std::string_view action, std::string_view method) {
    std::string text;
    if (action == "lock") {
        text = "Locked";
    } else if (action == "unlock") {
        text = "Unlocked";
    } else {
        return std::nullopt;
    }
    if (method.empty()) {
        return text;
    }
    for (const MethodText& known : kMethodTexts) {
        if (known.method == method) {
            text += ' ';
            text += known.text;
            return text;
        }
    }
    text += " by ";
    text += method;
    return text;
}

bool haAlert(const HaLockTopics& topics, std::string_view method, int64_t utc, MqttMessage& out) {
    if (!isPlainName(method)) {
        return false;
    }
    MqttMessage message;
    message.topic = topics.alert;
    message.payload = std::string(R"({"event_type":")") + kHaUnexpectedUnlock + R"(","method":")" +
                      std::string(method) + R"(","time":)" + std::to_string(utc) + "}";
    message.retain = false;
    out = std::move(message);
    return true;
}

std::optional<std::string> haLinkState(int64_t lastSeenUtc, int64_t nowUtc, int64_t watchedSinceUtc) {
    if (nowUtc <= 0) {
        return std::nullopt;
    }
    if (lastSeenUtc > 0 && nowUtc - lastSeenUtc <= kHaLinkWindowSeconds) {
        return std::string(kHaLinkUp);
    }
    if (lastSeenUtc <= 0 && nowUtc - watchedSinceUtc <= kHaLinkWindowSeconds) {
        return std::nullopt;
    }
    return std::string(kHaLinkDown);
}

}
