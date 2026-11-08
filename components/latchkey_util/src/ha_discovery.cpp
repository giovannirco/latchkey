// SPDX-License-Identifier: GPL-3.0-or-later
#include "latchkey_util/ha_discovery.h"

#include <cstddef>
#include <cstdint>
#include <initializer_list>
#include <utility>

namespace latchkey_util {

namespace {

constexpr char kHexDigits[] = "0123456789abcdef";
constexpr char kTopicRoot[] = "latchkey/";
constexpr char kIdPrefix[] = "latchkey_";
constexpr uint8_t kFirstPrintable = 0x20;

bool isId(std::string_view id) {
    if (id.empty()) {
        return false;
    }
    for (char c : id) {
        const bool allowed =
            (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') || (c >= '0' && c <= '9') || c == '_' || c == '-';
        if (!allowed) {
            return false;
        }
    }
    return true;
}

bool inRange(uint8_t byte, uint8_t low, uint8_t high) { return byte >= low && byte <= high; }

size_t sequenceLength(std::string_view text, size_t at) {
    const auto lead = static_cast<uint8_t>(text[at]);
    if (lead < 0x80) {
        return 1;
    }
    uint8_t secondLow = 0x80;
    uint8_t secondHigh = 0xBF;
    size_t length = 0;
    if (inRange(lead, 0xC2, 0xDF)) {
        length = 2;
    } else if (inRange(lead, 0xE0, 0xEF)) {
        length = 3;
        secondLow = lead == 0xE0 ? 0xA0 : 0x80;
        secondHigh = lead == 0xED ? 0x9F : 0xBF;
    } else if (inRange(lead, 0xF0, 0xF4)) {
        length = 4;
        secondLow = lead == 0xF0 ? 0x90 : 0x80;
        secondHigh = lead == 0xF4 ? 0x8F : 0xBF;
    } else {
        return 0;
    }
    if (at + length > text.size() || !inRange(static_cast<uint8_t>(text[at + 1]), secondLow, secondHigh)) {
        return 0;
    }
    for (size_t i = 2; i < length; ++i) {
        if (!inRange(static_cast<uint8_t>(text[at + i]), 0x80, 0xBF)) {
            return 0;
        }
    }
    return length;
}

void appendAscii(std::string& out, uint8_t byte) {
    switch (byte) {
        case '"':
            out += "\\\"";
            return;
        case '\\':
            out += "\\\\";
            return;
        case '\b':
            out += "\\b";
            return;
        case '\f':
            out += "\\f";
            return;
        case '\n':
            out += "\\n";
            return;
        case '\r':
            out += "\\r";
            return;
        case '\t':
            out += "\\t";
            return;
        default:
            break;
    }
    if (byte < kFirstPrintable) {
        out += "\\u00";
        out += kHexDigits[byte >> 4];
        out += kHexDigits[byte & 0x0F];
        return;
    }
    out += static_cast<char>(byte);
}

bool appendString(std::string& out, std::string_view text) {
    out += '"';
    for (size_t at = 0; at < text.size();) {
        const size_t length = sequenceLength(text, at);
        if (length == 0) {
            return false;
        }
        if (length == 1) {
            appendAscii(out, static_cast<uint8_t>(text[at]));
        } else {
            out.append(text.data() + at, length);
        }
        at += length;
    }
    out += '"';
    return true;
}

class JsonObject {
public:
    JsonObject& text(std::string_view key, std::string_view value) {
        name(key);
        valid_ = appendString(text_, value) && valid_;
        return *this;
    }

    JsonObject& optionalText(std::string_view key, std::string_view value) {
        return value.empty() ? *this : text(key, value);
    }

    JsonObject& nameOrNull(const char* value) {
        if (value == nullptr) {
            name("name");
            text_ += "null";
            return *this;
        }
        return text("name", value);
    }

    JsonObject& textList(std::string_view key, std::string_view value) {
        name(key);
        text_ += '[';
        valid_ = appendString(text_, value) && valid_;
        text_ += ']';
        return *this;
    }

    JsonObject& object(std::string_view key, const JsonObject& value) {
        name(key);
        text_ += value.text_;
        text_ += '}';
        valid_ = value.valid_ && valid_;
        return *this;
    }

    bool finish(std::string& out) const {
        if (!valid_) {
            return false;
        }
        out = text_ + '}';
        return true;
    }

private:
    void name(std::string_view key) {
        if (text_.size() > 1) {
            text_ += ',';
        }
        appendString(text_, key);
        text_ += ':';
    }

    std::string text_ = "{";
    bool valid_ = true;
};

std::string joined(std::initializer_list<std::string_view> parts) {
    std::string out;
    for (std::string_view part : parts) {
        out += part;
    }
    return out;
}

class Discovery {
public:
    Discovery(const HaLock& lock, const HaLockTopics& topics) : lock_(lock), topics_(topics) {}

    JsonObject entity(const char* name, std::string_view suffix) const {
        JsonObject device;
        device.textList("identifiers", joined({kIdPrefix, lock_.lock}))
            .text("name", lock_.name)
            .optionalText("model", lock_.model)
            .optionalText("manufacturer", lock_.manufacturer)
            .optionalText("sw_version", lock_.firmware);
        JsonObject origin;
        origin.text("name", "Latchkey").optionalText("sw_version", lock_.latchkeyVersion);
        JsonObject entity;
        entity.nameOrNull(name)
            .text("unique_id", joined({kIdPrefix, lock_.board, "_", lock_.lock, "_", suffix}))
            .object("device", device)
            .object("origin", origin)
            .text("availability_topic", topics_.availability)
            .text("payload_available", kHaOnline)
            .text("payload_not_available", kHaOffline);
        return entity;
    }

    bool add(std::string_view component, std::string_view objectId, const JsonObject& config,
             std::vector<MqttMessage>& out) const {
        MqttMessage message;
        message.topic = joined({lock_.discoveryPrefix, "/", component, "/", lock_.board, "/", objectId, "/config"});
        if (!config.finish(message.payload)) {
            return false;
        }
        out.push_back(std::move(message));
        return true;
    }

    std::string objectId(std::string_view suffix) const { return joined({lock_.lock, "_", suffix}); }

private:
    const HaLock& lock_;
    const HaLockTopics& topics_;
};

}

bool haLockTopics(std::string_view board, std::string_view lock, HaLockTopics& out) {
    if (!isId(board) || !isId(lock)) {
        return false;
    }
    const std::string base = joined({kTopicRoot, board, "/", lock, "/"});
    HaLockTopics topics;
    topics.availability = joined({kTopicRoot, board, "/availability"});
    topics.state = base + "state";
    topics.command = base + "set";
    topics.battery = base + "battery";
    topics.lastEvent = base + "last_event";
    topics.link = base + "link";
    topics.alert = base + "alert";
    out = std::move(topics);
    return true;
}

bool haDiscovery(const HaLock& lock, std::vector<MqttMessage>& out) {
    HaLockTopics topics;
    if (!isId(lock.discoveryPrefix) || lock.name.empty() || !haLockTopics(lock.board, lock.lock, topics)) {
        return false;
    }
    const Discovery discovery(lock, topics);
    JsonObject lockEntity = discovery.entity(nullptr, "lock");
    lockEntity.text("state_topic", topics.state)
        .text("command_topic", topics.command)
        .text("payload_lock", kHaLockCommand)
        .text("payload_unlock", kHaUnlockCommand)
        .text("state_locked", kHaLocked)
        .text("state_unlocked", kHaUnlocked);
    JsonObject battery = discovery.entity("Battery", "battery");
    battery.text("state_topic", topics.battery)
        .text("device_class", "battery")
        .text("state_class", "measurement")
        .text("unit_of_measurement", "%")
        .text("entity_category", "diagnostic");
    JsonObject lastEvent = discovery.entity("Last event", "last_event");
    lastEvent.text("state_topic", topics.lastEvent);
    JsonObject link = discovery.entity("Bluetooth link", "link");
    link.text("state_topic", topics.link)
        .text("device_class", "connectivity")
        .text("payload_on", kHaLinkUp)
        .text("payload_off", kHaLinkDown)
        .text("entity_category", "diagnostic");
    JsonObject alert = discovery.entity("Unlock alert", "unlock_alert");
    alert.text("state_topic", topics.alert).textList("event_types", kHaUnexpectedUnlock);
    std::vector<MqttMessage> messages;
    const bool built = discovery.add("lock", lock.lock, lockEntity, messages) &&
                       discovery.add("sensor", discovery.objectId("battery"), battery, messages) &&
                       discovery.add("sensor", discovery.objectId("last_event"), lastEvent, messages) &&
                       discovery.add("binary_sensor", discovery.objectId("link"), link, messages) &&
                       discovery.add("event", discovery.objectId("unlock_alert"), alert, messages);
    if (!built) {
        return false;
    }
    out = std::move(messages);
    return true;
}

}
