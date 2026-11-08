// SPDX-License-Identifier: GPL-3.0-or-later
#include "latchkey_util/ha_discovery.h"

#include <cstddef>
#include <cstdint>
#include <initializer_list>
#include <utility>

#include "latchkey_util/ble_adv.h"

namespace latchkey_util {

namespace {

constexpr char kHexDigits[] = "0123456789abcdef";
constexpr char kTopicRoot[] = "latchkey";
constexpr char kIdPrefix[] = "latchkey_";
constexpr char kBoardPrefix[] = "latchkey-";
constexpr char kCommandLevel[] = "set";
constexpr char kConfigLevel[] = "config";
constexpr size_t kLockIdSize = 2 * kBleAddressSize;
constexpr uint8_t kFirstPrintable = 0x20;

struct Entity {
    std::string_view component;
    std::string_view suffix;
};

constexpr Entity kLockEntity{"lock", ""};
constexpr Entity kBatteryEntity{"sensor", "battery"};
constexpr Entity kLastEventEntity{"sensor", "last_event"};
constexpr Entity kLinkEntity{"binary_sensor", "link"};
constexpr Entity kAlertEntity{"event", "unlock_alert"};
constexpr Entity kEntities[] = {kLockEntity, kBatteryEntity, kLastEventEntity, kLinkEntity, kAlertEntity};

bool isLockId(std::string_view id) {
    if (id.size() != kLockIdSize) {
        return false;
    }
    for (char c : id) {
        if (!((c >= '0' && c <= '9') || (c >= 'a' && c <= 'f'))) {
            return false;
        }
    }
    return true;
}

std::vector<std::string_view> levels(std::string_view topic) {
    std::vector<std::string_view> parts;
    size_t start = 0;
    while (true) {
        const size_t slash = topic.find('/', start);
        parts.push_back(topic.substr(start, slash == std::string_view::npos ? std::string_view::npos : slash - start));
        if (slash == std::string_view::npos) {
            return parts;
        }
        start = slash + 1;
    }
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

std::string objectIdOf(std::string_view lock, std::string_view suffix) {
    return suffix.empty() ? std::string(lock) : joined({lock, "_", suffix});
}

std::string configTopic(std::string_view prefix, const Entity& kind, std::string_view board, std::string_view lock) {
    return joined({prefix, "/", kind.component, "/", board, "/", objectIdOf(lock, kind.suffix), "/", kConfigLevel});
}

int nibble(char digit) { return digit <= '9' ? digit - '0' : digit - 'a' + 10; }

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

    bool add(const Entity& kind, const JsonObject& config, std::vector<MqttMessage>& out) const {
        MqttMessage message;
        message.topic = configTopic(lock_.discoveryPrefix, kind, lock_.board, lock_.lock);
        message.retain = true;
        if (!config.finish(message.payload)) {
            return false;
        }
        out.push_back(std::move(message));
        return true;
    }

private:
    const HaLock& lock_;
    const HaLockTopics& topics_;
};

}

bool isHaId(std::string_view id) {
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

std::string haBoardId(const uint8_t (&mac)[6]) {
    std::string id(kBoardPrefix);
    for (size_t i = 3; i < 6; ++i) {
        id += kHexDigits[mac[i] >> 4];
        id += kHexDigits[mac[i] & 0x0F];
    }
    return id;
}

bool haLockId(std::string_view mac, std::string& out) {
    uint8_t address[kBleAddressSize];
    if (!parseBleAddress(mac, address)) {
        return false;
    }
    std::string id;
    for (size_t i = kBleAddressSize; i > 0; --i) {
        id += kHexDigits[address[i - 1] >> 4];
        id += kHexDigits[address[i - 1] & 0x0F];
    }
    out = std::move(id);
    return true;
}

bool haLockMac(std::string_view lock, std::string& out) {
    if (!isLockId(lock)) {
        return false;
    }
    uint8_t address[kBleAddressSize];
    for (size_t octet = 0; octet < kBleAddressSize; ++octet) {
        address[kBleAddressSize - 1 - octet] =
            static_cast<uint8_t>(nibble(lock[2 * octet]) << 4 | nibble(lock[2 * octet + 1]));
    }
    out = formatBleAddress(address);
    return true;
}

bool haLockTopics(std::string_view board, std::string_view lock, HaLockTopics& out) {
    if (!isHaId(board) || !isHaId(lock)) {
        return false;
    }
    const std::string base = joined({kTopicRoot, "/", board, "/", lock, "/"});
    HaLockTopics topics;
    topics.availability = joined({kTopicRoot, "/", board, "/availability"});
    topics.state = base + "state";
    topics.command = base + kCommandLevel;
    topics.battery = base + "battery";
    topics.lastEvent = base + "last_event";
    topics.link = base + "link";
    topics.alert = base + "alert";
    out = std::move(topics);
    return true;
}

bool haDiscovery(const HaLock& lock, std::vector<MqttMessage>& out) {
    HaLockTopics topics;
    if (!isHaId(lock.discoveryPrefix) || lock.name.empty() || !haLockTopics(lock.board, lock.lock, topics)) {
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
    const bool built = discovery.add(kLockEntity, lockEntity, messages) &&
                       discovery.add(kBatteryEntity, battery, messages) &&
                       discovery.add(kLastEventEntity, lastEvent, messages) &&
                       discovery.add(kLinkEntity, link, messages) && discovery.add(kAlertEntity, alert, messages);
    if (!built) {
        return false;
    }
    out = std::move(messages);
    return true;
}

bool haRemoval(std::string_view discoveryPrefix, std::string_view board, std::string_view lock,
               std::vector<MqttMessage>& out) {
    HaLockTopics topics;
    if (!isHaId(discoveryPrefix) || !haLockTopics(board, lock, topics)) {
        return false;
    }
    std::vector<MqttMessage> messages;
    for (const Entity& kind : kEntities) {
        messages.push_back(MqttMessage{configTopic(discoveryPrefix, kind, board, lock), "", true});
    }
    for (const std::string* topic : {&topics.state, &topics.battery, &topics.lastEvent, &topics.link}) {
        messages.push_back(MqttMessage{*topic, "", true});
    }
    out = std::move(messages);
    return true;
}

std::optional<std::string> haConfigLock(std::string_view topic, std::string_view discoveryPrefix,
                                        std::string_view board) {
    const std::vector<std::string_view> parts = levels(topic);
    if (parts.size() != 5 || parts[0] != discoveryPrefix || parts[2] != board || parts[4] != kConfigLevel) {
        return std::nullopt;
    }
    const std::string_view objectId = parts[3];
    const std::string_view lock = objectId.substr(0, objectId.find('_'));
    if (!isLockId(lock)) {
        return std::nullopt;
    }
    for (const Entity& kind : kEntities) {
        if (parts[1] == kind.component && objectId == objectIdOf(lock, kind.suffix)) {
            return std::string(lock);
        }
    }
    return std::nullopt;
}

std::optional<std::string> haCommandLock(std::string_view topic, std::string_view board) {
    const std::vector<std::string_view> parts = levels(topic);
    if (parts.size() != 4 || parts[0] != kTopicRoot || parts[1] != board || parts[3] != kCommandLevel ||
        !isLockId(parts[2])) {
        return std::nullopt;
    }
    return std::string(parts[2]);
}

}
