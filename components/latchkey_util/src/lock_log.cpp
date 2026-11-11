// SPDX-License-Identifier: GPL-3.0-or-later
#include "latchkey_util/lock_log.h"

#include <algorithm>
#include <cstdio>
#include <initializer_list>

#include "latchkey_util/access_json.h"
#include "latchkey_util/credential_id.h"
#include "latchkey_util/lock_time.h"

namespace latchkey_util {

namespace {

void appendNumber(std::string& out, long long value) {
    char text[24];
    std::snprintf(text, sizeof(text), "%lld", value);
    out += text;
}

void appendEntry(std::string& out, const ttlock::LogEntry& entry, int32_t lockUtcOffsetSeconds) {
    out += "{\"seq\":";
    appendNumber(out, entry.recordNumber);
    out += ",\"time\":";
    int64_t local = 0;
    if (localSecondsOf(entry.time, local)) {
        appendNumber(out, local - lockUtcOffsetSeconds);
    } else {
        out += "null";
    }
    out += ",\"type\":";
    appendNumber(out, entry.type);
    out += ",\"battery\":";
    appendNumber(out, entry.battery);
    out += '}';
}

bool utcOf(const ttlock::LogEntry& entry, int32_t lockUtcOffsetSeconds, int64_t& out) {
    int64_t local = 0;
    if (!localSecondsOf(entry.time, local)) {
        return false;
    }
    out = local - lockUtcOffsetSeconds;
    return true;
}

bool isType(uint8_t type, std::initializer_list<uint8_t> types) {
    return std::find(types.begin(), types.end(), type) != types.end();
}

const char* credentialKind(uint8_t type) {
    if (isType(type, {4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 34, 38, 92, 93})) return "passcode";
    if (isType(type, {20, 21, 22, 23, 24, 33, 40})) return "fingerprint";
    if (isType(type, {15, 16, 17, 18, 25, 35, 39})) return "card";
    return nullptr;
}

bool failedAttempt(uint8_t type) { return isType(type, {7, 11, 12, 13, 22, 25, 38, 39, 40, 41}); }

const char* action(uint8_t type) {
    if (failedAttempt(type) || isType(type, {1, 4, 10, 17, 19, 20, 27, 28, 29, 92})) return "unlock";
    if (isType(type, {26, 33, 34, 35, 36})) return "lock";
    if (isType(type, {15, 21, 93})) return "add";
    if (isType(type, {6, 9, 18, 23})) return "delete";
    if (isType(type, {8, 16, 24})) return "clear";
    if (type == 5) return "change";
    return "unknown";
}

struct Credential {
    std::string id;
    std::string_view name;
    bool retired = false;
};

bool identify(uint8_t type, std::string_view value, const LogLabels& labels,
                const LockAesKey& key, HmacSha256 hmac, Credential& out) {
    if (isType(type, {8, 16, 24})) return true;
    const char* kind = credentialKind(type);
    const Label* label = nullptr;
    const RetiredLabel* retired = nullptr;
    if (std::string_view(kind) == "passcode") {
        if (value.size() < 4 || value.size() > 9 ||
            !std::all_of(value.begin(), value.end(), [](char c) { return c >= '0' && c <= '9'; })) return true;
        PasscodeId id;
        if (!passcodeId(key, value, hmac, id)) return false;
        const uint64_t number = passcodeIdNumber(id);
        label = labels.passcodes.find(number);
        retired = labels.retired.find('p', number);
        if (failedAttempt(type) && label == nullptr && retired == nullptr) return true;
        out.id = formatPasscodeId(id);
    } else {
        const bool fingerprint = std::string_view(kind) == "fingerprint";
        const uint64_t maximum = fingerprint ? kMaxFingerprintId : kMaxCardNumber;
        uint64_t id = 0;
        if (!parseCredentialId(value, maximum, id) || id == 0 || id == maximum) return true;
        out.id = formatCredentialId(id);
        label = (fingerprint ? labels.fingerprints : labels.cards).find(id);
        retired = labels.retired.find(fingerprint ? 'f' : 'c', id);
    }
    if (label != nullptr) out.name = label->name;
    else if (retired != nullptr) {
        out.name = retired->name;
        out.retired = true;
    }
    return true;
}

void appendNullableString(std::string& out, std::string_view value) {
    if (value.empty()) out += "null";
    else appendJsonString(out, value);
}

bool appendIdentity(std::string& out, uint8_t type, std::string_view value, const LogLabels& labels,
                      const LockAesKey& key, HmacSha256 hmac) {
    Credential credential;
    if (!identify(type, value, labels, key, hmac, credential)) return false;
    out += "{\"kind\":";
    appendJsonString(out, credentialKind(type));
    out += ",\"id\":";
    appendNullableString(out, credential.id);
    out += ",\"name\":";
    appendNullableString(out, credential.name);
    out += ",\"nameSource\":";
    appendNullableString(out, credential.name.empty() ? "" : credential.retired ? "last_known_label" : "current_label");
    out += '}';
    return true;
}

}

bool logEntryJson(const ttlock::LogEntry& entry, int32_t lockUtcOffsetSeconds, const LogLabels& labels,
                   const LockAesKey& key, HmacSha256 hmac, std::string& out) {
    std::string rendered;
    appendEntry(rendered, entry, lockUtcOffsetSeconds);
    rendered.pop_back();
    rendered += ",\"action\":";
    const char* operation = action(entry.type);
    appendJsonString(rendered, operation);
    rendered += ",\"outcome\":";
    appendJsonString(rendered, failedAttempt(entry.type) ? "failure" :
                     std::string_view(operation) == "unknown" ? "unknown" : "success");
    if (isType(entry.type, {1, 26, 28, 41, 52, 75, 76, 77})) {
        rendered += ",\"uid\":";
        appendNumber(rendered, entry.uid);
        rendered += ",\"recordId\":";
        appendNumber(rendered, entry.recordId);
    }
    if (credentialKind(entry.type) != nullptr) {
        rendered += ",\"credential\":";
        if (!appendIdentity(rendered, entry.type, entry.credential, labels, key, hmac)) return false;
        if (entry.type == 5 && !entry.newCredential.empty()) {
            rendered += ",\"newCredential\":";
            if (!appendIdentity(rendered, entry.type, entry.newCredential, labels, key, hmac)) return false;
        }
    }
    rendered += '}';
    out = std::move(rendered);
    return true;
}

std::string logEntriesJson(const std::vector<ttlock::LogEntry>& entries, int32_t lockUtcOffsetSeconds) {
    return logEntriesJson(entries, WatchState{}, lockUtcOffsetSeconds);
}

std::string logEntriesJson(const std::vector<ttlock::LogEntry>& entries, const WatchState& state,
                           int32_t unknownOffset) {
    std::string out = "[";
    for (size_t i = 0; i < entries.size(); ++i) {
        if (i > 0) {
            out += ',';
        }
        appendEntry(out, entries[i], recordOffset(state, entries[i].recordNumber, unknownOffset));
    }
    out += ']';
    return out;
}

LogStep stepLog(const WatchState& state, const ttlock::LogPage& page, int32_t lockUtcOffsetSeconds) {
    LogStep step;
    step.state = state;
    uint32_t newest = state.lastUtc;
    uint16_t highest = 0;
    for (size_t i = 0; i < page.entries.size(); ++i) {
        const ttlock::LogEntry& entry = page.entries[i];
        int64_t utc = 0;
        const bool datable = utcOf(entry, recordOffset(state, entry.recordNumber, lockUtcOffsetSeconds), utc);
        const bool restarted = state.lastUtc != 0 && datable && utc > static_cast<int64_t>(state.lastUtc);
        if (entry.recordNumber < state.cursor && !restarted) {
            continue;
        }
        step.fresh.push_back(i);
        highest = std::max(highest, entry.recordNumber);
        if (datable && utc > static_cast<int64_t>(newest)) {
            newest = static_cast<uint32_t>(utc);
        }
    }
    if (step.fresh.empty()) {
        return step;
    }
    step.state.cursor = page.sequence != 0 ? page.sequence : static_cast<uint16_t>(highest + 1);
    step.state.lastUtc = newest;
    step.more = page.sequence != 0;
    return step;
}

bool LogEndSearch::done() const { return low_ > high_; }

uint16_t LogEndSearch::slot() const { return static_cast<uint16_t>((low_ + high_) / 2); }

void LogEndSearch::read(const ttlock::LogPage& page, int32_t lockUtcOffsetSeconds) {
    const uint16_t asked = slot();
    ++reads_;
    const ttlock::LogEntry* found = nullptr;
    for (const ttlock::LogEntry& entry : page.entries) {
        int64_t utc = 0;
        if (entry.recordNumber >= asked && utcOf(entry, lockUtcOffsetSeconds, utc) &&
            utc > static_cast<int64_t>(lastUtc_)) {
            lastUtc_ = static_cast<uint32_t>(utc);
        }
        if (entry.recordNumber >= asked && (found == nullptr || entry.recordNumber > found->recordNumber)) {
            found = &entry;
        }
    }
    if (found == nullptr) {
        high_ = asked - 1;
        return;
    }
    cursor_ = page.sequence > found->recordNumber ? page.sequence : static_cast<uint16_t>(found->recordNumber + 1);
    low_ = asked + 1;
}

WatchState LogEndSearch::baseline(const WatchState& state) const {
    WatchState out = state;
    out.baselined = true;
    out.cursor = cursor_;
    out.lastUtc = lastUtc_;
    return out;
}

size_t LogEndSearch::reads() const { return reads_; }

}
