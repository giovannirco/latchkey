// SPDX-License-Identifier: GPL-3.0-or-later
#include "latchkey_util/log_ring.h"

#include <algorithm>
#include <cstdio>
#include <cstring>

#include "latchkey_util/access_json.h"

namespace latchkey_util {

namespace {

constexpr size_t kHeaderBytes = 12;
constexpr size_t kPrefixStart = 3;

std::optional<LogLevel> levelOfLetter(char letter) {
    switch (letter) {
        case 'E':
            return LogLevel::Error;
        case 'W':
            return LogLevel::Warn;
        case 'I':
            return LogLevel::Info;
        case 'D':
            return LogLevel::Debug;
        case 'V':
            return LogLevel::Verbose;
        default:
            return std::nullopt;
    }
}

std::string_view withoutLineEnd(std::string_view text) {
    while (!text.empty() && (text.back() == '\n' || text.back() == '\r')) {
        text.remove_suffix(1);
    }
    return text;
}

char printable(char c) {
    const auto byte = static_cast<unsigned char>(c);
    return byte < 0x20 || byte == 0x7F ? ' ' : c;
}

void putLittleEndian(uint8_t* out, uint32_t value, size_t bytes) {
    for (size_t i = 0; i < bytes; ++i) {
        out[i] = static_cast<uint8_t>(value >> (8 * i));
    }
}

uint32_t takeLittleEndian(const uint8_t* in, size_t bytes) {
    uint32_t value = 0;
    for (size_t i = 0; i < bytes; ++i) {
        value |= static_cast<uint32_t>(in[i]) << (8 * i);
    }
    return value;
}

void appendNumber(std::string& out, unsigned long long value) {
    char text[24];
    std::snprintf(text, sizeof(text), "%llu", value);
    out += text;
}

void appendSigned(std::string& out, long long value) {
    char text[24];
    std::snprintf(text, sizeof(text), "%lld", value);
    out += text;
}

}

LogLine parseLogLine(std::string_view text) {
    text = withoutLineEnd(text);
    const LogLine whole{LogLevel::Info, {}, text};
    const std::optional<LogLevel> level = text.empty() ? std::nullopt : levelOfLetter(text[0]);
    if (!level.has_value() || text.size() < kPrefixStart || text[1] != ' ' || text[2] != '(') {
        return whole;
    }
    size_t position = kPrefixStart;
    while (position < text.size() && text[position] >= '0' && text[position] <= '9') {
        ++position;
    }
    if (position == kPrefixStart || position + 1 >= text.size() || text[position] != ')' ||
        text[position + 1] != ' ') {
        return whole;
    }
    const std::string_view rest = text.substr(position + 2);
    const size_t colon = rest.find(':');
    if (colon == std::string_view::npos || rest.substr(0, colon).find(' ') != std::string_view::npos) {
        return {*level, {}, rest};
    }
    std::string_view message = rest.substr(colon + 1);
    if (!message.empty() && message.front() == ' ') {
        message.remove_prefix(1);
    }
    return {*level, rest.substr(0, colon), message};
}

std::string_view logLevelName(LogLevel level) {
    switch (level) {
        case LogLevel::Error:
            return "error";
        case LogLevel::Warn:
            return "warn";
        case LogLevel::Info:
            return "info";
        case LogLevel::Debug:
            return "debug";
        case LogLevel::Verbose:
            return "verbose";
    }
    return "info";
}

std::optional<LogLevel> parseLogLevel(std::string_view name) {
    for (LogLevel level : {LogLevel::Error, LogLevel::Warn, LogLevel::Info, LogLevel::Debug, LogLevel::Verbose}) {
        if (name == logLevelName(level)) {
            return level;
        }
    }
    return std::nullopt;
}

bool passesLevel(LogLevel level, LogLevel threshold) {
    return static_cast<uint8_t>(level) <= static_cast<uint8_t>(threshold);
}

size_t utf8Prefix(std::string_view text, size_t maxBytes) {
    if (text.size() <= maxBytes) {
        return text.size();
    }
    size_t cut = maxBytes;
    while (cut > 0 && (static_cast<unsigned char>(text[cut]) & 0xC0) == 0x80) {
        --cut;
    }
    return cut;
}

LogRing::LogRing(uint8_t* storage, size_t capacity) : storage_(storage), capacity_(capacity) {}

size_t LogRing::advance(size_t offset, size_t length) const { return (offset + length) % capacity_; }

size_t LogRing::writeOffset() const { return advance(head_, used_); }

void LogRing::put(size_t offset, const void* data, size_t length) {
    const auto* bytes = static_cast<const uint8_t*>(data);
    const size_t first = std::min(length, capacity_ - offset);
    std::memcpy(storage_ + offset, bytes, first);
    std::memcpy(storage_, bytes + first, length - first);
}

void LogRing::get(size_t offset, void* data, size_t length) const {
    auto* bytes = static_cast<uint8_t*>(data);
    const size_t first = std::min(length, capacity_ - offset);
    std::memcpy(bytes, storage_ + offset, first);
    std::memcpy(bytes + first, storage_, length - first);
}

LogRing::Header LogRing::header(size_t offset) const {
    uint8_t raw[kHeaderBytes];
    get(offset, raw, sizeof(raw));
    Header out;
    out.seq = takeLittleEndian(raw, 4);
    out.upMs = takeLittleEndian(raw + 4, 4);
    out.level = raw[8];
    out.tagLength = raw[9];
    out.messageLength = static_cast<uint16_t>(takeLittleEndian(raw + 10, 2));
    return out;
}

size_t LogRing::recordSize(size_t offset) const {
    const Header found = header(offset);
    return kHeaderBytes + found.tagLength + found.messageLength;
}

void LogRing::dropOldest() {
    const size_t size = recordSize(head_);
    head_ = advance(head_, size);
    used_ -= size;
    --count_;
}

uint32_t LogRing::append(uint32_t upMs, const LogLine& line) {
    const size_t room = capacity_ > kHeaderBytes ? capacity_ - kHeaderBytes : 0;
    const size_t tagLength = utf8Prefix(line.tag, std::min(kMaxLogTag, room));
    const size_t messageLength = utf8Prefix(line.message, std::min(kMaxLogMessage, room - tagLength));
    const size_t size = kHeaderBytes + tagLength + messageLength;
    if (size > capacity_) {
        return next_++;
    }
    while (capacity_ - used_ < size) {
        dropOldest();
    }
    const uint32_t seq = next_++;
    uint8_t raw[kHeaderBytes];
    putLittleEndian(raw, seq, 4);
    putLittleEndian(raw + 4, upMs, 4);
    raw[8] = static_cast<uint8_t>(line.level);
    raw[9] = static_cast<uint8_t>(tagLength);
    putLittleEndian(raw + 10, static_cast<uint32_t>(messageLength), 2);
    size_t offset = writeOffset();
    put(offset, raw, sizeof(raw));
    offset = advance(offset, sizeof(raw));
    for (std::string_view text : {line.tag.substr(0, tagLength), line.message.substr(0, messageLength)}) {
        for (char c : text) {
            storage_[offset] = static_cast<uint8_t>(printable(c));
            offset = advance(offset, 1);
        }
    }
    used_ += size;
    ++count_;
    return seq;
}

LogRing::Cursor LogRing::oldestCursor() const { return {oldest(), head_}; }

LogRing::Cursor LogRing::after(uint32_t seq) const {
    const uint32_t target = seq + 1;
    if (target <= oldest()) {
        return oldestCursor();
    }
    if (target >= next_) {
        return {next_, writeOffset()};
    }
    Cursor cursor = oldestCursor();
    while (cursor.seq < target) {
        cursor.offset = advance(cursor.offset, recordSize(cursor.offset));
        ++cursor.seq;
    }
    return cursor;
}

LogRing::Cursor LogRing::newest(size_t count, LogLevel threshold) const {
    const Cursor end{next_, writeOffset()};
    if (count == 0) {
        return end;
    }
    size_t matching = 0;
    Cursor cursor = oldestCursor();
    while (cursor.seq < next_) {
        matching += passesLevel(static_cast<LogLevel>(header(cursor.offset).level), threshold) ? 1 : 0;
        cursor.offset = advance(cursor.offset, recordSize(cursor.offset));
        ++cursor.seq;
    }
    const size_t skip = matching > count ? matching - count : 0;
    size_t seen = 0;
    cursor = oldestCursor();
    while (cursor.seq < next_) {
        if (passesLevel(static_cast<LogLevel>(header(cursor.offset).level), threshold) && seen++ == skip) {
            return cursor;
        }
        cursor.offset = advance(cursor.offset, recordSize(cursor.offset));
        ++cursor.seq;
    }
    return end;
}

bool LogRing::read(Cursor& cursor, LogLevel threshold, LogEntry& out) const {
    if (cursor.seq < oldest()) {
        cursor = oldestCursor();
    }
    while (cursor.seq < next_) {
        const Header found = header(cursor.offset);
        const size_t start = cursor.offset;
        cursor.offset = advance(cursor.offset, kHeaderBytes + found.tagLength + found.messageLength);
        ++cursor.seq;
        if (!passesLevel(static_cast<LogLevel>(found.level), threshold)) {
            continue;
        }
        out.seq = found.seq;
        out.upMs = found.upMs;
        out.level = static_cast<LogLevel>(found.level);
        out.tagLength = found.tagLength;
        out.messageLength = found.messageLength;
        const size_t tagOffset = advance(start, kHeaderBytes);
        get(tagOffset, out.tag, found.tagLength);
        get(advance(tagOffset, found.tagLength), out.message, found.messageLength);
        return true;
    }
    return false;
}

uint32_t LogRing::oldest() const { return next_ - static_cast<uint32_t>(count_); }

uint32_t LogRing::next() const { return next_; }

size_t LogRing::count() const { return count_; }

size_t LogRing::usedBytes() const { return used_; }

LogTimes logTimes(uint32_t entryUpMs, uint64_t nowUpMs, std::optional<int64_t> nowUtcMs) {
    const uint32_t age = static_cast<uint32_t>(nowUpMs) - entryUpMs;
    LogTimes times;
    times.uptimeMs = nowUpMs >= age ? nowUpMs - age : 0;
    if (nowUtcMs.has_value()) {
        times.utcMs = *nowUtcMs - static_cast<int64_t>(age);
    }
    return times;
}

void appendLogEntryJson(std::string& out, const LogEntry& entry, const LogTimes& times) {
    out += "{\"seq\":";
    appendNumber(out, entry.seq);
    out += ",\"uptimeMs\":";
    appendNumber(out, times.uptimeMs);
    out += ",\"utcMs\":";
    if (times.utcMs.has_value()) {
        appendSigned(out, *times.utcMs);
    } else {
        out += "null";
    }
    out += ",\"level\":";
    appendJsonString(out, logLevelName(entry.level));
    out += ",\"tag\":";
    appendJsonString(out, entry.tagText());
    out += ",\"message\":";
    appendJsonString(out, entry.messageText());
    out += '}';
}

}
