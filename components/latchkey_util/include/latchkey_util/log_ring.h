// SPDX-License-Identifier: GPL-3.0-or-later
#pragma once

#include <cstddef>
#include <cstdint>
#include <optional>
#include <string>
#include <string_view>

namespace latchkey_util {

inline constexpr size_t kMaxLogTag = 32;
inline constexpr size_t kMaxLogMessage = 240;

enum class LogLevel : uint8_t {
    Error = 1,
    Warn = 2,
    Info = 3,
    Debug = 4,
    Verbose = 5,
};

struct LogLine {
    LogLevel level = LogLevel::Info;
    std::string_view tag;
    std::string_view message;
};

LogLine parseLogLine(std::string_view text);

std::string_view logLevelName(LogLevel level);

std::optional<LogLevel> parseLogLevel(std::string_view name);

bool passesLevel(LogLevel level, LogLevel threshold);

size_t utf8Prefix(std::string_view text, size_t maxBytes);

struct LogEntry {
    uint32_t seq = 0;
    uint32_t upMs = 0;
    LogLevel level = LogLevel::Info;
    uint8_t tagLength = 0;
    uint16_t messageLength = 0;
    char tag[kMaxLogTag] = {};
    char message[kMaxLogMessage] = {};

    std::string_view tagText() const { return {tag, tagLength}; }

    std::string_view messageText() const { return {message, messageLength}; }
};

class LogRing {
public:
    struct Cursor {
        uint32_t seq = 0;
        size_t offset = 0;
    };

    LogRing(uint8_t* storage, size_t capacity);

    uint32_t append(uint32_t upMs, const LogLine& line);

    Cursor oldestCursor() const;

    Cursor after(uint32_t seq) const;

    Cursor newest(size_t count, LogLevel threshold) const;

    bool read(Cursor& cursor, LogLevel threshold, LogEntry& out) const;

    uint32_t oldest() const;

    uint32_t next() const;

    size_t count() const;

    size_t usedBytes() const;

private:
    struct Header {
        uint32_t seq = 0;
        uint32_t upMs = 0;
        uint8_t level = 0;
        uint8_t tagLength = 0;
        uint16_t messageLength = 0;
    };

    void put(size_t offset, const void* data, size_t length);

    void get(size_t offset, void* data, size_t length) const;

    Header header(size_t offset) const;

    size_t recordSize(size_t offset) const;

    size_t advance(size_t offset, size_t length) const;

    size_t writeOffset() const;

    void dropOldest();

    uint8_t* storage_;
    size_t capacity_;
    size_t head_ = 0;
    size_t used_ = 0;
    size_t count_ = 0;
    uint32_t next_ = 1;
};

struct LogTimes {
    uint64_t uptimeMs = 0;
    std::optional<int64_t> utcMs;
};

LogTimes logTimes(uint32_t entryUpMs, uint64_t nowUpMs, std::optional<int64_t> nowUtcMs);

void appendLogEntryJson(std::string& out, const LogEntry& entry, const LogTimes& times);

}
