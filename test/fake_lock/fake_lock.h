// SPDX-License-Identifier: GPL-3.0-or-later
#pragma once

#include <cstddef>
#include <cstdint>
#include <deque>
#include <initializer_list>
#include <string>
#include <utility>
#include <vector>

#include "ttlock/aes.h"
#include "ttlock/bytes.h"
#include "ttlock/frame.h"
#include "ttlock/status.h"
#include "ttlock/transport.h"

namespace fake {

using ttlock::AesKey;
using ttlock::Bytes;
using ttlock::Status;

inline constexpr ttlock::LockVersion kRequestVersion{5, 3, 1, 1, 1};
inline constexpr ttlock::LockVersion kReplyVersion{5, 3, 2, 1, 1};
inline constexpr uint8_t kReplyCommand = 0x54;
inline constexpr uint8_t kSuccess = 0x01;
inline constexpr uint8_t kFailed = 0x00;

inline Bytes concat(std::initializer_list<Bytes> parts) {
    Bytes out;
    for (const Bytes& part : parts) {
        out.insert(out.end(), part.begin(), part.end());
    }
    return out;
}

inline Bytes text(const std::string& value) {
    return Bytes(value.begin(), value.end());
}

inline Bytes be32(uint32_t value) {
    return Bytes{static_cast<uint8_t>(value >> 24), static_cast<uint8_t>(value >> 16), static_cast<uint8_t>(value >> 8),
                 static_cast<uint8_t>(value)};
}

inline Bytes lockFrame(const AesKey& key, const Bytes& plain) {
    Bytes wire = ttlock::encodeFrame(kReplyVersion, kReplyCommand, plain, key);
    wire.resize(wire.size() - 2);
    return wire;
}

inline Bytes success(const AesKey& key, uint8_t command, const Bytes& data = {}) {
    return lockFrame(key, concat({Bytes{command, kSuccess}, data}));
}

inline Bytes failure(const AesKey& key, uint8_t command, uint8_t code) {
    return lockFrame(key, Bytes{command, kFailed, code});
}

inline Bytes withBadCrc(Bytes frame) {
    frame.back() ^= 0xFF;
    return frame;
}

struct Request {
    uint8_t command = 0;
    Bytes payload;
    ttlock::LockVersion version;
    bool decoded = false;
    bool crcOk = false;
    bool crlf = false;
    Bytes raw;
};

enum class After : uint8_t {
    Stay,
    Drop,
};

struct Step {
    uint8_t command = 0;
    AesKey key{};
    std::vector<Bytes> replies;
    After after = After::Stay;
};

class FakeLock : public ttlock::Transport {
public:
    void expect(uint8_t command, const AesKey& key, std::vector<Bytes> replies, After after = After::Stay) {
        script_.push_back(Step{command, key, std::move(replies), after});
    }

    void push(Bytes frame) {
        inbox_.push_back(std::move(frame));
    }

    Status send(const Bytes& wire) override {
        if (dropped_ || (dropPending_ && inbox_.empty())) {
            dropped_ = true;
            return Status::Disconnected;
        }
        const bool scripted = cursor_ < script_.size();
        const AesKey key = scripted ? script_[cursor_].key : ttlock::kDefaultAesKey;
        requests_.push_back(decodeRequest(wire, key));
        if (!scripted) {
            ++unexpected_;
            return Status::Ok;
        }
        Step& step = script_[cursor_++];
        if (step.command != requests_.back().command || !requests_.back().decoded) {
            ++unexpected_;
        }
        for (Bytes& reply : step.replies) {
            inbox_.push_back(std::move(reply));
        }
        dropPending_ = step.after == After::Drop;
        return Status::Ok;
    }

    Status receive(Bytes& frame, uint32_t timeoutMs) override {
        receiveTimeouts_.push_back(timeoutMs);
        if (!inbox_.empty()) {
            frame = std::move(inbox_.front());
            inbox_.pop_front();
            return Status::Ok;
        }
        if (dropped_ || dropPending_) {
            dropped_ = true;
            return Status::Disconnected;
        }
        return Status::Timeout;
    }

    const std::vector<Request>& requests() const {
        return requests_;
    }

    std::vector<uint8_t> commands() const {
        std::vector<uint8_t> out;
        for (const Request& request : requests_) {
            out.push_back(request.command);
        }
        return out;
    }

    const std::vector<uint32_t>& receiveTimeouts() const {
        return receiveTimeouts_;
    }

    bool scriptDone() const {
        return cursor_ == script_.size() && inbox_.empty();
    }

    size_t unexpected() const {
        return unexpected_;
    }

private:
    static Request decodeRequest(const Bytes& wire, const AesKey& key) {
        Request request;
        request.crlf = wire.size() >= 2 && wire[wire.size() - 2] == 0x0D && wire.back() == 0x0A;
        if (!request.crlf) {
            return request;
        }
        const Bytes raw(wire.begin(), wire.end() - 2);
        request.raw = raw;
        ttlock::DecodedFrame frame;
        if (ttlock::decodeFrame(raw, key, frame) != Status::Ok) {
            return request;
        }
        request.decoded = true;
        request.command = frame.command;
        request.payload = frame.payload;
        request.crcOk = frame.crcOk;
        request.version = ttlock::LockVersion{raw[2], raw[3], raw[4], static_cast<uint16_t>(raw[5] << 8 | raw[6]),
                                              static_cast<uint16_t>(raw[7] << 8 | raw[8])};
        return request;
    }

    std::vector<Step> script_;
    size_t cursor_ = 0;
    std::deque<Bytes> inbox_;
    std::vector<Request> requests_;
    std::vector<uint32_t> receiveTimeouts_;
    bool dropPending_ = false;
    bool dropped_ = false;
    size_t unexpected_ = 0;
};

class FakeClock : public ttlock::Clock {
public:
    bool isSynced = true;
    int64_t utc = 1762524000;
    int32_t offset = -3 * 3600;

    bool synced() override {
        return isSynced;
    }

    int64_t utcSeconds() override {
        return utc;
    }

    int32_t utcOffsetSeconds() override {
        return offset;
    }
};

class FakeRandom : public ttlock::Random {
public:
    void script(std::initializer_list<uint8_t> bytes) {
        scripted_.insert(scripted_.end(), bytes.begin(), bytes.end());
    }

    void scriptU32(uint32_t value) {
        script({static_cast<uint8_t>(value >> 24), static_cast<uint8_t>(value >> 16), static_cast<uint8_t>(value >> 8),
                static_cast<uint8_t>(value)});
    }

    void fill(uint8_t* data, size_t len) override {
        for (size_t i = 0; i < len; ++i) {
            if (!scripted_.empty()) {
                data[i] = scripted_.front();
                scripted_.pop_front();
                continue;
            }
            state_ ^= state_ << 13;
            state_ ^= state_ >> 17;
            state_ ^= state_ << 5;
            data[i] = static_cast<uint8_t>(state_);
        }
        drawn_ += len;
    }

    size_t drawn() const {
        return drawn_;
    }

private:
    std::deque<uint8_t> scripted_;
    uint32_t state_ = 0x2545F491;
    size_t drawn_ = 0;
};

}
