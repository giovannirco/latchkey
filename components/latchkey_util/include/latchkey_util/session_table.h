// SPDX-License-Identifier: GPL-3.0-or-later
#pragma once

#include <array>
#include <cstddef>
#include <cstdint>
#include <optional>
#include <vector>

namespace latchkey_util {

inline constexpr size_t kSessionDigestSize = 32;
inline constexpr size_t kMaxSessions = 4;

using SessionDigest = std::array<uint8_t, kSessionDigestSize>;

struct SessionInfo {
    uint32_t id = 0;
    int64_t createdAt = 0;
    int64_t lastSeenAt = 0;
};

class SessionTable {
public:
    SessionTable(int64_t idleSeconds, int64_t lifetimeSeconds, uint32_t firstId);

    SessionInfo open(const SessionDigest& digest, int64_t now);

    std::optional<uint32_t> touch(const SessionDigest& digest, int64_t now);

    bool close(uint32_t id);

    void closeAllExcept(std::optional<uint32_t> keep);

    std::vector<SessionInfo> list(int64_t now);

    int64_t expiresAt(const SessionInfo& session) const;

private:
    struct Slot {
        bool used = false;
        SessionDigest digest{};
        SessionInfo info;
    };

    bool alive(const Slot& slot, int64_t now) const;

    void expire(int64_t now);

    static void clear(Slot& slot);

    int64_t idleSeconds_;
    int64_t lifetimeSeconds_;
    uint32_t nextId_;
    std::array<Slot, kMaxSessions> slots_{};
};

}
