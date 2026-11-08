// SPDX-License-Identifier: GPL-3.0-or-later
#include "latchkey_util/session_table.h"

#include <algorithm>

#include "latchkey_util/constant_time.h"

namespace latchkey_util {

SessionTable::SessionTable(int64_t idleSeconds, int64_t lifetimeSeconds, uint32_t firstId)
    : idleSeconds_(idleSeconds), lifetimeSeconds_(lifetimeSeconds), nextId_(firstId) {}

SessionInfo SessionTable::open(const SessionDigest& digest, int64_t now) {
    expire(now);
    Slot* target = nullptr;
    for (Slot& slot : slots_) {
        if (!slot.used) {
            target = &slot;
            break;
        }
    }
    if (target == nullptr) {
        target = &slots_[0];
        for (Slot& slot : slots_) {
            const bool older = slot.info.lastSeenAt < target->info.lastSeenAt ||
                               (slot.info.lastSeenAt == target->info.lastSeenAt && slot.info.id < target->info.id);
            if (older) {
                target = &slot;
            }
        }
    }
    target->used = true;
    target->digest = digest;
    target->info = SessionInfo{nextId_++, now, now};
    return target->info;
}

std::optional<uint32_t> SessionTable::touch(const SessionDigest& digest, int64_t now) {
    Slot* match = nullptr;
    for (Slot& slot : slots_) {
        const bool same = constantTimeEqual(slot.digest.data(), digest.data(), digest.size());
        if (same && slot.used) {
            match = &slot;
        }
    }
    if (match == nullptr) {
        return std::nullopt;
    }
    if (!alive(*match, now)) {
        clear(*match);
        return std::nullopt;
    }
    match->info.lastSeenAt = now;
    return match->info.id;
}

bool SessionTable::close(uint32_t id) {
    for (Slot& slot : slots_) {
        if (slot.used && slot.info.id == id) {
            clear(slot);
            return true;
        }
    }
    return false;
}

void SessionTable::closeAllExcept(std::optional<uint32_t> keep) {
    for (Slot& slot : slots_) {
        if (slot.used && (!keep.has_value() || slot.info.id != *keep)) {
            clear(slot);
        }
    }
}

std::vector<SessionInfo> SessionTable::list(int64_t now) {
    expire(now);
    std::vector<SessionInfo> sessions;
    for (const Slot& slot : slots_) {
        if (slot.used) {
            sessions.push_back(slot.info);
        }
    }
    std::sort(sessions.begin(), sessions.end(),
              [](const SessionInfo& a, const SessionInfo& b) { return a.id < b.id; });
    return sessions;
}

int64_t SessionTable::expiresAt(const SessionInfo& session) const { return session.createdAt + lifetimeSeconds_; }

bool SessionTable::alive(const Slot& slot, int64_t now) const {
    return slot.used && now - slot.info.lastSeenAt < idleSeconds_ && now - slot.info.createdAt < lifetimeSeconds_;
}

void SessionTable::expire(int64_t now) {
    for (Slot& slot : slots_) {
        if (slot.used && !alive(slot, now)) {
            clear(slot);
        }
    }
}

void SessionTable::clear(Slot& slot) { slot = Slot{}; }

}
