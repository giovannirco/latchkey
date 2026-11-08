// SPDX-License-Identifier: GPL-3.0-or-later
#pragma once

#include <cstddef>
#include <cstdint>
#include <optional>
#include <string>
#include <string_view>
#include <vector>

#include "store.h"

namespace auth {

inline constexpr uint32_t kPasswordIterations = 4400;
inline constexpr size_t kMinPassword = 12;
inline constexpr size_t kMaxPassword = 128;
inline constexpr int64_t kIdleTimeoutSeconds = 15 * 60;
inline constexpr int64_t kSessionLifetimeSeconds = 12 * 60 * 60;

enum class Verdict : uint8_t {
    Ok,
    Rejected,
    RateLimited,
    TimeUnsynced,
    Malformed,
    Unclaimed,
    Failed,
};

struct Credentials {
    std::string_view password;
    uint32_t code = 0;
};

struct Session {
    uint32_t id = 0;
    std::optional<int64_t> createdAt;
    std::optional<int64_t> lastSeenAt;
    std::optional<int64_t> expiresAt;
};

struct Login {
    Verdict verdict = Verdict::Failed;
    uint32_t retryAfter = 0;
    std::string token;
    Session session;
};

struct Change {
    Verdict verdict = Verdict::Failed;
    uint32_t retryAfter = 0;
};

struct Rotation {
    Verdict verdict = Verdict::Failed;
    std::string otpauth;
};

void init();

bool hashPassword(std::string_view password, store::auth::Owner& owner);

Login login(const std::optional<Credentials>& credentials, bool openSession);

std::optional<uint32_t> sessionFor(std::string_view token);

std::vector<Session> sessions();

bool revoke(uint32_t id);

void endSessions(std::optional<uint32_t> keep);

Change changePassword(std::string_view current, std::string_view next, std::optional<uint32_t> keep);

Rotation rotateTotp();

}
