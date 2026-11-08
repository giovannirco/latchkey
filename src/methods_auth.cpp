// SPDX-License-Identifier: GPL-3.0-or-later
#include <cstdint>
#include <cstdio>
#include <cstring>
#include <optional>
#include <string>
#include <string_view>

#include "mbedtls/platform_util.h"

#include "auth.h"
#include "latchkey_util/totp.h"
#include "methods.h"
#include "rpc.h"

namespace methods {

namespace {

constexpr size_t kMaxSessionIdDigits = 10;

const cJSON* member(const cJSON* params, const char* key) { return cJSON_GetObjectItemCaseSensitive(params, key); }

bool absent(const cJSON* item) { return item == nullptr || cJSON_IsNull(item); }

rpc::Reply invalid(const char* message) { return rpc::fail("invalid_argument", message); }

rpc::Reply unaudited(rpc::Reply reply) {
    reply.audited = false;
    return reply;
}

rpc::Reply anonymous(rpc::Reply reply, const rpc::Context& context) {
    if (context.origin == rpc::Transport::Web && !context.session.has_value()) {
        reply.audited = false;
    }
    return reply;
}

bool readText(const cJSON* params, const char* key, size_t minLength, size_t maxLength, std::string_view& out) {
    const cJSON* item = member(params, key);
    if (!cJSON_IsString(item) || item->valuestring == nullptr) {
        return false;
    }
    const size_t length = std::strlen(item->valuestring);
    if (length < minLength || length > maxLength) {
        return false;
    }
    out = std::string_view(item->valuestring, length);
    return true;
}

bool readFlag(const cJSON* item, bool& out) {
    if (absent(item)) {
        out = false;
        return true;
    }
    if (!cJSON_IsBool(item)) {
        return false;
    }
    out = cJSON_IsTrue(item);
    return true;
}

bool readSessionId(const cJSON* item, uint32_t& out) {
    if (!cJSON_IsString(item) || item->valuestring == nullptr) {
        return false;
    }
    const std::string_view text(item->valuestring);
    if (text.empty() || text.size() > kMaxSessionIdDigits) {
        return false;
    }
    uint64_t value = 0;
    for (char c : text) {
        if (c < '0' || c > '9') {
            return false;
        }
        value = value * 10 + static_cast<uint64_t>(c - '0');
    }
    if (value > UINT32_MAX) {
        return false;
    }
    out = static_cast<uint32_t>(value);
    return true;
}

void addTime(cJSON* object, const char* key, const std::optional<int64_t>& utc) {
    if (utc.has_value()) {
        cJSON_AddNumberToObject(object, key, static_cast<double>(*utc));
    } else {
        cJSON_AddNullToObject(object, key);
    }
}

cJSON* sessionJson(const auth::Session& session, const std::optional<uint32_t>& current) {
    cJSON* json = cJSON_CreateObject();
    cJSON_AddStringToObject(json, "id", std::to_string(session.id).c_str());
    addTime(json, "createdAt", session.createdAt);
    addTime(json, "lastSeenAt", session.lastSeenAt);
    cJSON_AddStringToObject(json, "origin", rpc::toString(rpc::Transport::Web));
    cJSON_AddBoolToObject(json, "current", current.has_value() && *current == session.id);
    return json;
}

rpc::Reply rateLimited(uint32_t retryAfter) {
    char message[64];
    std::snprintf(message, sizeof(message), "too many failed sign-ins; try again in %u s",
                  static_cast<unsigned>(retryAfter));
    rpc::Reply reply = rpc::fail("rate_limited", message);
    reply.errorData.reset(cJSON_CreateObject());
    cJSON_AddNumberToObject(reply.errorData.get(), "retryAfter", retryAfter);
    reply.audited = false;
    return reply;
}

rpc::Reply notClaimed() { return unaudited(rpc::fail("not_claimed", "the board has no owner yet: claim it over USB")); }

const char* readLogin(const cJSON* params, const rpc::Context& context, std::optional<auth::Credentials>& out,
                      bool& openSession) {
    std::string_view password;
    if (!readText(params, "password", 1, auth::kMaxPassword, password)) {
        return "password must be a string of 1 to 128 bytes";
    }
    const cJSON* totp = member(params, "totp");
    uint32_t code = 0;
    if (!cJSON_IsString(totp) || totp->valuestring == nullptr || !latchkey_util::parseTotpCode(totp->valuestring, code)) {
        return "totp must be the six digits of the authenticator code";
    }
    bool dryRun = false;
    if (!readFlag(member(params, "dryRun"), dryRun)) {
        return "dryRun must be true or false";
    }
    if (context.origin == rpc::Transport::Serial && !dryRun) {
        return "the serial console has no sessions: pass dryRun to check the password and code";
    }
    if (context.origin == rpc::Transport::Web && dryRun) {
        return "dryRun is only for the serial console";
    }
    out = auth::Credentials{password, code};
    openSession = !dryRun;
    return nullptr;
}

rpc::Reply loggedIn(auth::Login& login, bool openSession) {
    cJSON* result = cJSON_CreateObject();
    if (!openSession) {
        cJSON_AddBoolToObject(result, "ok", true);
        return rpc::ok(result);
    }
    cJSON_AddNumberToObject(result, "idleTimeout", static_cast<double>(auth::kIdleTimeoutSeconds));
    cJSON* session = cJSON_AddObjectToObject(result, "session");
    cJSON_AddStringToObject(session, "id", std::to_string(login.session.id).c_str());
    addTime(session, "expiresAt", login.session.expiresAt);
    rpc::Reply reply = rpc::ok(result);
    reply.sessionToken = std::move(login.token);
    return reply;
}

rpc::Reply login(const cJSON* params, const rpc::Context& context) {
    std::optional<auth::Credentials> credentials;
    bool openSession = false;
    const char* problem = readLogin(params, context, credentials, openSession);
    auth::Login result = auth::login(credentials, openSession);
    switch (result.verdict) {
        case auth::Verdict::Ok:
            return loggedIn(result, openSession);
        case auth::Verdict::Rejected:
            return rpc::fail("unauthorized", "wrong password or code");
        case auth::Verdict::RateLimited:
            return rateLimited(result.retryAfter);
        case auth::Verdict::TimeUnsynced:
            return unaudited(rpc::fail("time_unsynced", "the board clock is not set, so codes cannot be checked"));
        case auth::Verdict::Malformed:
            return unaudited(invalid(problem));
        case auth::Verdict::Unclaimed:
            return notClaimed();
        case auth::Verdict::Failed:
            break;
    }
    return rpc::fail("internal", "the login check failed");
}

rpc::Reply logout(const cJSON* params, const rpc::Context& context) {
    bool all = false;
    if (!readFlag(member(params, "all"), all)) {
        return anonymous(invalid("all must be true or false"), context);
    }
    if (context.origin == rpc::Transport::Serial) {
        if (!all) {
            return invalid("the serial console has no session: pass all to end every web session");
        }
        auth::endSessions(std::nullopt);
        return rpc::ok();
    }
    rpc::Reply reply = rpc::ok();
    reply.endSession = true;
    if (!context.session.has_value()) {
        reply.audited = false;
        return reply;
    }
    if (all) {
        auth::endSessions(std::nullopt);
    } else {
        auth::revoke(*context.session);
    }
    return reply;
}

rpc::Reply sessions(const cJSON*, const rpc::Context& context) {
    cJSON* result = cJSON_CreateObject();
    cJSON* list = cJSON_AddArrayToObject(result, "sessions");
    for (const auth::Session& session : auth::sessions()) {
        cJSON_AddItemToArray(list, sessionJson(session, context.session));
    }
    return rpc::ok(result);
}

rpc::Reply revoke(const cJSON* params, const rpc::Context& context) {
    uint32_t id = 0;
    if (!readSessionId(member(params, "id"), id)) {
        return invalid("id must be a session id from auth.sessions");
    }
    if (!auth::revoke(id)) {
        return invalid("no session has that id");
    }
    rpc::Reply reply = rpc::ok();
    reply.endSession = context.session.has_value() && *context.session == id;
    return reply;
}

rpc::Reply changePassword(const cJSON* params, const rpc::Context& context) {
    std::string_view current;
    if (!readText(params, "current", 1, auth::kMaxPassword, current)) {
        return invalid("current must be the current password");
    }
    std::string_view next;
    if (!readText(params, "new", auth::kMinPassword, auth::kMaxPassword, next)) {
        return invalid("new must be 12 to 128 bytes");
    }
    const auth::Change change = auth::changePassword(current, next, context.session);
    switch (change.verdict) {
        case auth::Verdict::Ok:
            return rpc::ok();
        case auth::Verdict::Rejected:
            return invalid("the current password is wrong");
        case auth::Verdict::RateLimited:
            return rateLimited(change.retryAfter);
        case auth::Verdict::Unclaimed:
            return notClaimed();
        default:
            break;
    }
    return rpc::fail("internal", "cannot store the new password");
}

rpc::Reply rotateTotp(const cJSON*, const rpc::Context&) {
    auth::Rotation rotation = auth::rotateTotp();
    if (rotation.verdict == auth::Verdict::Unclaimed) {
        return notClaimed();
    }
    if (rotation.verdict != auth::Verdict::Ok) {
        return rpc::fail("internal", "cannot store the new authenticator secret");
    }
    cJSON* result = cJSON_CreateObject();
    cJSON_AddStringToObject(result, "otpauth", rotation.otpauth.c_str());
    mbedtls_platform_zeroize(rotation.otpauth.data(), rotation.otpauth.size());
    return rpc::ok(result);
}

}

void registerAuth() {
    rpc::registerMethod("auth.login", {.needsSession = false}, login);
    rpc::registerMethod("auth.logout", {.needsSession = false}, logout);
    rpc::registerMethod("auth.sessions", {.audited = false}, sessions);
    rpc::registerMethod("auth.revoke", {}, revoke);
    rpc::registerMethod("auth.changePassword", {}, changePassword);
    rpc::registerMethod("auth.rotateTotp", {.needsButton = true}, rotateTotp);
}

}
