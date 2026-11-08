// SPDX-License-Identifier: GPL-3.0-or-later
#include "auth.h"

#include <array>
#include <mutex>

#include "esp_log.h"
#include "esp_random.h"
#include "esp_timer.h"
#include "mbedtls/platform_util.h"
#include "psa/crypto.h"

extern "C" {
#include "mbedtls/constant_time.h"
}

#include "board.h"
#include "clock.h"
#include "latchkey_util/otpauth.h"
#include "latchkey_util/rate_limit.h"
#include "latchkey_util/session_table.h"
#include "latchkey_util/totp.h"

namespace auth {

namespace {

constexpr const char* TAG = "auth";
constexpr latchkey_util::RateLimiter::Policy kLoginPolicy{5, 30, 15 * 60};
constexpr size_t kTokenBytes = 32;
constexpr size_t kTokenLength = kTokenBytes * 2;
constexpr char kHexDigits[] = "0123456789abcdef";

std::mutex s_loginMutex;
std::mutex s_sessionMutex;
latchkey_util::RateLimiter s_limiter(kLoginPolicy);
uint64_t s_lastStep = 0;
latchkey_util::SessionTable s_sessions(kIdleTimeoutSeconds, kSessionLifetimeSeconds, 1);

int64_t monotonicMs() { return esp_timer_get_time() / 1000; }

int64_t monotonicSeconds() { return esp_timer_get_time() / 1000000; }

bool derive(std::string_view password, const std::array<uint8_t, latchkey_util::kPasswordSaltSize>& salt,
            uint32_t iterations, std::array<uint8_t, latchkey_util::kPasswordHashSize>& out) {
    psa_key_derivation_operation_t operation = PSA_KEY_DERIVATION_OPERATION_INIT;
    const bool derived =
        psa_key_derivation_setup(&operation, PSA_ALG_PBKDF2_HMAC(PSA_ALG_SHA_256)) == PSA_SUCCESS &&
        psa_key_derivation_input_integer(&operation, PSA_KEY_DERIVATION_INPUT_COST, iterations) == PSA_SUCCESS &&
        psa_key_derivation_input_bytes(&operation, PSA_KEY_DERIVATION_INPUT_SALT, salt.data(), salt.size()) ==
            PSA_SUCCESS &&
        psa_key_derivation_input_bytes(&operation, PSA_KEY_DERIVATION_INPUT_PASSWORD,
                                       reinterpret_cast<const uint8_t*>(password.data()),
                                       password.size()) == PSA_SUCCESS &&
        psa_key_derivation_output_bytes(&operation, out.data(), out.size()) == PSA_SUCCESS;
    psa_key_derivation_abort(&operation);
    return derived;
}

bool passwordMatches(std::string_view password, const latchkey_util::PasswordRecord& record, bool& matches) {
    std::array<uint8_t, latchkey_util::kPasswordHashSize> derived{};
    if (!derive(password, record.salt, record.iterations, derived)) {
        return false;
    }
    matches = mbedtls_ct_memcmp(derived.data(), record.hash.data(), derived.size()) == 0;
    mbedtls_platform_zeroize(derived.data(), derived.size());
    return true;
}

bool hmacSha1(const uint8_t* key, size_t keyLength, const uint8_t* message, size_t messageLength,
              uint8_t (&digest)[latchkey_util::kHmacSha1Size]) {
    psa_key_attributes_t attributes = PSA_KEY_ATTRIBUTES_INIT;
    psa_set_key_type(&attributes, PSA_KEY_TYPE_HMAC);
    psa_set_key_bits(&attributes, PSA_BYTES_TO_BITS(keyLength));
    psa_set_key_usage_flags(&attributes, PSA_KEY_USAGE_SIGN_MESSAGE);
    psa_set_key_algorithm(&attributes, PSA_ALG_HMAC(PSA_ALG_SHA_1));
    mbedtls_svc_key_id_t keyId = MBEDTLS_SVC_KEY_ID_INIT;
    const psa_status_t imported = psa_import_key(&attributes, key, keyLength, &keyId);
    psa_reset_key_attributes(&attributes);
    if (imported != PSA_SUCCESS) {
        return false;
    }
    size_t length = 0;
    const psa_status_t computed = psa_mac_compute(keyId, PSA_ALG_HMAC(PSA_ALG_SHA_1), message, messageLength,
                                                  digest, sizeof(digest), &length);
    psa_destroy_key(keyId);
    return computed == PSA_SUCCESS && length == sizeof(digest);
}

bool digestOf(std::string_view token, latchkey_util::SessionDigest& out) {
    size_t length = 0;
    return psa_hash_compute(PSA_ALG_SHA_256, reinterpret_cast<const uint8_t*>(token.data()), token.size(),
                            out.data(), out.size(), &length) == PSA_SUCCESS &&
           length == out.size();
}

bool isToken(std::string_view token) {
    if (token.size() != kTokenLength) {
        return false;
    }
    for (char c : token) {
        if ((c < '0' || c > '9') && (c < 'a' || c > 'f')) {
            return false;
        }
    }
    return true;
}

std::string newToken() {
    uint8_t bytes[kTokenBytes];
    esp_fill_random(bytes, sizeof(bytes));
    std::string token(kTokenLength, '0');
    for (size_t i = 0; i < sizeof(bytes); ++i) {
        token[i * 2] = kHexDigits[bytes[i] >> 4];
        token[i * 2 + 1] = kHexDigits[bytes[i] & 0x0F];
    }
    mbedtls_platform_zeroize(bytes, sizeof(bytes));
    return token;
}

std::optional<int64_t> toUtc(int64_t monotonic) {
    if (!wallclock::synced()) {
        return std::nullopt;
    }
    return wallclock::utcSeconds() - (monotonicSeconds() - monotonic);
}

Session describe(const latchkey_util::SessionInfo& info) {
    return Session{info.id, toUtc(info.createdAt), toUtc(info.lastSeenAt), toUtc(s_sessions.expiresAt(info))};
}

void recordFailure() {
    if (!s_limiter.recordFailure(monotonicMs())) {
        return;
    }
    const uint32_t failures = s_limiter.failures();
    const esp_err_t error = store::auth::saveFailures(failures);
    if (error != ESP_OK) {
        ESP_LOGE(TAG, "cannot store the failed login count: %s", esp_err_to_name(error));
    }
    const uint32_t wait = s_limiter.retryAfterSeconds(monotonicMs());
    if (wait > 0) {
        ESP_LOGW(TAG, "%u failed logins in a row: the next one waits %u s", static_cast<unsigned>(failures),
                 static_cast<unsigned>(wait));
    }
}

void recordSuccess(uint64_t step) {
    if (s_limiter.recordSuccess()) {
        const esp_err_t error = store::auth::saveFailures(0);
        if (error != ESP_OK) {
            ESP_LOGE(TAG, "cannot reset the failed login count: %s", esp_err_to_name(error));
        }
    }
    s_lastStep = step;
    const esp_err_t error = store::auth::saveLastStep(step);
    if (error != ESP_OK) {
        ESP_LOGE(TAG, "cannot store the last accepted code step: %s", esp_err_to_name(error));
    }
}

bool loadClaim(store::auth::Owner& owner, Verdict& verdict) {
    if (!store::auth::claimed()) {
        verdict = Verdict::Unclaimed;
        return false;
    }
    if (!store::auth::loadOwner(owner)) {
        verdict = Verdict::Failed;
        return false;
    }
    return true;
}

}

void init() {
    const store::auth::LoginState state = store::auth::loadLoginState();
    {
        std::lock_guard<std::mutex> lock(s_loginMutex);
        s_limiter.restore(state.failures, monotonicMs());
        s_lastStep = state.lastStep;
    }
    {
        std::lock_guard<std::mutex> lock(s_sessionMutex);
        s_sessions = latchkey_util::SessionTable(kIdleTimeoutSeconds, kSessionLifetimeSeconds, esp_random());
    }
    if (state.failures > 0) {
        ESP_LOGW(TAG, "%u failed logins on record since the last success", static_cast<unsigned>(state.failures));
    }
}

bool hashPassword(std::string_view password, latchkey_util::PasswordRecord& record) {
    return derive(password, record.salt, record.iterations, record.hash);
}

Login login(const std::optional<Credentials>& credentials, bool openSession) {
    std::lock_guard<std::mutex> lock(s_loginMutex);
    Login result;
    result.retryAfter = s_limiter.retryAfterSeconds(monotonicMs());
    if (result.retryAfter > 0) {
        result.verdict = Verdict::RateLimited;
        return result;
    }
    if (!wallclock::synced()) {
        result.verdict = Verdict::TimeUnsynced;
        return result;
    }
    if (!credentials.has_value()) {
        result.verdict = Verdict::Malformed;
        return result;
    }
    store::auth::Owner owner;
    if (!loadClaim(owner, result.verdict)) {
        return result;
    }
    bool passwordOk = false;
    const bool derived = passwordMatches(credentials->password, owner.password, passwordOk);
    uint64_t step = 0;
    const latchkey_util::TotpVerdict code =
        latchkey_util::totpVerify(owner.totpSecret.data(), owner.totpSecret.size(), wallclock::utcSeconds(),
                                  credentials->code, s_lastStep, hmacSha1, step);
    mbedtls_platform_zeroize(&owner, sizeof(owner));
    if (!derived || code == latchkey_util::TotpVerdict::HmacFailed) {
        ESP_LOGE(TAG, "login check failed in the crypto library");
        result.verdict = Verdict::Failed;
        return result;
    }
    const bool accepted = passwordOk & (code == latchkey_util::TotpVerdict::Accepted);
    if (!accepted) {
        recordFailure();
        result.verdict = Verdict::Rejected;
        return result;
    }
    recordSuccess(step);
    result.verdict = Verdict::Ok;
    if (!openSession) {
        return result;
    }
    std::string token = newToken();
    latchkey_util::SessionDigest digest{};
    if (!digestOf(token, digest)) {
        mbedtls_platform_zeroize(token.data(), token.size());
        result.verdict = Verdict::Failed;
        return result;
    }
    std::lock_guard<std::mutex> sessionLock(s_sessionMutex);
    result.session = describe(s_sessions.open(digest, monotonicSeconds()));
    result.token = std::move(token);
    return result;
}

std::optional<uint32_t> sessionFor(std::string_view token) {
    if (!isToken(token)) {
        return std::nullopt;
    }
    latchkey_util::SessionDigest digest{};
    if (!digestOf(token, digest)) {
        return std::nullopt;
    }
    std::lock_guard<std::mutex> lock(s_sessionMutex);
    return s_sessions.touch(digest, monotonicSeconds());
}

std::vector<Session> sessions() {
    std::lock_guard<std::mutex> lock(s_sessionMutex);
    std::vector<Session> out;
    for (const latchkey_util::SessionInfo& info : s_sessions.list(monotonicSeconds())) {
        out.push_back(describe(info));
    }
    return out;
}

bool revoke(uint32_t id) {
    std::lock_guard<std::mutex> lock(s_sessionMutex);
    return s_sessions.close(id);
}

void endSessions(std::optional<uint32_t> keep) {
    std::lock_guard<std::mutex> lock(s_sessionMutex);
    s_sessions.closeAllExcept(keep);
}

Change changePassword(std::string_view current, std::string_view next, std::optional<uint32_t> keep) {
    std::lock_guard<std::mutex> lock(s_loginMutex);
    Change change;
    change.retryAfter = s_limiter.retryAfterSeconds(monotonicMs());
    if (change.retryAfter > 0) {
        change.verdict = Verdict::RateLimited;
        return change;
    }
    store::auth::Owner owner;
    if (!loadClaim(owner, change.verdict)) {
        return change;
    }
    bool matches = false;
    if (!passwordMatches(current, owner.password, matches)) {
        mbedtls_platform_zeroize(&owner, sizeof(owner));
        change.verdict = Verdict::Failed;
        return change;
    }
    if (!matches) {
        mbedtls_platform_zeroize(&owner, sizeof(owner));
        recordFailure();
        change.verdict = Verdict::Rejected;
        return change;
    }
    esp_fill_random(owner.password.salt.data(), owner.password.salt.size());
    owner.password.iterations = kPasswordIterations;
    const bool stored = hashPassword(next, owner.password) && store::auth::savePassword(owner.password) == ESP_OK;
    mbedtls_platform_zeroize(&owner, sizeof(owner));
    if (!stored) {
        change.verdict = Verdict::Failed;
        return change;
    }
    endSessions(keep);
    change.verdict = Verdict::Ok;
    return change;
}

Rotation rotateTotp() {
    std::lock_guard<std::mutex> lock(s_loginMutex);
    Rotation rotation;
    if (!store::auth::claimed()) {
        rotation.verdict = Verdict::Unclaimed;
        return rotation;
    }
    store::auth::TotpSecret secret{};
    esp_fill_random(secret.data(), secret.size());
    const bool stored = store::auth::saveTotpSecret(secret) == ESP_OK;
    if (stored) {
        rotation.otpauth = latchkey_util::otpauthUri(board::name(), secret.data(), secret.size());
    }
    mbedtls_platform_zeroize(secret.data(), secret.size());
    if (!stored) {
        rotation.verdict = Verdict::Failed;
        return rotation;
    }
    s_lastStep = 0;
    const esp_err_t error = store::auth::saveLastStep(0);
    if (error != ESP_OK) {
        ESP_LOGE(TAG, "cannot reset the last accepted code step: %s", esp_err_to_name(error));
    }
    rotation.verdict = Verdict::Ok;
    return rotation;
}

}
