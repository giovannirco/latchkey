// SPDX-License-Identifier: GPL-3.0-or-later
#pragma once

#include <unity.h>

#include <array>
#include <cstdlib>
#include <cstring>
#include <optional>
#include <string>
#include <utility>

#include "../reference/allocation_failure.h"
#include "latchkey_util/rpc_text.h"
#include "../../src/rpc.cpp"
#include "../../src/rpc_json.cpp"

namespace {
struct Allocation { void* pointer = nullptr; size_t size = 0; };
std::array<Allocation, 1024> allocations;
size_t liveBytes = 0;
size_t peakBytes = 0;
size_t allocationAttempts = 0;
size_t failAllocation = 0;
size_t unclearedSecrets = 0;
std::string_view watchedSecret;
bool fixtureClockSynced = false;
int64_t fixtureUtc = 1762524000;
size_t auditWrites = 0;
size_t alertEvents = 0;
std::string lastAuditResult;
std::function<void()> beforePress;
bool openSession = true;
bool pressAllowed = true;
bool rejectJob = false;
bool runImmediately = false;
size_t handlerCalls = 0;
size_t confirmations = 0;
std::optional<jobs::Work> queuedWork;
const char* expectedParams = nullptr;
bool rawReleasedAtRun = false;
bool paramsNotDuplicated = false;
size_t resultSize = 0;
bool invalidArguments = false;
bool handlerFails = false;
std::optional<uint32_t> endedSession;
events::Sink eventSink;
size_t peakTransportBytes = 0;
size_t parameterCopiesAtSubmit = 0;

void measureTransportBytes() {
    size_t bytes = liveBytes;
    for (const auto& allocation : allocation_failure::allocations) bytes += allocation.size;
    peakTransportBytes = std::max(peakTransportBytes, bytes);
}

void* allocateJson(size_t size) {
    if (++allocationAttempts == failAllocation) return nullptr;
    void* pointer = std::malloc(size);
    if (pointer == nullptr) return nullptr;
    for (auto& allocation : allocations) {
        if (allocation.pointer != nullptr) continue;
        allocation = {pointer, size};
        liveBytes += size;
        peakBytes = std::max(peakBytes, liveBytes);
        measureTransportBytes();
        return pointer;
    }
    std::abort();
}

void freeJson(void* pointer) {
    if (pointer == nullptr) return;
    for (auto& allocation : allocations) {
        if (allocation.pointer != pointer) continue;
        if (!watchedSecret.empty() &&
            std::string_view(static_cast<char*>(pointer), allocation.size).find(watchedSecret) != std::string_view::npos) {
            ++unclearedSecrets;
        }
        liveBytes -= allocation.size;
        allocation = {};
        std::free(pointer);
        return;
    }
    std::abort();
}

rpc::Reply handle(const cJSON* params, const rpc::Context&) {
    ++handlerCalls;
    rawReleasedAtRun = allocation_failure::checkedWipes == 1 && allocation_failure::wiped;
    const auto* secret = cJSON_GetObjectItemCaseSensitive(params, "passphrase");
    paramsNotDuplicated = secret != nullptr && secret->valuestring == expectedParams;
    if (handlerFails) return rpc::fail("fixture_failure", "handler failed");
    if (resultSize != 0) return rpc::ok(cJSON_CreateString(std::string(resultSize, 'x').c_str()));
    return rpc::ok();
}

rpc::Reply check(const cJSON* params, const rpc::Context&) {
    const auto* secret = cJSON_GetObjectItemCaseSensitive(params, "passphrase");
    expectedParams = secret != nullptr ? secret->valuestring : nullptr;
    return invalidArguments ? rpc::fail("invalid_argument", "fixture argument rejected") : rpc::ok();
}

latchkey_util::RpcText request(std::string_view text) {
    latchkey_util::RpcText owned;
    TEST_ASSERT_TRUE(owned.assign(text));
    return owned;
}

rpc::Response dispatchRequest(latchkey_util::RpcText input, rpc::Transport origin, std::string_view token) {
    return rpc::dispatch(std::move(input), origin, token);
}

bool hasError(const rpc::Response& response, const char* code) {
    rpc::Json json(cJSON_Parse(response.json.c_str()));
    const auto* error = cJSON_GetObjectItemCaseSensitive(json.get(), "error");
    const auto* value = cJSON_GetObjectItemCaseSensitive(error, "code");
    return cJSON_IsString(value) && std::strcmp(value->valuestring, code) == 0;
}
}

void* heap_caps_malloc(size_t size, uint32_t) { return allocateJson(size); }
void heap_caps_free(void* pointer) { freeJson(pointer); }

namespace auth {
std::optional<uint32_t> sessionFor(std::string_view token) {
    if (openSession && token == "fixture-session-2") return 2;
    return openSession && token == "fixture-session" ? std::optional<uint32_t>(1) : std::nullopt;
}
bool sessionOpen(uint32_t id) { return openSession && endedSession != id; }
void onSessionsEnded(void (*)()) {}
}
namespace audit { void append(const Entry& entry) { ++auditWrites; lastAuditResult = entry.result; } }
namespace wallclock {
bool synced() { return fixtureClockSynced; }
int64_t utcSeconds() { return fixtureUtc; }
}
namespace board {
bool waitForPress(uint32_t, const std::function<bool()>& keepWaiting) {
    ++confirmations;
    if (beforePress) beforePress();
    return pressAllowed && keepWaiting();
}
}
namespace events {
void publish(const char* name, cJSON* data) {
    rpc::Json owned(data);
    if (std::strcmp(name, "lock.alert") == 0) ++alertEvents;
}
void addSink(Sink sink) { eventSink = std::move(sink); }
}
#ifndef LATCHKEY_NATIVE_REAL_JOBS
namespace jobs {
bool idle() { return !queuedWork.has_value(); }
std::optional<std::string> submit(std::optional<uint32_t>, Work work) {
    if (!watchedSecret.empty()) {
        for (const auto& allocation : allocations) {
            if (allocation.pointer != nullptr &&
                std::string_view(static_cast<char*>(allocation.pointer), allocation.size).find(watchedSecret) !=
                    std::string_view::npos) ++parameterCopiesAtSubmit;
        }
    }
    if (rejectJob) return std::nullopt;
    if (runImmediately) rpc::executeJob(std::move(*work), false);
    else queuedWork = std::move(work);
    return "fixture-job";
}
}
#endif

void resetRpcFixture() {
    queuedWork.reset();
    fixtureClockSynced = false;
    fixtureUtc = 1762524000;
    auditWrites = 0;
    alertEvents = 0;
    lastAuditResult.clear();
    beforePress = {};
    watchedSecret = {};
    unclearedSecrets = handlerCalls = confirmations = 0;
    peakBytes = liveBytes;
    openSession = pressAllowed = true;
    rejectJob = runImmediately = false;
    expectedParams = nullptr;
    rawReleasedAtRun = paramsNotDuplicated = false;
    resultSize = failAllocation = allocationAttempts = 0;
    invalidArguments = handlerFails = false;
    endedSession.reset();
    allocation_failure::reset();
    peakTransportBytes = parameterCopiesAtSubmit = 0;
    allocation_failure::onChange = measureTransportBytes;
}
void clearRpcFixture() { queuedWork.reset(); allocation_failure::resume(); failAllocation = 0; }
