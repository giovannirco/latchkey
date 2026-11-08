// SPDX-License-Identifier: GPL-3.0-or-later
#include "rpc.h"

#include <cstdlib>
#include <map>
#include <memory>
#include <string_view>
#include <utility>

#include "esp_log.h"

#include "audit.h"
#include "auth.h"
#include "board.h"
#include "clock.h"
#include "events.h"
#include "jobs.h"
#include "latchkey_util/access.h"
#include "latchkey_util/json_depth.h"

namespace rpc {

namespace {

constexpr const char* TAG = "rpc";
constexpr size_t kMaxNesting = 8;
constexpr size_t kMaxValues = 256;
constexpr const char* kOutOfMemoryLine = R"({"id":null,"error":{"code":"internal","message":"out of memory"}})";
constexpr uint32_t kConfirmTimeoutMs = 30000;

struct Method {
    Access access;
    Handler handler;
    Handler check;
};

std::map<std::string, Method, std::less<>>& methods() {
    static std::map<std::string, Method, std::less<>> table;
    return table;
}

cJSON* errorObject(const Reply& reply) {
    cJSON* error = cJSON_CreateObject();
    cJSON_AddStringToObject(error, "code", reply.error.c_str());
    cJSON_AddStringToObject(error, "message", reply.message.c_str());
    const cJSON* item = nullptr;
    cJSON_ArrayForEach(item, reply.errorData.get()) {
        cJSON_AddItemToObject(error, item->string, cJSON_Duplicate(item, true));
    }
    return error;
}

std::string render(const cJSON* id, Reply reply) {
    Json envelope(cJSON_CreateObject());
    cJSON_AddItemToObject(envelope.get(), "id", id != nullptr ? cJSON_Duplicate(id, true) : cJSON_CreateNull());
    addOutcome(envelope.get(), std::move(reply));
    char* text = cJSON_PrintUnformatted(envelope.get());
    if (text == nullptr) {
        ESP_LOGE(TAG, "out of memory rendering a reply");
        return kOutOfMemoryLine;
    }
    std::string line(text);
    cJSON_free(text);
    return line;
}

bool isValidId(const cJSON* id) {
    return id == nullptr || cJSON_IsNull(id) || cJSON_IsNumber(id) || cJSON_IsString(id);
}

latchkey_util::AccessDecision decide(const Access& access, const Context& context) {
    return latchkey_util::decideAccess({access.needsSession, access.needsButton, access.serialOnly, access.job},
                                       context.origin == Transport::Serial, context.session.has_value());
}

Response respond(const cJSON* id, Reply reply) {
    Response response;
    response.sessionToken = std::move(reply.sessionToken);
    response.endSession = reply.endSession;
    response.json = render(id, std::move(reply));
    return response;
}

uint32_t auditTime() { return wallclock::synced() ? static_cast<uint32_t>(wallclock::utcSeconds()) : 0; }

void record(const std::string& method, const Method& target, const Context& context, const Reply& reply) {
    if (target.access.audited && reply.audited) {
        audit::append({auditTime(), context.origin, method, reply.target, reply.error.empty() ? "ok" : reply.error});
    }
}

bool sessionOpen(const Context& context) { return !context.session.has_value() || auth::sessionOpen(*context.session); }

Reply sessionEnded() { return fail("unauthorized", "the session ended before the request ran"); }

Reply pressThenRun(const JobSpec& spec) {
    switch (confirmPresence(spec.action, spec.context)) {
        case Presence::Confirmed:
            return spec.run();
        case Presence::NotPressed:
            return fail("confirm_timeout", "the button was not pressed within 30 s");
        case Presence::SessionEnded:
            break;
    }
    return sessionEnded();
}

Reply runJob(const JobSpec& spec, bool expired) {
    if (expired) {
        return fail("busy", "the board was busy with other requests for 60 s; try again");
    }
    if (!sessionOpen(spec.context)) {
        return sessionEnded();
    }
    Reply verdict = spec.check ? spec.check() : ok();
    if (!verdict.error.empty()) {
        return verdict;
    }
    Reply reply = spec.confirm ? pressThenRun(spec) : spec.run();
    if (reply.target.empty()) {
        reply.target = verdict.target;
    }
    return reply;
}

JobSpec methodJob(const std::string& method, const Method& target, const Context& context, bool confirm,
                  std::shared_ptr<cJSON> copy) {
    JobSpec spec;
    spec.action = method;
    spec.context = context;
    spec.confirm = confirm;
    if (target.check) {
        spec.check = [check = target.check, copy, context] { return check(copy.get(), context); };
    }
    spec.run = [handler = target.handler, copy, context] { return handler(copy.get(), context); };
    spec.finish = [&method, &target, context](const Reply& reply) { record(method, target, context, reply); };
    return spec;
}

}

const char* toString(Transport transport) { return transport == Transport::Serial ? "serial" : "web"; }

Reply ok(cJSON* result) {
    Reply reply;
    reply.result.reset(result);
    return reply;
}

Reply fail(const char* code, const char* message) {
    Reply reply;
    reply.error = code;
    reply.message = message;
    return reply;
}

void addOutcome(cJSON* object, Reply reply) {
    if (reply.error.empty()) {
        cJSON_AddItemToObject(object, "result", reply.result != nullptr ? reply.result.release() : cJSON_CreateObject());
    } else {
        cJSON_AddItemToObject(object, "error", errorObject(reply));
    }
}

void registerMethod(const char* name, Access access, Handler handler, Handler check) {
    const bool inserted = methods().emplace(name, Method{access, std::move(handler), std::move(check)}).second;
    if (!inserted) {
        ESP_LOGE(TAG, "method %s registered twice", name);
        abort();
    }
}

Presence confirmPresence(const std::string& action, const Context& context) {
    cJSON* required = cJSON_CreateObject();
    cJSON_AddStringToObject(required, "action", action.c_str());
    cJSON_AddNumberToObject(required, "timeoutMs", kConfirmTimeoutMs);
    events::publish("confirm.required", required);
    const bool pressed = board::waitForPress(kConfirmTimeoutMs, [&context] { return sessionOpen(context); });
    const bool open = sessionOpen(context);
    cJSON* result = cJSON_CreateObject();
    cJSON_AddStringToObject(result, "action", action.c_str());
    cJSON_AddBoolToObject(result, "confirmed", pressed && open);
    events::publish("confirm.result", result);
    if (!open) {
        return Presence::SessionEnded;
    }
    return pressed ? Presence::Confirmed : Presence::NotPressed;
}

Reply startJob(JobSpec spec) {
    if (spec.confirm && !jobs::idle()) {
        return fail("busy", "the board is waiting on another request; try again when it is done");
    }
    const std::optional<uint32_t> session = spec.context.session;
    const std::optional<std::string> job = jobs::submit(session, [spec = std::move(spec)](bool expired) {
        Reply reply = runJob(spec, expired);
        if (spec.finish) {
            spec.finish(reply);
        }
        return reply;
    });
    if (!job.has_value()) {
        return fail("busy", "too many requests are waiting; try again");
    }
    cJSON* result = cJSON_CreateObject();
    cJSON_AddStringToObject(result, "job", job->c_str());
    Reply reply = ok(result);
    reply.audited = false;
    return reply;
}

Response dispatch(const char* requestJson, Transport origin, std::string_view sessionToken) {
    if (!latchkey_util::jsonNestingWithin(requestJson, kMaxNesting)) {
        return respond(nullptr, fail("bad_request", "request nested too deeply"));
    }
    if (!latchkey_util::jsonValuesWithin(requestJson, kMaxValues)) {
        return respond(nullptr, fail("bad_request", "request has too many values"));
    }
    Json request(cJSON_ParseWithOpts(requestJson, nullptr, true));
    if (request == nullptr || !cJSON_IsObject(request.get())) {
        return respond(nullptr, fail("bad_request", "request must be a JSON object"));
    }
    const cJSON* id = cJSON_GetObjectItemCaseSensitive(request.get(), "id");
    if (!isValidId(id)) {
        return respond(nullptr, fail("bad_request", "id must be a number or a string"));
    }
    const cJSON* method = cJSON_GetObjectItemCaseSensitive(request.get(), "method");
    if (!cJSON_IsString(method) || method->valuestring == nullptr) {
        return respond(id, fail("bad_request", "method must be a string"));
    }
    const cJSON* params = cJSON_GetObjectItemCaseSensitive(request.get(), "params");
    Json emptyParams;
    if (params == nullptr || cJSON_IsNull(params)) {
        emptyParams.reset(cJSON_CreateObject());
        params = emptyParams.get();
    }
    if (!cJSON_IsObject(params)) {
        return respond(id, fail("invalid_argument", "params must be an object"));
    }
    const auto entry = methods().find(std::string_view(method->valuestring));
    if (entry == methods().end()) {
        return respond(id, fail("unknown_method", "no such method"));
    }
    const Method& target = entry->second;
    const Context context{origin, origin == Transport::Web ? auth::sessionFor(sessionToken) : std::nullopt};
    const latchkey_util::AccessDecision decision = decide(target.access, context);
    Reply reply;
    if (decision.error != nullptr) {
        reply = fail(decision.error, decision.message);
        reply.audited = decision.audited;
    } else if (decision.job) {
        std::shared_ptr<cJSON> copy(cJSON_Duplicate(params, true), cJSON_Delete);
        reply = copy == nullptr ? fail("internal", "out of memory")
                                : startJob(methodJob(entry->first, target, context, decision.confirm, copy));
    } else {
        reply = target.handler(params, context);
    }
    record(entry->first, target, context, reply);
    return respond(id, std::move(reply));
}

std::string errorLine(const char* code, const char* message) { return render(nullptr, fail(code, message)); }

}
