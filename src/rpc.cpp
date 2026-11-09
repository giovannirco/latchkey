// SPDX-License-Identifier: GPL-3.0-or-later
#include "rpc.h"

#include <cstdlib>
#include <cstring>
#include <map>
#include <memory>
#include <new>
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

bool containsNul(std::string_view text) {
    if (text.find('\0') != std::string_view::npos) return true;
    bool inString = false;
    for (size_t i = 0; i < text.size(); ++i) {
        if (text[i] == '"') {
            inString = !inString;
        } else if (inString && text[i] == '\\') {
            if (text.substr(++i, 5) == "u0000") return true;
        }
    }
    return false;
}

Json errorObject(const Reply& reply) {
    Json error(cJSON_CreateObject());
    if (!error || !cJSON_AddStringToObject(error.get(), "code", reply.error.c_str()) ||
        !cJSON_AddStringToObject(error.get(), "message", reply.message.c_str())) return {};
    const cJSON* item = nullptr;
    cJSON_ArrayForEach(item, reply.errorData.get()) {
        Json copy(cJSON_Duplicate(item, true));
        if (!copy || !cJSON_AddItemToObject(error.get(), item->string, copy.get())) return {};
        copy.release();
    }
    return error;
}

latchkey_util::RpcText renderReply(Json id, Reply reply) {
    Json envelope(cJSON_CreateObject());
    Json identity = id ? std::move(id) : Json(cJSON_CreateNull());
    if (!envelope || !identity || !cJSON_AddItemToObject(envelope.get(), "id", identity.get())) return {};
    identity.release();
    if (!addOutcome(envelope.get(), std::move(reply))) return {};
    return render(std::move(envelope));
}

bool isValidId(const cJSON* id) {
    return id == nullptr || cJSON_IsNull(id) || cJSON_IsNumber(id) || cJSON_IsString(id);
}

latchkey_util::AccessDecision decide(const Access& access, const Context& context) {
    return latchkey_util::decideAccess({access.needsSession, access.needsButton, access.serialOnly, access.job},
                                       context.origin == Transport::Serial, context.session.has_value());
}

Response respond(Json id, Reply reply) {
    Response response;
    response.sessionToken = std::move(reply.sessionToken);
    response.endSession = reply.endSession;
    response.json = renderReply(std::move(id), std::move(reply));
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
            return spec.run(spec.params.get(), spec.context);
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
    Reply verdict = spec.check ? spec.check(spec.params.get(), spec.context) : ok();
    if (!verdict.error.empty()) {
        return verdict;
    }
    Reply reply = spec.confirm ? pressThenRun(spec) : spec.run(spec.params.get(), spec.context);
    if (reply.target.empty()) {
        reply.target = verdict.target;
    }
    return reply;
}

void finishMethodJob(const JobSpec& spec, const Reply& reply) {
    if (spec.audited && reply.audited) {
        audit::append({auditTime(), spec.context.origin, spec.action, reply.target,
                       reply.error.empty() ? "ok" : reply.error});
    }
}

JobSpec methodJob(const std::string& method, const Method& target, const Context& context, bool confirm, Json params) {
    JobSpec spec;
    spec.action = method.c_str();
    spec.context = context;
    spec.confirm = confirm;
    spec.audited = target.access.audited;
    spec.params = std::move(params);
    if (target.check) {
        spec.check = std::cref(target.check);
    }
    spec.run = std::cref(target.handler);
    spec.finish = finishMethodJob;
    return spec;
}

}

const char* toString(Transport transport) {
    switch (transport) {
        case Transport::Serial:
            return "serial";
        case Transport::Web:
            return "web";
        case Transport::Mqtt:
            return "mqtt";
        case Transport::Board:
            return "board";
    }
    return "web";
}

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

bool addOutcome(cJSON* object, Reply reply) {
    Json value = reply.error.empty() ? std::move(reply.result) : errorObject(reply);
    if (reply.error.empty() && !value) value.reset(cJSON_CreateObject());
    if (!value || !cJSON_AddItemToObject(object, reply.error.empty() ? "result" : "error", value.get())) return false;
    value.release();
    return true;
}

latchkey_util::RpcText render(Json envelope) {
    if (!envelope) return {};
    latchkey_util::RpcText text(latchkey_util::RpcText::Limit::Response);
    for (size_t capacity = 256; capacity <= latchkey_util::kMaxRpcResponse; capacity *= 2) {
        text.clear();
        if (!text.resize(capacity)) return {};
        if (cJSON_PrintPreallocated(envelope.get(), text.data(), static_cast<int>(capacity + 1), false)) {
            text.resize(std::strlen(text.c_str()));
            return text;
        }
    }
    return {};
}

void registerMethod(const char* name, Access access, Handler handler, Handler check) {
    const bool inserted = methods().emplace(name, Method{access, std::move(handler), std::move(check)}).second;
    if (!inserted) {
        ESP_LOGE(TAG, "method %s registered twice", name);
        abort();
    }
}

Presence confirmPresence(const char* action, const Context& context) {
    cJSON* required = cJSON_CreateObject();
    cJSON_AddStringToObject(required, "action", action);
    cJSON_AddNumberToObject(required, "timeoutMs", kConfirmTimeoutMs);
    events::publish("confirm.required", required);
    const bool pressed = board::waitForPress(kConfirmTimeoutMs, [&context] { return sessionOpen(context); });
    const bool open = sessionOpen(context);
    cJSON* result = cJSON_CreateObject();
    cJSON_AddStringToObject(result, "action", action);
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
    Json result(cJSON_CreateObject());
    cJSON* id = cJSON_AddStringToObject(result.get(), "job", "job-00000000");
    if (!result || id == nullptr) return fail("internal", "out of memory");
    const std::optional<uint32_t> session = spec.context.session;
    jobs::Work work(new (std::nothrow) JobSpec(std::move(spec)));
    if (work == nullptr) return fail("internal", "out of memory");
    const std::optional<std::string> job = jobs::submit(session, std::move(work));
    if (!job.has_value()) {
        return fail("busy", "too many requests are waiting; try again");
    }
    std::memcpy(id->valuestring, job->c_str(), job->size() + 1);
    Reply reply = ok(result.release());
    reply.audited = false;
    return reply;
}

Reply executeJob(JobSpec spec, bool expired) {
    Reply reply = runJob(spec, expired);
    if (spec.finish) spec.finish(spec, reply);
    return reply;
}

Response dispatch(latchkey_util::RpcText requestJson, Transport origin, std::string_view sessionToken) {
    if (requestJson.size() > latchkey_util::kMaxRpcText) {
        return respond(nullptr, fail("bad_request", "request too large"));
    }
    if (containsNul(requestJson.view())) {
        return respond(nullptr, fail("bad_request", "NUL characters are not supported"));
    }
    if (!latchkey_util::jsonNestingWithin(requestJson.view(), kMaxNesting)) {
        return respond(nullptr, fail("bad_request", "request nested too deeply"));
    }
    if (!latchkey_util::jsonValuesWithin(requestJson.view(), kMaxValues)) {
        return respond(nullptr, fail("bad_request", "request has too many values"));
    }
    Json request(cJSON_ParseWithLengthOpts(requestJson.c_str(), requestJson.size() + 1, nullptr, true));
    requestJson.clear();
    if (request == nullptr || !cJSON_IsObject(request.get())) {
        return respond(nullptr, fail("bad_request", "request must be a JSON object"));
    }
    Json id(cJSON_DetachItemFromObjectCaseSensitive(request.get(), "id"));
    if (!isValidId(id.get())) {
        return respond(nullptr, fail("bad_request", "id must be a number or a string"));
    }
    const cJSON* method = cJSON_GetObjectItemCaseSensitive(request.get(), "method");
    if (!cJSON_IsString(method) || method->valuestring == nullptr) {
        return respond(std::move(id), fail("bad_request", "method must be a string"));
    }
    Json params(cJSON_DetachItemFromObjectCaseSensitive(request.get(), "params"));
    if (params == nullptr || cJSON_IsNull(params.get())) {
        params.reset(cJSON_CreateObject());
        if (params == nullptr) return respond(std::move(id), fail("internal", "out of memory"));
    }
    if (!cJSON_IsObject(params.get())) {
        return respond(std::move(id), fail("invalid_argument", "params must be an object"));
    }
    const auto entry = methods().find(std::string_view(method->valuestring));
    if (entry == methods().end()) {
        return respond(std::move(id), fail("unknown_method", "no such method"));
    }
    const Method& target = entry->second;
    request.reset();
    const Context context{origin, origin == Transport::Web ? auth::sessionFor(sessionToken) : std::nullopt};
    const latchkey_util::AccessDecision decision = decide(target.access, context);
    Reply reply;
    if (decision.error != nullptr) {
        reply = fail(decision.error, decision.message);
        reply.audited = decision.audited;
    } else if (decision.job) {
        reply = startJob(methodJob(entry->first, target, context, decision.confirm, std::move(params)));
    } else {
        reply = target.handler(params.get(), context);
    }
    params.reset();
    record(entry->first, target, context, reply);
    return respond(std::move(id), std::move(reply));
}

latchkey_util::RpcText errorLine(const char* code, const char* message) { return renderReply(nullptr, fail(code, message)); }

}
