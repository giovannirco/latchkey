// SPDX-License-Identifier: GPL-3.0-or-later
#include "rpc.h"

#include <cstdlib>
#include <map>
#include <string_view>
#include <utility>

#include "esp_log.h"

#include "audit.h"
#include "auth.h"
#include "clock.h"
#include "latchkey_util/json_depth.h"

namespace rpc {

namespace {

constexpr const char* TAG = "rpc";
constexpr size_t kMaxNesting = 8;
constexpr const char* kOutOfMemoryLine = R"({"id":null,"error":{"code":"internal","message":"out of memory"}})";

struct Method {
    Access access;
    Handler handler;
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
    if (reply.error.empty()) {
        cJSON_AddItemToObject(envelope.get(), "result",
                              reply.result != nullptr ? reply.result.release() : cJSON_CreateObject());
    } else {
        cJSON_AddItemToObject(envelope.get(), "error", errorObject(reply));
    }
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

Reply refuse(const char* code, const char* message, const Context& context) {
    Reply reply = fail(code, message);
    reply.audited = context.session.has_value();
    return reply;
}

Reply checkAccess(const Access& access, const Context& context) {
    if (context.origin == Transport::Serial) {
        return ok();
    }
    if (access.serialOnly) {
        return refuse("forbidden", "serial console only", context);
    }
    if (access.needsSession && !context.session.has_value()) {
        return refuse("unauthorized", "sign in first", context);
    }
    if (access.needsButton) {
        return refuse("forbidden", "this needs a press of the board's button, which the web cannot ask for yet",
                      context);
    }
    return ok();
}

Response respond(const cJSON* id, Reply reply) {
    Response response;
    response.sessionToken = std::move(reply.sessionToken);
    response.endSession = reply.endSession;
    response.json = render(id, std::move(reply));
    return response;
}

uint32_t auditTime() { return wallclock::synced() ? static_cast<uint32_t>(wallclock::utcSeconds()) : 0; }

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

void registerMethod(const char* name, Access access, Handler handler) {
    const bool inserted = methods().emplace(name, Method{access, std::move(handler)}).second;
    if (!inserted) {
        ESP_LOGE(TAG, "method %s registered twice", name);
        abort();
    }
}

Response dispatch(const char* requestJson, Transport origin, std::string_view sessionToken) {
    if (!latchkey_util::jsonNestingWithin(requestJson, kMaxNesting)) {
        return respond(nullptr, fail("bad_request", "request nested too deeply"));
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
    Reply reply = checkAccess(target.access, context);
    if (reply.error.empty()) {
        reply = target.handler(params, context);
    }
    if (target.access.audited && reply.audited) {
        audit::append({auditTime(), origin, entry->first, reply.target, reply.error.empty() ? "ok" : reply.error});
    }
    return respond(id, std::move(reply));
}

std::string errorLine(const char* code, const char* message) { return render(nullptr, fail(code, message)); }

}
