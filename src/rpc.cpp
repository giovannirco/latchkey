// SPDX-License-Identifier: GPL-3.0-or-later
#include "rpc.h"

#include <cstdlib>
#include <map>
#include <string_view>
#include <utility>

#include "esp_log.h"

#include "audit.h"
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

cJSON* errorObject(const std::string& code, const std::string& message) {
    cJSON* error = cJSON_CreateObject();
    cJSON_AddStringToObject(error, "code", code.c_str());
    cJSON_AddStringToObject(error, "message", message.c_str());
    return error;
}

std::string render(const cJSON* id, Reply reply) {
    Json envelope(cJSON_CreateObject());
    cJSON_AddItemToObject(envelope.get(), "id", id != nullptr ? cJSON_Duplicate(id, true) : cJSON_CreateNull());
    if (reply.error.empty()) {
        cJSON_AddItemToObject(envelope.get(), "result",
                              reply.result != nullptr ? reply.result.release() : cJSON_CreateObject());
    } else {
        cJSON_AddItemToObject(envelope.get(), "error", errorObject(reply.error, reply.message));
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

Reply checkAccess(const Access& access, Transport origin) {
    if (origin == Transport::Serial) {
        return ok();
    }
    if (access.serialOnly) {
        return fail("forbidden", "serial console only");
    }
    if (access.needsSession || access.needsButton) {
        return fail("unauthorized", "no web session");
    }
    return ok();
}

uint32_t auditTime() { return wallclock::synced() ? static_cast<uint32_t>(wallclock::utcSeconds()) : 0; }

}

const char* toString(Transport transport) { return transport == Transport::Serial ? "serial" : "web"; }

Reply ok(cJSON* result) { return Reply{Json(result), {}, {}, {}}; }

Reply fail(const char* code, const char* message) { return Reply{nullptr, code, message, {}}; }

void registerMethod(const char* name, Access access, Handler handler) {
    const bool inserted = methods().emplace(name, Method{access, std::move(handler)}).second;
    if (!inserted) {
        ESP_LOGE(TAG, "method %s registered twice", name);
        abort();
    }
}

std::string dispatch(const char* requestJson, Transport origin) {
    if (!latchkey_util::jsonNestingWithin(requestJson, kMaxNesting)) {
        return render(nullptr, fail("bad_request", "request nested too deeply"));
    }
    Json request(cJSON_ParseWithOpts(requestJson, nullptr, true));
    if (request == nullptr || !cJSON_IsObject(request.get())) {
        return render(nullptr, fail("bad_request", "request must be a JSON object"));
    }
    const cJSON* id = cJSON_GetObjectItemCaseSensitive(request.get(), "id");
    if (!isValidId(id)) {
        return render(nullptr, fail("bad_request", "id must be a number or a string"));
    }
    const cJSON* method = cJSON_GetObjectItemCaseSensitive(request.get(), "method");
    if (!cJSON_IsString(method) || method->valuestring == nullptr) {
        return render(id, fail("bad_request", "method must be a string"));
    }
    const cJSON* params = cJSON_GetObjectItemCaseSensitive(request.get(), "params");
    Json emptyParams;
    if (params == nullptr || cJSON_IsNull(params)) {
        emptyParams.reset(cJSON_CreateObject());
        params = emptyParams.get();
    }
    if (!cJSON_IsObject(params)) {
        return render(id, fail("invalid_argument", "params must be an object"));
    }
    const auto entry = methods().find(std::string_view(method->valuestring));
    if (entry == methods().end()) {
        return render(id, fail("unknown_method", "no such method"));
    }
    const Method& target = entry->second;
    Reply reply = checkAccess(target.access, origin);
    if (reply.error.empty()) {
        reply = target.handler(params, Context{origin});
    }
    if (target.access.audited) {
        audit::append({auditTime(), origin, entry->first, reply.target, reply.error.empty() ? "ok" : reply.error});
    }
    return render(id, std::move(reply));
}

std::string errorLine(const char* code, const char* message) { return render(nullptr, fail(code, message)); }

}
