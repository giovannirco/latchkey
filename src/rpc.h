// SPDX-License-Identifier: GPL-3.0-or-later
#pragma once

#include <cstdint>
#include <functional>
#include <memory>
#include <optional>
#include <string>
#include <string_view>

#include "cJSON.h"

namespace rpc {

enum class Transport : uint8_t {
    Serial,
    Web,
};

const char* toString(Transport transport);

struct Access {
    bool needsSession = true;
    bool needsButton = false;
    bool serialOnly = false;
    bool audited = true;
    bool job = false;
};

struct Context {
    Transport origin;
    std::optional<uint32_t> session;
};

struct JsonDeleter {
    void operator()(cJSON* json) const { cJSON_Delete(json); }
};

using Json = std::unique_ptr<cJSON, JsonDeleter>;

struct Reply {
    Json result;
    std::string error;
    std::string message;
    std::string target;
    Json errorData;
    std::string sessionToken;
    bool endSession = false;
    bool audited = true;
};

struct Response {
    std::string json;
    std::string sessionToken;
    bool endSession = false;
};

Reply ok(cJSON* result = nullptr);

Reply fail(const char* code, const char* message);

void addOutcome(cJSON* object, Reply reply);

using Handler = std::function<Reply(const cJSON* params, const Context& context)>;

void registerMethod(const char* name, Access access, Handler handler);

Response dispatch(const char* requestJson, Transport origin, std::string_view sessionToken);

std::string errorLine(const char* code, const char* message);

}
