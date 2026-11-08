// SPDX-License-Identifier: GPL-3.0-or-later
#pragma once

#include <cstdint>
#include <functional>
#include <memory>
#include <string>

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
};

struct Context {
    Transport origin;
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
};

Reply ok(cJSON* result = nullptr);

Reply fail(const char* code, const char* message);

using Handler = std::function<Reply(const cJSON* params, const Context& context)>;

void registerMethod(const char* name, Access access, Handler handler);

std::string dispatch(const char* requestJson, Transport origin);

std::string errorLine(const char* code, const char* message);

}
