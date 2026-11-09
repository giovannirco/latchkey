// SPDX-License-Identifier: GPL-3.0-or-later
#pragma once

#include <cstdint>
#include <functional>
#include <memory>
#include <optional>
#include <string>
#include <string_view>

#include "cJSON.h"
#include "latchkey_util/rpc_text.h"

namespace rpc {

inline constexpr std::string_view kRenderFailure =
    R"({"id":null,"error":{"code":"internal","message":"reply exceeded memory limits"}})";

void init();

enum class Transport : uint8_t {
    Serial,
    Web,
    Mqtt,
    Board,
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
    latchkey_util::RpcText json;
    std::string sessionToken;
    bool endSession = false;
};

Reply ok(cJSON* result = nullptr);

Reply fail(const char* code, const char* message);

bool addOutcome(cJSON* object, Reply reply);
latchkey_util::RpcText render(Json envelope);

using Handler = std::function<Reply(cJSON* params, const Context& context)>;

void registerMethod(const char* name, Access access, Handler handler, Handler check = nullptr);

enum class Presence : uint8_t {
    Confirmed,
    NotPressed,
    SessionEnded,
};

Presence confirmPresence(const char* action, const Context& context);

struct JobSpec {
    const char* action = nullptr;
    Context context;
    bool confirm = false;
    bool audited = false;
    Json params;
    Handler check;
    Handler run;
    std::function<void(const JobSpec&, const Reply&)> finish;
};

Reply startJob(JobSpec spec);
Reply executeJob(JobSpec spec, bool expired);

Response dispatch(latchkey_util::RpcText requestJson, Transport origin, std::string_view sessionToken);

latchkey_util::RpcText errorLine(const char* code, const char* message);

}
