// SPDX-License-Identifier: GPL-3.0-or-later
#pragma once

#include <cstddef>
#include <cstdint>
#include <functional>
#include <optional>
#include <string>

#include "esp_err.h"
#include "rpc.h"
#include "store.h"
#include "ttlock/session.h"
#include "ttlock/status.h"

namespace lock_manager {

using LockWork =
    std::function<ttlock::Status(ttlock::Session& session, const store::locks::Record& record, rpc::Reply& reply)>;

void start();

rpc::Reply scan(uint32_t seconds);

rpc::Reply pair(const std::string& mac, const std::string& name, uint32_t waitSeconds,
                const std::string& adminPasscode);

rpc::Reply list();

bool holds(const std::string& mac);

bool record(const std::string& mac, store::locks::Record& out);

rpc::Reply featureMask(const std::string& mac, uint64_t& out);

rpc::Reply runOnLock(const std::string& mac, const char* action, LockWork work);

esp_err_t loadLabels(const std::string& mac, store::labels::Kind kind, latchkey_util::LabelTable& out);

esp_err_t saveLabels(const std::string& mac, store::labels::Kind kind, const latchkey_util::LabelTable& table);

bool labelsFit(const std::string& mac, store::labels::Kind kind, const latchkey_util::LabelTable& table);

struct AdminPasscodeCopy {
    std::string code;
    bool confirmed = false;

    ~AdminPasscodeCopy();
};

bool stageAdminPasscode(const std::string& mac, const std::string& candidate, AdminPasscodeCopy& previous);

bool confirmAdminPasscode(const std::string& mac);

bool restoreAdminPasscode(const std::string& mac, const AdminPasscodeCopy& previous);

rpc::Reply rename(const std::string& mac, const std::string& name);

rpc::Reply forget(const std::string& mac);

rpc::Reply status(const std::string& mac);

rpc::Reply info(const std::string& mac);

rpc::Reply features(const std::string& mac);

rpc::Reply unlock(const std::string& mac);

rpc::Reply readLog(const std::string& mac, std::optional<uint16_t> since);

esp_err_t rememberAlert(const std::string& mac, const latchkey_util::LockAlert& alert, bool& added);

rpc::Reply alerts(const std::string& mac);

rpc::Reply acknowledgeAlerts(const std::string& mac, uint32_t through);

cJSON* warnings();

rpc::Reply lock(const std::string& mac);

rpc::Reply syncTime(const std::string& mac);

rpc::Reply factoryReset(const std::string& mac);

esp_err_t storedCount(size_t& out);

esp_err_t eraseAll();

void cancelErase();

uint32_t workerStackFree();

}
