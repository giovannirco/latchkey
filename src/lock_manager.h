// SPDX-License-Identifier: GPL-3.0-or-later
#pragma once

#include <cstddef>
#include <cstdint>
#include <functional>
#include <optional>
#include <string>

#include "esp_err.h"
#include "latchkey_util/key_restore.h"
#include "rpc.h"
#include "store.h"
#include "ttlock/session.h"
#include "ttlock/status.h"

namespace lock_manager {

using LockWork =
    std::function<ttlock::Status(ttlock::Session& session, const store::locks::Record& record, rpc::Reply& reply)>;

class StoragePublication : public latchkey_util::RestorePublication {
public:
    virtual void metadataChanged(std::string_view mac, const latchkey_util::LockMetadata* metadata) noexcept = 0;
};

using StorageWork = std::function<rpc::Reply(latchkey_util::RestoreStorage&, StoragePublication&)>;

rpc::Reply runStorage(const char* action, StorageWork work);

void start();

rpc::Reply scan(uint32_t seconds);

rpc::Reply pair(const std::string& mac, const std::string& name, uint32_t waitSeconds,
                const std::string& adminPasscode);

rpc::Reply list();

bool holds(const std::string& mac);

bool record(const std::string& mac, store::locks::Record& out);

rpc::Reply featureMask(const std::string& mac, uint64_t& out);

rpc::Reply runOnLock(const std::string& mac, const char* action, LockWork work);
rpc::Reply runOnLockDirect(const std::string& mac, const char* action, LockWork work);
rpc::Reply synchronizeHardeningTime(ttlock::Session& session, const std::string& mac);
esp_err_t beginHardening(const std::string& mac);

rpc::Reply failure(ttlock::Status status, uint8_t lockError);

esp_err_t loadLabels(const std::string& mac, store::labels::Kind kind, latchkey_util::LabelTable& out);

esp_err_t saveLabels(const std::string& mac, store::labels::Kind kind, const latchkey_util::LabelTable& table);

bool labelsFit(const std::string& mac, store::labels::Kind kind, const latchkey_util::LabelTable& table);

struct AdminState {
    store::locks::Record record{};
    latchkey_util::LockMetadata metadata;
    ~AdminState();
};

esp_err_t readAdminState(const std::string& mac, AdminState& out);

esp_err_t stageAdminPasscode(const std::string& mac, std::string_view candidate,
                              latchkey_util::AdminProvenance provenance);

esp_err_t confirmAdminPasscode(const std::string& mac);

esp_err_t reconcileAdminPasscode(const std::string& mac, std::string_view observed);

esp_err_t rejectAdminPasscode(const std::string& mac);

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

esp_err_t checkEraseAll();

esp_err_t eraseAll();

void cancelErase();

uint32_t workerStackFree();

}
