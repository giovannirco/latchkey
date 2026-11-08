// SPDX-License-Identifier: GPL-3.0-or-later
#pragma once

#include <cstddef>
#include <cstdint>
#include <string>

#include "esp_err.h"
#include "rpc.h"

namespace lock_manager {

void start();

rpc::Reply scan(uint32_t seconds);

rpc::Reply pair(const std::string& mac, const std::string& name, uint32_t waitSeconds);

rpc::Reply list();

rpc::Reply rename(const std::string& mac, const std::string& name);

rpc::Reply forget(const std::string& mac);

rpc::Reply status(const std::string& mac);

rpc::Reply info(const std::string& mac);

rpc::Reply features(const std::string& mac);

rpc::Reply unlock(const std::string& mac);

rpc::Reply lock(const std::string& mac);

rpc::Reply syncTime(const std::string& mac);

rpc::Reply factoryReset(const std::string& mac);

esp_err_t storedCount(size_t& out);

esp_err_t eraseAll();

void cancelErase();

uint32_t workerStackFree();

}
