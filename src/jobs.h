// SPDX-License-Identifier: GPL-3.0-or-later
#pragma once

#include <cstdint>
#include <functional>
#include <optional>
#include <string>

#include "rpc.h"

namespace jobs {

using Work = std::function<rpc::Reply(bool expired)>;

using Task = std::function<void(bool expired)>;

void start();

std::optional<std::string> submit(std::optional<uint32_t> session, Work work);

bool post(Task task);

bool idle();

uint32_t stackFree();

}
