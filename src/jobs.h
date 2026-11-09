// SPDX-License-Identifier: GPL-3.0-or-later
#pragma once

#include <cstdint>
#include <functional>
#include <optional>
#include <string>

#include "rpc.h"

namespace jobs {

using Work = std::unique_ptr<rpc::JobSpec>;

void start();

std::optional<std::string> submit(std::optional<uint32_t> session, Work work);

bool idle();

uint32_t stackFree();

}
