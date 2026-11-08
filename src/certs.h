// SPDX-License-Identifier: GPL-3.0-or-later
#pragma once

#include <cstdint>
#include <optional>
#include <string>

#include "esp_err.h"
#include "latchkey_util/certificate.h"

namespace certs {

void init();

esp_err_t ensure(uint32_t ipv4, latchkey_util::TlsIdentity& out);

std::optional<std::string> fingerprint();

}
