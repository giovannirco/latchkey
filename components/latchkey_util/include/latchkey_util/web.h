// SPDX-License-Identifier: GPL-3.0-or-later
#pragma once

#include <optional>
#include <string>
#include <string_view>

namespace latchkey_util {

inline constexpr const char* kSessionCookieName = "lk_session";
inline constexpr const char* kClearedSessionCookie = "lk_session=; Path=/; Max-Age=0; Secure; HttpOnly; SameSite=Strict";

bool isJsonContentType(std::string_view value);

bool sameOrigin(std::string_view origin, std::string_view host);

std::optional<std::string> httpsRedirect(std::string_view host);

std::string sessionCookie(std::string_view token);

}
