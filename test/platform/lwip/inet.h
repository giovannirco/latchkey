// SPDX-License-Identifier: GPL-3.0-or-later
#pragma once
#include <arpa/inet.h>
inline char* inet_ntoa_r(in_addr address, char* text, int length) {
    return const_cast<char*>(inet_ntop(AF_INET, &address, text, length));
}
