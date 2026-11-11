// SPDX-License-Identifier: GPL-3.0-or-later
#pragma once

#include <fcntl.h>
#include <netinet/tcp.h>
#include <sys/socket.h>

int lwip_shutdown(int fd, int how);
#define shutdown(fd, how) lwip_shutdown(fd, how)
