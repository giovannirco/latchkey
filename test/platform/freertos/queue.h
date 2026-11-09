// SPDX-License-Identifier: GPL-3.0-or-later
#pragma once

#include "FreeRTOS.h"

using QueueHandle_t = void*;
QueueHandle_t xQueueCreate(UBaseType_t, UBaseType_t);
BaseType_t xQueueSend(QueueHandle_t, const void*, TickType_t);
BaseType_t xQueueReceive(QueueHandle_t, void*, TickType_t);
