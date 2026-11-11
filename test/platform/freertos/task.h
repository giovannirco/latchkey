// SPDX-License-Identifier: GPL-3.0-or-later
#pragma once

#include "FreeRTOS.h"

using TaskHandle_t = void*;
BaseType_t xTaskCreate(void (*)(void*), const char*, uint32_t, void*, UBaseType_t, TaskHandle_t*);
BaseType_t xTaskCreatePinnedToCore(void (*)(void*), const char*, uint32_t, void*, UBaseType_t, TaskHandle_t*, BaseType_t);
void vTaskDelay(TickType_t ticks);
TaskHandle_t xTaskGetCurrentTaskHandle();
TaskHandle_t xTaskGetHandle(const char*);
uint32_t uxTaskGetStackHighWaterMark(TaskHandle_t);
void vTaskDelete(TaskHandle_t);
void xTaskNotifyGive(TaskHandle_t);
uint32_t ulTaskNotifyTake(BaseType_t, TickType_t);
