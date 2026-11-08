// SPDX-License-Identifier: GPL-3.0-or-later
#include "jobs.h"

#include <cstdio>
#include <cstdlib>
#include <mutex>
#include <new>
#include <utility>
#include <vector>

#include "esp_log.h"
#include "esp_random.h"
#include "esp_timer.h"
#include "freertos/FreeRTOS.h"
#include "freertos/task.h"
#include "mbedtls/platform_util.h"

#include "latchkey_util/job_queue.h"
#include "ws.h"

namespace jobs {

namespace {

constexpr const char* TAG = "jobs";
constexpr uint32_t kTaskStack = 6144;
constexpr UBaseType_t kTaskPriority = 5;
constexpr size_t kCapacity = 4;
constexpr TickType_t kIdleWait = pdMS_TO_TICKS(1000);

struct Job {
    std::string id;
    std::optional<uint32_t> session;
    Work work;
};

std::mutex s_mutex;
latchkey_util::JobQueue<Job*> s_queue(kCapacity);
TaskHandle_t s_task = nullptr;
uint32_t s_nextId = 0;

uint32_t nowMs() { return static_cast<uint32_t>(esp_timer_get_time() / 1000); }

std::string doneLine(const Job& job, rpc::Reply reply) {
    cJSON* event = cJSON_CreateObject();
    cJSON_AddStringToObject(event, "event", "job.done");
    cJSON* data = cJSON_AddObjectToObject(event, "data");
    cJSON_AddStringToObject(data, "job", job.id.c_str());
    rpc::addOutcome(data, std::move(reply));
    char* text = cJSON_PrintUnformatted(event);
    cJSON_Delete(event);
    if (text == nullptr) {
        return {};
    }
    std::string line(text);
    mbedtls_platform_zeroize(text, line.size());
    cJSON_free(text);
    return line;
}

void finish(Job* job, bool expired) {
    std::string line = doneLine(*job, job->work(expired));
    if (line.empty()) {
        ESP_LOGE(TAG, "out of memory rendering the outcome of %s", job->id.c_str());
    } else {
        ws::deliver(job->session, std::move(line));
    }
    delete job;
}

void worker(void*) {
    while (true) {
        std::vector<Job*> late;
        std::optional<Job*> next;
        {
            std::lock_guard<std::mutex> lock(s_mutex);
            late = s_queue.expire(nowMs());
            next = s_queue.pop(nowMs());
        }
        for (Job* job : late) {
            finish(job, true);
        }
        if (next.has_value()) {
            finish(*next, false);
            continue;
        }
        ulTaskNotifyTake(pdTRUE, kIdleWait);
    }
}

}

void start() {
    s_nextId = esp_random();
    if (xTaskCreate(worker, "web_jobs", kTaskStack, nullptr, kTaskPriority, &s_task) != pdPASS) {
        ESP_LOGE(TAG, "cannot start the job task");
        abort();
    }
}

std::optional<std::string> submit(std::optional<uint32_t> session, Work work) {
    std::lock_guard<std::mutex> lock(s_mutex);
    char id[16];
    std::snprintf(id, sizeof(id), "job-%08x", static_cast<unsigned>(s_nextId++));
    Job* job = new (std::nothrow) Job{id, session, std::move(work)};
    if (job == nullptr || !s_queue.push(job, nowMs())) {
        delete job;
        return std::nullopt;
    }
    xTaskNotifyGive(s_task);
    return std::string(id);
}

uint32_t stackFree() { return s_task != nullptr ? uxTaskGetStackHighWaterMark(s_task) : 0; }

}
