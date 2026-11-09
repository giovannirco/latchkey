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

#include "latchkey_util/job_queue.h"
#include "ws.h"

namespace jobs {

namespace {

constexpr const char* TAG = "jobs";
constexpr uint32_t kTaskStack = 5120;
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
bool s_running = false;

uint32_t nowMs() { return static_cast<uint32_t>(esp_timer_get_time() / 1000); }

latchkey_util::RpcText doneLine(const Job& job, rpc::Reply reply) {
    rpc::Json event(cJSON_CreateObject());
    if (!event || !cJSON_AddStringToObject(event.get(), "event", "job.done")) return {};
    cJSON* data = cJSON_AddObjectToObject(event.get(), "data");
    if (data == nullptr || !cJSON_AddStringToObject(data, "job", job.id.c_str()) ||
        !rpc::addOutcome(data, std::move(reply))) return {};
    return rpc::render(std::move(event));
}

void finish(Job* job, bool expired) {
    rpc::Reply reply = rpc::executeJob(std::move(*job->work), expired);
    job->work.reset();
    auto line = doneLine(*job, std::move(reply));
    if (line.empty()) {
        ESP_LOGE(TAG, "out of memory rendering the outcome of %s", job->id.c_str());
    }
    ws::deliver(job->session, std::move(line));
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
            s_running = next.has_value();
        }
        for (Job* job : late) {
            finish(job, true);
        }
        if (next.has_value()) {
            finish(*next, false);
            std::lock_guard<std::mutex> lock(s_mutex);
            s_running = false;
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

bool idle() {
    std::lock_guard<std::mutex> lock(s_mutex);
    return !s_running && s_queue.empty();
}

uint32_t stackFree() { return s_task != nullptr ? uxTaskGetStackHighWaterMark(s_task) : 0; }

}
