// SPDX-License-Identifier: GPL-3.0-or-later
#include "ota.h"

#include <algorithm>
#include <cinttypes>
#include <cstdint>
#include <cstdio>
#include <cstdlib>
#include <memory>
#include <new>
#include <optional>
#include <string>

#include "cJSON.h"
#include "esp_app_desc.h"
#include "esp_log.h"
#include "esp_ota_ops.h"
#include "esp_partition.h"
#include "esp_system.h"
#include "esp_timer.h"
#include "freertos/FreeRTOS.h"
#include "freertos/task.h"
#include "mbedtls/platform_util.h"
#include "sdkconfig.h"

#include "audit.h"
#include "auth.h"
#include "clock.h"
#include "console.h"
#include "http.h"
#include "jobs.h"
#include "latchkey_util/app_image.h"
#include "latchkey_util/first_boot.h"
#include "latchkey_util/web.h"
#include "rpc.h"
#include "store.h"
#include "wifi.h"

namespace ota {

namespace {

constexpr const char* TAG = "ota";
constexpr const char* kAction = "ota";
constexpr size_t kChunk = 4096;
constexpr size_t kContentType = 64;
constexpr int64_t kStallUs = 15LL * 1000 * 1000;
constexpr int64_t kUploadUs = 280LL * 1000 * 1000;
constexpr int64_t kDrainUs = 60LL * 1000 * 1000;
constexpr uint64_t kRestartDelayUs = 1000 * 1000;
constexpr uint32_t kCheckStack = 4096;
constexpr UBaseType_t kCheckPriority = 1;
constexpr TickType_t kCheckPeriod = pdMS_TO_TICKS(1000);
constexpr uint16_t kChipId = CONFIG_IDF_FIRMWARE_CHIP_ID;

struct Upload {
    httpd_req_t* req;
    rpc::Context context;
    size_t remaining;
};

esp_timer_handle_t s_restartTimer = nullptr;

int64_t nowUs() { return esp_timer_get_time(); }

uint32_t auditTime() { return wallclock::synced() ? static_cast<uint32_t>(wallclock::utcSeconds()) : 0; }

void record(const std::string& version, const char* result) {
    audit::append({auditTime(), rpc::Transport::Web, kAction, version, result});
}

esp_err_t refuseRecorded(httpd_req_t* req, const char* status, const char* code, const char* message) {
    record({}, code);
    return http::refuse(req, status, code, message);
}

bool receive(Upload& upload, uint8_t* buffer, size_t size, int64_t deadline) {
    size_t received = 0;
    int64_t progress = nowUs();
    while (received < size) {
        const int64_t now = nowUs();
        if (now > deadline || now - progress > kStallUs) {
            return false;
        }
        const int count = httpd_req_recv(upload.req, reinterpret_cast<char*>(buffer) + received, size - received);
        if (count == HTTPD_SOCK_ERR_TIMEOUT) {
            continue;
        }
        if (count <= 0) {
            return false;
        }
        received += static_cast<size_t>(count);
        upload.remaining -= static_cast<size_t>(count);
        progress = nowUs();
    }
    return true;
}

void drain(Upload& upload, uint8_t* buffer) {
    const int64_t deadline = nowUs() + kDrainUs;
    while (upload.remaining > 0 && receive(upload, buffer, std::min(kChunk, upload.remaining), deadline)) {
    }
}

void closeRequest(httpd_req_t* req) {
    const httpd_handle_t server = req->handle;
    const int fd = httpd_req_to_sockfd(req);
    httpd_req_async_handler_complete(req);
    httpd_sess_trigger_close(server, fd);
}

void respond(Upload& upload, uint8_t* buffer, const char* status, const std::string& json) {
    httpd_resp_set_hdr(upload.req, "Connection", "close");
    if (http::sendJson(upload.req, status, json) != ESP_OK) {
        ESP_LOGW(TAG, "the reply to an update could not be sent");
    }
    if (buffer != nullptr) {
        drain(upload, buffer);
    }
    closeRequest(upload.req);
}

void fail(Upload& upload, uint8_t* buffer, const std::string& version, const char* status, const char* code,
          const std::string& message) {
    record(version, code);
    respond(upload, buffer, status, rpc::errorLine(code, message.c_str()));
}

std::optional<std::string> headProblem(const uint8_t* data, size_t size, latchkey_util::AppImageHead& head) {
    const latchkey_util::ImageHeadVerdict verdict =
        latchkey_util::checkAppImageHead(data, size, kChipId, esp_app_get_description()->project_name, head);
    if (verdict != latchkey_util::ImageHeadVerdict::Ok) {
        return latchkey_util::appImageProblem(verdict, head, kChipId);
    }
    const auto* header = reinterpret_cast<const esp_image_header_t*>(data);
    const auto* description =
        reinterpret_cast<const esp_app_desc_t*>(data + sizeof(esp_image_header_t) + sizeof(esp_image_segment_header_t));
    const esp_err_t validity = esp_ota_check_image_validity(ESP_PARTITION_TYPE_APP, header, description);
    if (validity == ESP_ERR_INVALID_VERSION) {
        return "this image does not support the revision of this chip";
    }
    if (validity == ESP_ERR_OTA_SPI_MODE_MISMATCH) {
        return "this image expects another flash mode than this board uses";
    }
    if (validity != ESP_OK) {
        return "this image cannot run on this board";
    }
    return std::nullopt;
}

bool pendingVerify() {
    esp_ota_img_states_t state;
    return esp_ota_get_state_partition(esp_ota_get_running_partition(), &state) == ESP_OK &&
           state == ESP_OTA_IMG_PENDING_VERIFY;
}

void restartNow(void*) {
    console::flush();
    esp_restart();
}

bool confirmed(Upload& upload, uint8_t* buffer, const std::string& version) {
    switch (rpc::confirmPresence(kAction, upload.context)) {
        case rpc::Presence::Confirmed:
            return true;
        case rpc::Presence::NotPressed:
            fail(upload, buffer, version, "403 Forbidden", "confirm_timeout", "the button was not pressed within 30 s");
            return false;
        case rpc::Presence::SessionEnded:
            break;
    }
    fail(upload, buffer, version, "401 Unauthorized", "unauthorized", "the session ended before the update ran");
    return false;
}

bool stream(Upload& upload, uint8_t* buffer, size_t first, esp_ota_handle_t handle, int64_t deadline,
            esp_err_t& error) {
    error = esp_ota_write(handle, buffer, first);
    while (error == ESP_OK && upload.remaining > 0) {
        const size_t size = std::min(kChunk, upload.remaining);
        if (!receive(upload, buffer, size, deadline)) {
            return false;
        }
        error = esp_ota_write(handle, buffer, size);
    }
    return true;
}

void install(Upload upload, bool expired) {
    if (expired) {
        fail(upload, nullptr, {}, "503 Service Unavailable", "busy", "the board was busy with other requests; try again");
        return;
    }
    std::unique_ptr<uint8_t[]> buffer(new (std::nothrow) uint8_t[kChunk]);
    if (buffer == nullptr) {
        fail(upload, nullptr, {}, "503 Service Unavailable", "busy", "the board is out of memory");
        return;
    }
    const int64_t started = nowUs();
    const int64_t deadline = started + kUploadUs;
    const size_t bytes = upload.remaining;
    const size_t first = std::min(kChunk, upload.remaining);
    if (!receive(upload, buffer.get(), first, deadline)) {
        record({}, "bad_request");
        closeRequest(upload.req);
        return;
    }
    latchkey_util::AppImageHead head;
    const std::optional<std::string> problem = headProblem(buffer.get(), first, head);
    if (problem.has_value()) {
        fail(upload, buffer.get(), {}, "400 Bad Request", "invalid_argument", *problem);
        return;
    }
    if (!confirmed(upload, buffer.get(), head.version)) {
        return;
    }
    const esp_partition_t* target = esp_ota_get_next_update_partition(nullptr);
    esp_ota_handle_t handle = 0;
    esp_err_t error = esp_ota_begin(target, OTA_WITH_SEQUENTIAL_WRITES, &handle);
    if (error != ESP_OK) {
        ESP_LOGE(TAG, "cannot start writing %s: %s", target->label, esp_err_to_name(error));
        fail(upload, buffer.get(), head.version, "500 Internal Server Error", "internal",
             "the board cannot start writing the update");
        return;
    }
    if (!stream(upload, buffer.get(), first, handle, deadline, error)) {
        esp_ota_abort(handle);
        ESP_LOGW(TAG, "the upload stopped with %u bytes left", static_cast<unsigned>(upload.remaining));
        record(head.version, "bad_request");
        closeRequest(upload.req);
        return;
    }
    if (error != ESP_OK) {
        esp_ota_abort(handle);
        ESP_LOGE(TAG, "cannot write %s: %s", target->label, esp_err_to_name(error));
        fail(upload, buffer.get(), head.version, "500 Internal Server Error", "internal",
             "the board cannot write the update");
        return;
    }
    error = esp_ota_end(handle);
    ESP_LOGI(TAG, "%u bytes received in %lld ms, heap min free %u, worker stack free %u", static_cast<unsigned>(bytes),
             static_cast<long long>((nowUs() - started) / 1000), static_cast<unsigned>(esp_get_minimum_free_heap_size()),
             static_cast<unsigned>(uxTaskGetStackHighWaterMark(nullptr)));
    if (error == ESP_ERR_OTA_VALIDATE_FAILED) {
        fail(upload, buffer.get(), head.version, "400 Bad Request", "invalid_argument",
             "the image did not pass verification; the board keeps its firmware");
        return;
    }
    if (error != ESP_OK) {
        ESP_LOGE(TAG, "cannot finish %s: %s", target->label, esp_err_to_name(error));
        fail(upload, buffer.get(), head.version, "500 Internal Server Error", "internal",
             "the board cannot finish the update");
        return;
    }
    if (!auth::sessionOpen(*upload.context.session)) {
        fail(upload, buffer.get(), head.version, "401 Unauthorized", "unauthorized",
             "the session ended before the update ran");
        return;
    }
    error = esp_ota_set_boot_partition(target);
    if (error != ESP_OK) {
        ESP_LOGE(TAG, "cannot boot from %s: %s", target->label, esp_err_to_name(error));
        fail(upload, buffer.get(), head.version, "500 Internal Server Error", "internal",
             "the board cannot switch to the update");
        return;
    }
    record(head.version, "ok");
    char reply[64];
    std::snprintf(reply, sizeof(reply), R"({"result":{"bytes":%u,"rebooting":true}})", static_cast<unsigned>(bytes));
    respond(upload, nullptr, HTTPD_200, reply);
    ESP_LOGW(TAG, "firmware %s written to %s; restarting into it", head.version.c_str(), target->label);
    if (esp_timer_start_once(s_restartTimer, kRestartDelayUs) != ESP_OK) {
        restartNow(nullptr);
    }
}

latchkey_util::FirstBootSignals readSignals() {
    latchkey_util::FirstBootSignals signals;
    store::Usage usage;
    size_t locks = 0;
    signals.storageReadable = store::usage(usage) == ESP_OK && store::locks::count(locks) == ESP_OK;
    signals.consoleRunning = xTaskGetHandle("console") != nullptr;
    const wifi::Status status = wifi::status();
    signals.wifiConfigured = status.configured;
    signals.wifiStarted = wifi::running();
    signals.wifiConnected = status.connected;
    signals.webServing = http::serving();
    return signals;
}

void watchFirstBoot(void*) {
    while (true) {
        vTaskDelay(kCheckPeriod);
        const latchkey_util::FirstBootSignals signals = readSignals();
        const auto uptime = static_cast<uint32_t>(nowUs() / 1000000);
        const latchkey_util::FirstBootVerdict verdict = latchkey_util::judgeFirstBoot(signals, uptime);
        if (verdict == latchkey_util::FirstBootVerdict::Healthy) {
            const esp_err_t error = esp_ota_mark_app_valid_cancel_rollback();
            if (error == ESP_OK) {
                ESP_LOGI(TAG, "firmware %s passed its first-boot check and is kept", esp_app_get_description()->version);
            } else {
                ESP_LOGE(TAG, "cannot keep the firmware: %s", esp_err_to_name(error));
            }
            break;
        }
        if (verdict == latchkey_util::FirstBootVerdict::Unhealthy) {
            ESP_LOGE(TAG, "the new firmware failed its first-boot check (%s); restarting into the previous one",
                     latchkey_util::firstBootProblem(signals));
            restartNow(nullptr);
        }
    }
    vTaskDelete(nullptr);
}

const char* stateName(esp_ota_img_states_t state) {
    switch (state) {
        case ESP_OTA_IMG_NEW:
            return "new";
        case ESP_OTA_IMG_PENDING_VERIFY:
            return "pending_verify";
        case ESP_OTA_IMG_VALID:
            return "valid";
        case ESP_OTA_IMG_INVALID:
            return "invalid";
        case ESP_OTA_IMG_ABORTED:
            return "aborted";
        case ESP_OTA_IMG_UNDEFINED:
            return "undefined";
    }
    return "unknown";
}

void addText(cJSON* object, const char* key, const std::optional<std::string>& value) {
    if (value.has_value()) {
        cJSON_AddStringToObject(object, key, value->c_str());
    } else {
        cJSON_AddNullToObject(object, key);
    }
}

cJSON* slotJson(const esp_partition_t* partition) {
    cJSON* slot = cJSON_CreateObject();
    cJSON_AddStringToObject(slot, "slot", partition->label);
    uint8_t bytes[latchkey_util::kAppImageHeadBytes];
    latchkey_util::AppImageHead head;
    const bool image = esp_partition_read(partition, 0, bytes, sizeof(bytes)) == ESP_OK &&
                       latchkey_util::checkAppImageHead(bytes, sizeof(bytes), kChipId,
                                                        esp_app_get_description()->project_name,
                                                        head) != latchkey_util::ImageHeadVerdict::NotAnImage;
    addText(slot, "version", image ? std::optional<std::string>(head.version) : std::nullopt);
    addText(slot, "elfSha256", image ? std::optional<std::string>(head.elfSha256) : std::nullopt);
    esp_ota_img_states_t state;
    addText(slot, "state",
            esp_ota_get_state_partition(partition, &state) == ESP_OK ? std::optional<std::string>(stateName(state))
                                                                     : std::nullopt);
    return slot;
}

rpc::Reply status(const cJSON*, const rpc::Context&) {
    const esp_partition_t* running = esp_ota_get_running_partition();
    const esp_partition_t* other = esp_ota_get_next_update_partition(nullptr);
    const esp_partition_t* boot = esp_ota_get_boot_partition();
    if (running == nullptr || other == nullptr || boot == nullptr) {
        return rpc::fail("internal", "cannot read the app slots");
    }
    cJSON* result = cJSON_CreateObject();
    cJSON_AddItemToObject(result, "running", slotJson(running));
    cJSON_AddItemToObject(result, "other", slotJson(other));
    cJSON_AddStringToObject(result, "boot", boot->label);
    return rpc::ok(result);
}

}

void start() {
    const esp_timer_create_args_t restart = {
        .callback = restartNow,
        .arg = nullptr,
        .dispatch_method = ESP_TIMER_TASK,
        .name = "ota_restart",
        .skip_unhandled_events = true,
    };
    ESP_ERROR_CHECK(esp_timer_create(&restart, &s_restartTimer));
    rpc::registerMethod("system.ota.status", {.serialOnly = true, .audited = false}, status);
    const esp_partition_t* running = esp_ota_get_running_partition();
    if (!pendingVerify()) {
        ESP_LOGI(TAG, "running %s from %s", esp_app_get_description()->version, running->label);
        return;
    }
    ESP_LOGW(TAG, "first boot of %s from %s: it is kept once it has run %" PRIu32 " s with storage, console and Wi-Fi",
             esp_app_get_description()->version, running->label, latchkey_util::kFirstBootSettleSeconds);
    if (xTaskCreate(watchFirstBoot, "ota_check", kCheckStack, nullptr, kCheckPriority, nullptr) != pdPASS) {
        ESP_LOGE(TAG, "cannot start the first-boot check");
        abort();
    }
}

esp_err_t accept(httpd_req_t* req) {
    if (!http::fromBoardAddress(req)) {
        return http::refuse(req, "403 Forbidden", "forbidden", "cross-origin request refused");
    }
    std::string token = http::sessionToken(req);
    const std::optional<uint32_t> session = auth::sessionFor(token);
    mbedtls_platform_zeroize(token.data(), token.size());
    if (!session.has_value()) {
        return http::refuse(req, "401 Unauthorized", "unauthorized", "sign in first");
    }
    char type[kContentType] = {};
    if (httpd_req_get_hdr_value_str(req, "Content-Type", type, sizeof(type)) != ESP_OK ||
        !latchkey_util::isOctetStreamContentType(type)) {
        return refuseRecorded(req, "415 Unsupported Media Type", "invalid_argument",
                              "send the image as application/octet-stream");
    }
    const esp_partition_t* target = esp_ota_get_next_update_partition(nullptr);
    switch (latchkey_util::checkUploadSize(req->content_len, target->size)) {
        case latchkey_util::UploadSize::TooSmall:
            return refuseRecorded(req, "400 Bad Request", "invalid_argument", "the file is too small to be firmware");
        case latchkey_util::UploadSize::TooLarge: {
            char message[64];
            std::snprintf(message, sizeof(message), "the image is larger than the %" PRIu32 "-byte app slot",
                          target->size);
            return refuseRecorded(req, "413 Content Too Large", "invalid_argument", message);
        }
        case latchkey_util::UploadSize::Fits:
            break;
    }
    if (pendingVerify()) {
        return refuseRecorded(req, "503 Service Unavailable", "busy",
                              "the board is still checking the firmware it started with; try again in two minutes");
    }
    if (!jobs::idle()) {
        return refuseRecorded(req, "503 Service Unavailable", "busy",
                              "the board is waiting on another request; try again when it is done");
    }
    httpd_req_t* copy = nullptr;
    if (httpd_req_async_handler_begin(req, &copy) != ESP_OK) {
        return refuseRecorded(req, "503 Service Unavailable", "busy", "the board is out of memory");
    }
    const Upload upload{copy, rpc::Context{rpc::Transport::Web, session}, copy->content_len};
    if (!jobs::post([upload](bool expired) { install(upload, expired); })) {
        Upload refused = upload;
        fail(refused, nullptr, {}, "503 Service Unavailable", "busy", "the board is answering other requests");
    }
    return ESP_OK;
}

}
