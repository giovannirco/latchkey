// SPDX-License-Identifier: GPL-3.0-or-later
#define LOG_LOCAL_LEVEL ESP_LOG_DEBUG

#include "ble_central.h"

#include <algorithm>
#include <atomic>
#include <cstring>
#include <utility>

#include "esp_log.h"
#include "freertos/FreeRTOS.h"
#include "freertos/queue.h"
#include "freertos/semphr.h"
#include "freertos/task.h"
#include "host/ble_att.h"
#include "host/ble_gap.h"
#include "host/ble_gatt.h"
#include "host/ble_hs.h"
#include "host/ble_uuid.h"
#include "host/util/util.h"
#include "nimble/hci_common.h"
#include "nimble/nimble_port.h"
#include "nimble/nimble_port_freertos.h"
#include "os/os_mbuf.h"

#include "latchkey_util/ble_adv.h"
#include "ttlock/crc8.h"

namespace ble {

namespace {

constexpr const char* TAG = "ble";
constexpr UBaseType_t kInboxDepth = 16;
constexpr uint16_t kLockService = 0x1910;
constexpr uint16_t kWriteCharacteristic = 0xFFF2;
constexpr uint16_t kNotifyCharacteristic = 0xFFF4;
constexpr uint16_t kBatteryLevel = 0x2A19;
constexpr uint32_t kSettleMs = 500;
constexpr size_t kMinLockManufacturerData = 15;
constexpr uint8_t kV3ProtocolType = 0x05;
constexpr uint8_t kV3ProtocolVersion = 0x03;
constexpr size_t kChunk = 20;
constexpr size_t kCommandIndex = 9;
constexpr size_t kLengthIndex = 11;
constexpr uint32_t kProcedureTimeoutMs = 5000;
constexpr uint32_t kWriteTimeoutMs = 2000;
constexpr uint32_t kDisconnectTimeoutMs = 2000;
constexpr uint32_t kConnectGraceMs = 2000;
constexpr uint32_t kReceiveSliceMs = 200;
constexpr int kNoResponseRetries = 20;
constexpr int kBusyRetries = 5;
constexpr TickType_t kBusyRetryDelay = pdMS_TO_TICKS(20);
constexpr TickType_t kNoResponseRetryDelay = pdMS_TO_TICKS(10);
constexpr uint16_t kBackgroundIntervalMs = 500;
constexpr uint16_t kBackgroundWindowMs = 125;
constexpr uint16_t kFastIntervalMs = 60;
constexpr uint16_t kFastWindowMs = 30;
constexpr uint8_t kEnableNotifications[] = {0x01, 0x00};

struct Discovery {
    uint16_t serviceStart = 0;
    uint16_t serviceEnd = 0;
    uint16_t writeHandle = 0;
    uint8_t writeProperties = 0;
    uint16_t notifyHandle = 0;
    uint16_t notifyEnd = 0;
    uint16_t cccd = 0;
};

StaticQueue_t s_inboxBuffer;
uint8_t s_inboxStorage[kInboxDepth * sizeof(Message)];
QueueHandle_t s_inbox = nullptr;
StaticSemaphore_t s_procedureBuffer;
SemaphoreHandle_t s_procedureDone = nullptr;
StaticSemaphore_t s_connectBuffer;
SemaphoreHandle_t s_connectDone = nullptr;
StaticSemaphore_t s_disconnectBuffer;
SemaphoreHandle_t s_disconnectDone = nullptr;

std::atomic<bool> s_ready{false};
std::atomic<ScanMode> s_scan{ScanMode::Off};
std::atomic<uint16_t> s_connection{BLE_HS_CONN_HANDLE_NONE};
std::atomic<uint32_t> s_link{0};
std::atomic<uint16_t> s_notifyHandle{0};
std::atomic<uint32_t> s_procedure{0};
std::atomic<uint32_t> s_reports{0};
std::atomic<uint32_t> s_frames{0};
std::atomic<uint32_t> s_badCrc{0};
std::atomic<uint32_t> s_dropped{0};
uint8_t s_ownAddressType = BLE_OWN_ADDR_PUBLIC;
int s_procedureStatus = 0;
int s_connectStatus = 0;
uint16_t s_writeHandle = 0;
bool s_writeWithoutResponse = false;
Discovery s_found;

const ble_uuid16_t kLockServiceUuid = BLE_UUID16_INIT(kLockService);
const ble_uuid16_t kBatteryLevelUuid = BLE_UUID16_INIT(kBatteryLevel);

void post(const Message& message) {
    if (xQueueSend(s_inbox, &message, 0) != pdTRUE) {
        s_dropped.fetch_add(1);
    }
}

bool looksLikeLock(const uint8_t* data, size_t length) {
    latchkey_util::AdField field;
    if (!latchkey_util::findAdField(data, length, latchkey_util::kAdTypeManufacturer, field) ||
        field.size < kMinLockManufacturerData) {
        return false;
    }
    const bool v3 = field.data[0] == kV3ProtocolType && field.data[1] == kV3ProtocolVersion;
    return v3 || latchkey_util::hasUuid16(data, length, kLockService);
}

int onScanEvent(struct ble_gap_event* event, void*) {
    if (event->type == BLE_GAP_EVENT_DISC_COMPLETE) {
        s_scan = ScanMode::Off;
        return 0;
    }
    if (event->type != BLE_GAP_EVENT_DISC) {
        return 0;
    }
    s_reports.fetch_add(1);
    if (!looksLikeLock(event->disc.data, event->disc.length_data)) {
        return 0;
    }
    Message message{};
    message.kind = Message::Kind::Advert;
    message.advert.address.type = event->disc.addr.type;
    std::memcpy(message.advert.address.value, event->disc.addr.val, sizeof(message.advert.address.value));
    message.advert.rssi = event->disc.rssi;
    message.advert.eventType = event->disc.event_type;
    message.advert.length = static_cast<uint8_t>(std::min<size_t>(event->disc.length_data, kAdvertMax));
    std::memcpy(message.advert.data, event->disc.data, message.advert.length);
    post(message);
    return 0;
}

void dropLink(int reason) {
    s_connection = BLE_HS_CONN_HANDLE_NONE;
    s_notifyHandle = 0;
    Message message{};
    message.kind = Message::Kind::Disconnected;
    message.link = s_link;
    message.reason = reason;
    post(message);
    xSemaphoreGive(s_disconnectDone);
}

int onLinkEvent(struct ble_gap_event* event, void*) {
    switch (event->type) {
        case BLE_GAP_EVENT_CONNECT:
            s_connectStatus = event->connect.status;
            if (event->connect.status == 0) {
                s_connection = event->connect.conn_handle;
            }
            xSemaphoreGive(s_connectDone);
            return 0;
        case BLE_GAP_EVENT_DISCONNECT:
            dropLink(event->disconnect.reason);
            return 0;
        case BLE_GAP_EVENT_NOTIFY_RX: {
            if (event->notify_rx.attr_handle != s_notifyHandle) {
                return 0;
            }
            Message message{};
            message.kind = Message::Kind::Notification;
            message.link = s_link;
            const uint16_t length = OS_MBUF_PKTLEN(event->notify_rx.om);
            message.notification.length = static_cast<uint16_t>(std::min<size_t>(length, kNotificationMax));
            if (length > kNotificationMax) {
                s_dropped.fetch_add(1);
            }
            os_mbuf_copydata(event->notify_rx.om, 0, message.notification.length, message.notification.data);
            post(message);
            return 0;
        }
        default:
            return 0;
    }
}

void* beginProcedure() {
    xSemaphoreTake(s_procedureDone, 0);
    return reinterpret_cast<void*>(static_cast<uintptr_t>(s_procedure.fetch_add(1) + 1));
}

bool isCurrent(void* procedure) { return reinterpret_cast<uintptr_t>(procedure) == s_procedure; }

void endProcedure(void* procedure, int status) {
    if (!isCurrent(procedure)) {
        return;
    }
    s_procedureStatus = status;
    xSemaphoreGive(s_procedureDone);
}

int awaitProcedure(int started, uint32_t timeoutMs) {
    if (started != 0) {
        return started;
    }
    if (xSemaphoreTake(s_procedureDone, pdMS_TO_TICKS(timeoutMs)) != pdTRUE) {
        s_procedure.fetch_add(1);
        return BLE_HS_ETIMEOUT;
    }
    return s_procedureStatus;
}

int doneStatus(const struct ble_gatt_error* error) { return error->status == BLE_HS_EDONE ? 0 : error->status; }

uint16_t uuid16(const ble_uuid_any_t& uuid) { return uuid.u.type == BLE_UUID_TYPE_16 ? ble_uuid_u16(&uuid.u) : 0; }

int onMtu(uint16_t, const struct ble_gatt_error* error, uint16_t, void* procedure) {
    endProcedure(procedure, error->status);
    return 0;
}

int onService(uint16_t, const struct ble_gatt_error* error, const struct ble_gatt_svc* service, void* procedure) {
    if (error->status == 0 && service != nullptr) {
        if (isCurrent(procedure) && s_found.serviceStart == 0) {
            s_found.serviceStart = service->start_handle;
            s_found.serviceEnd = service->end_handle;
        }
        return 0;
    }
    endProcedure(procedure, doneStatus(error));
    return 0;
}

int onCharacteristic(uint16_t, const struct ble_gatt_error* error, const struct ble_gatt_chr* chr, void* procedure) {
    if (error->status == 0 && chr != nullptr) {
        if (!isCurrent(procedure)) {
            return 0;
        }
        if (s_found.notifyHandle != 0 && s_found.notifyEnd == 0) {
            s_found.notifyEnd = static_cast<uint16_t>(chr->def_handle - 1);
        }
        const uint16_t uuid = uuid16(chr->uuid);
        if (uuid == kWriteCharacteristic) {
            s_found.writeHandle = chr->val_handle;
            s_found.writeProperties = chr->properties;
        } else if (uuid == kNotifyCharacteristic) {
            s_found.notifyHandle = chr->val_handle;
            s_found.notifyEnd = 0;
        }
        return 0;
    }
    endProcedure(procedure, doneStatus(error));
    return 0;
}

int onDescriptor(uint16_t, const struct ble_gatt_error* error, uint16_t, const struct ble_gatt_dsc* descriptor,
                 void* procedure) {
    if (error->status == 0 && descriptor != nullptr) {
        if (isCurrent(procedure) && s_found.cccd == 0 && uuid16(descriptor->uuid) == BLE_GATT_DSC_CLT_CFG_UUID16) {
            s_found.cccd = descriptor->handle;
        }
        return 0;
    }
    endProcedure(procedure, doneStatus(error));
    return 0;
}

int onWritten(uint16_t, const struct ble_gatt_error* error, struct ble_gatt_attr*, void* procedure) {
    endProcedure(procedure, error->status);
    return 0;
}

int onBatteryRead(uint16_t, const struct ble_gatt_error* error, struct ble_gatt_attr* attr, void* procedure) {
    if (error->status == 0 && attr != nullptr) {
        return 0;
    }
    endProcedure(procedure, doneStatus(error));
    return 0;
}

int discover(uint16_t connection, LinkInfo& info) {
    s_found = Discovery{};
    void* procedure = beginProcedure();
    int rc = awaitProcedure(ble_gattc_exchange_mtu(connection, onMtu, procedure), kProcedureTimeoutMs);
    if (rc != 0) {
        ESP_LOGW(TAG, "MTU exchange failed: %d", rc);
    }
    procedure = beginProcedure();
    rc = awaitProcedure(ble_gattc_disc_svc_by_uuid(connection, &kLockServiceUuid.u, onService, procedure),
                        kProcedureTimeoutMs);
    if (rc != 0 || s_found.serviceStart == 0) {
        ESP_LOGW(TAG, "no lock service: %d", rc);
        return rc != 0 ? rc : BLE_HS_ENOENT;
    }
    procedure = beginProcedure();
    rc = awaitProcedure(
        ble_gattc_disc_all_chrs(connection, s_found.serviceStart, s_found.serviceEnd, onCharacteristic, procedure),
        kProcedureTimeoutMs);
    if (rc != 0 || s_found.writeHandle == 0 || s_found.notifyHandle == 0) {
        ESP_LOGW(TAG, "lock characteristics missing: %d", rc);
        return rc != 0 ? rc : BLE_HS_ENOENT;
    }
    const uint16_t notifyEnd = s_found.notifyEnd != 0 ? s_found.notifyEnd : s_found.serviceEnd;
    procedure = beginProcedure();
    rc = awaitProcedure(ble_gattc_disc_all_dscs(connection, s_found.notifyHandle, notifyEnd, onDescriptor, procedure),
                        kProcedureTimeoutMs);
    if (rc != 0 || s_found.cccd == 0) {
        ESP_LOGW(TAG, "no notification descriptor: %d", rc);
        return rc != 0 ? rc : BLE_HS_ENOENT;
    }
    s_notifyHandle = s_found.notifyHandle;
    procedure = beginProcedure();
    rc = awaitProcedure(ble_gattc_write_flat(connection, s_found.cccd, kEnableNotifications,
                                             sizeof(kEnableNotifications), onWritten, procedure),
                        kProcedureTimeoutMs);
    if (rc != 0) {
        ESP_LOGW(TAG, "subscribe failed: %d", rc);
        return rc;
    }
    vTaskDelay(pdMS_TO_TICKS(kSettleMs));
    procedure = beginProcedure();
    rc = awaitProcedure(ble_gattc_read_by_uuid(connection, 1, 0xFFFF, &kBatteryLevelUuid.u, onBatteryRead, procedure),
                        kProcedureTimeoutMs);
    ESP_LOGD(TAG, "battery level read: %d", rc);
    s_writeHandle = s_found.writeHandle;
    s_writeWithoutResponse = (s_found.writeProperties & BLE_GATT_CHR_PROP_WRITE_NO_RSP) != 0;
    info.mtu = ble_att_mtu(connection);
    info.writeProperties = s_found.writeProperties;
    info.writeWithoutResponse = s_writeWithoutResponse;
    return 0;
}

int writeChunk(const uint8_t* data, size_t length) {
    const uint16_t connection = s_connection;
    if (connection == BLE_HS_CONN_HANDLE_NONE) {
        return BLE_HS_ENOTCONN;
    }
    if (s_writeWithoutResponse) {
        for (int attempt = 0;; ++attempt) {
            const int rc = ble_gattc_write_no_rsp_flat(connection, s_writeHandle, data, static_cast<uint16_t>(length));
            if (rc != BLE_HS_ENOMEM || attempt >= kNoResponseRetries) {
                return rc;
            }
            vTaskDelay(kNoResponseRetryDelay);
        }
    }
    void* procedure = beginProcedure();
    return awaitProcedure(
        ble_gattc_write_flat(connection, s_writeHandle, data, static_cast<uint16_t>(length), onWritten, procedure),
        kWriteTimeoutMs);
}

void dropStaleLinkMessages() {
    Message message{};
    const UBaseType_t waiting = uxQueueMessagesWaiting(s_inbox);
    for (UBaseType_t i = 0; i < waiting && xQueueReceive(s_inbox, &message, 0) == pdTRUE; ++i) {
        if (message.kind == Message::Kind::Advert || message.kind == Message::Kind::Wake) {
            post(message);
        }
    }
}

void onSync() {
    int rc = ble_hs_util_ensure_addr(0);
    if (rc == 0) {
        rc = ble_hs_id_infer_auto(0, &s_ownAddressType);
    }
    if (rc != 0) {
        ESP_LOGE(TAG, "no usable Bluetooth address: %d", rc);
        return;
    }
    s_scan = ScanMode::Off;
    s_ready = true;
    wake();
}

void onReset(int reason) {
    s_ready = false;
    s_scan = ScanMode::Off;
    if (s_connection != BLE_HS_CONN_HANDLE_NONE) {
        dropLink(reason);
    }
    ESP_LOGW(TAG, "host reset, reason %d", reason);
}

void hostTask(void*) {
    nimble_port_run();
    nimble_port_freertos_deinit();
}

void noteFrame(const ttlock::Bytes& frame, uint8_t command) {
    s_frames.fetch_add(1);
    const bool crcOk = frame.size() > 1 && ttlock::crc8(frame.data(), frame.size() - 1) == frame.back();
    if (!crcOk) {
        s_badCrc.fetch_add(1);
        ESP_LOGW(TAG, "reply to 0x%02x failed its CRC (%u bytes)", command, static_cast<unsigned>(frame.size()));
    }
    ESP_LOGD(TAG, "rx after 0x%02x: %u bytes, %u encrypted, crc %s", command, static_cast<unsigned>(frame.size()),
             frame.size() > kLengthIndex ? frame[kLengthIndex] : 0, crcOk ? "ok" : "bad");
}

}

const char* addressTypeName(uint8_t type) {
    switch (type) {
        case BLE_ADDR_PUBLIC:
            return "public";
        case BLE_ADDR_RANDOM:
            return "random";
        case BLE_ADDR_PUBLIC_ID:
            return "public identity";
        case BLE_ADDR_RANDOM_ID:
            return "random identity";
        default:
            return "unknown";
    }
}

bool isConnectable(const Advert& advert) {
    return advert.eventType == BLE_HCI_ADV_RPT_EVTYPE_ADV_IND || advert.eventType == BLE_HCI_ADV_RPT_EVTYPE_DIR_IND;
}

void init() {
    s_inbox = xQueueCreateStatic(kInboxDepth, sizeof(Message), s_inboxStorage, &s_inboxBuffer);
    s_procedureDone = xSemaphoreCreateBinaryStatic(&s_procedureBuffer);
    s_connectDone = xSemaphoreCreateBinaryStatic(&s_connectBuffer);
    s_disconnectDone = xSemaphoreCreateBinaryStatic(&s_disconnectBuffer);
    ESP_ERROR_CHECK(nimble_port_init());
    ble_hs_cfg.sync_cb = onSync;
    ble_hs_cfg.reset_cb = onReset;
    nimble_port_freertos_init(hostTask);
}

bool ready() { return s_ready; }

bool receive(Message& out, uint32_t timeoutMs) { return xQueueReceive(s_inbox, &out, pdMS_TO_TICKS(timeoutMs)) == pdTRUE; }

void wake() {
    Message message{};
    message.kind = Message::Kind::Wake;
    xQueueSend(s_inbox, &message, 0);
}

int scan(ScanMode mode) {
    if (!s_ready) {
        return BLE_HS_ENOTSYNCED;
    }
    if (mode == s_scan && (mode == ScanMode::Off || ble_gap_disc_active())) {
        return 0;
    }
    if (ble_gap_disc_active()) {
        const int rc = ble_gap_disc_cancel();
        if (rc != 0 && rc != BLE_HS_EALREADY) {
            return rc;
        }
    }
    s_scan = ScanMode::Off;
    if (mode == ScanMode::Off) {
        return 0;
    }
    struct ble_gap_disc_params params{};
    params.passive = 1;
    params.filter_duplicates = 0;
    params.filter_policy = 0;
    params.limited = 0;
    const bool fast = mode == ScanMode::Fast;
    params.itvl = BLE_GAP_SCAN_ITVL_MS(fast ? kFastIntervalMs : kBackgroundIntervalMs);
    params.window = BLE_GAP_SCAN_WIN_MS(fast ? kFastWindowMs : kBackgroundWindowMs);
    const int rc = ble_gap_disc(s_ownAddressType, BLE_HS_FOREVER, &params, onScanEvent, nullptr);
    if (rc == 0) {
        s_scan = mode;
    }
    return rc;
}

ScanMode scanMode() { return s_scan; }

int connect(const Address& address, uint32_t timeoutMs, LinkInfo& info) {
    if (!s_ready) {
        return BLE_HS_ENOTSYNCED;
    }
    const int stopped = scan(ScanMode::Off);
    if (stopped != 0) {
        return stopped;
    }
    xSemaphoreTake(s_connectDone, 0);
    xSemaphoreTake(s_disconnectDone, 0);
    s_link.fetch_add(1);
    dropStaleLinkMessages();
    ble_addr_t peer{};
    peer.type = address.type;
    std::memcpy(peer.val, address.value, sizeof(peer.val));
    s_connectStatus = 0;
    int rc = BLE_HS_EBUSY;
    for (int attempt = 0; rc == BLE_HS_EBUSY && attempt < kBusyRetries; ++attempt) {
        if (attempt > 0) {
            vTaskDelay(kBusyRetryDelay);
        }
        rc = ble_gap_connect(s_ownAddressType, &peer, static_cast<int32_t>(timeoutMs), nullptr, onLinkEvent, nullptr);
    }
    if (rc != 0) {
        return rc;
    }
    if (xSemaphoreTake(s_connectDone, pdMS_TO_TICKS(timeoutMs + kConnectGraceMs)) != pdTRUE) {
        ble_gap_conn_cancel();
        return BLE_HS_ETIMEOUT;
    }
    if (s_connectStatus != 0) {
        return s_connectStatus;
    }
    const uint16_t connection = s_connection;
    const int discovered = discover(connection, info);
    if (discovered != 0) {
        disconnect();
        return discovered;
    }
    ESP_LOGI(TAG, "link to %s (%s address): mtu %u, write characteristic properties 0x%02x, writes %s",
             latchkey_util::formatBleAddress(address.value).c_str(), addressTypeName(address.type), info.mtu,
             info.writeProperties, info.writeWithoutResponse ? "without response" : "with response");
    return 0;
}

void disconnect() {
    const uint16_t connection = s_connection;
    if (connection == BLE_HS_CONN_HANDLE_NONE) {
        return;
    }
    xSemaphoreTake(s_disconnectDone, 0);
    const int rc = ble_gap_terminate(connection, BLE_ERR_REM_USER_CONN_TERM);
    if (rc == BLE_HS_ENOTCONN) {
        s_connection = BLE_HS_CONN_HANDLE_NONE;
        return;
    }
    if (rc != 0) {
        ESP_LOGW(TAG, "terminate failed: %d", rc);
        return;
    }
    if (xSemaphoreTake(s_disconnectDone, pdMS_TO_TICKS(kDisconnectTimeoutMs)) != pdTRUE) {
        ESP_LOGW(TAG, "no disconnect event within %u ms", static_cast<unsigned>(kDisconnectTimeoutMs));
    }
}

bool connected() { return s_connection != BLE_HS_CONN_HANDLE_NONE; }

Stats stats() {
    Stats result;
    result.ready = s_ready;
    result.connected = connected();
    result.scan = s_scan;
    result.reports = s_reports;
    result.frames = s_frames;
    result.badCrc = s_badCrc;
    result.dropped = s_dropped;
    return result;
}

LinkTransport::LinkTransport(AdvertSink sink) : sink_(std::move(sink)) {}

void LinkTransport::reset() {
    reassembler_.reset();
    lastCommand_ = 0;
}

ttlock::Status LinkTransport::send(const ttlock::Bytes& wireFrameWithCrlf) {
    if (!connected()) {
        return ttlock::Status::Disconnected;
    }
    lastCommand_ = wireFrameWithCrlf.size() > kCommandIndex ? wireFrameWithCrlf[kCommandIndex] : 0;
    ESP_LOGD(TAG, "tx 0x%02x: %u bytes", lastCommand_, static_cast<unsigned>(wireFrameWithCrlf.size()));
    for (const ttlock::Bytes& piece : ttlock::chunk(wireFrameWithCrlf, kChunk)) {
        const int rc = writeChunk(piece.data(), piece.size());
        if (rc != 0) {
            ESP_LOGW(TAG, "write of 0x%02x failed: %d", lastCommand_, rc);
            return rc == BLE_HS_ETIMEOUT ? ttlock::Status::Timeout : ttlock::Status::Disconnected;
        }
    }
    return ttlock::Status::Ok;
}

ttlock::Status LinkTransport::receive(ttlock::Bytes& frameWithoutCrlf, uint32_t timeoutMs) {
    const TickType_t started = xTaskGetTickCount();
    const TickType_t budget = pdMS_TO_TICKS(timeoutMs);
    while (true) {
        const TickType_t elapsed = xTaskGetTickCount() - started;
        if (elapsed >= budget) {
            return ttlock::Status::Timeout;
        }
        Message message{};
        const TickType_t slice = std::min<TickType_t>(budget - elapsed, pdMS_TO_TICKS(kReceiveSliceMs));
        if (xQueueReceive(s_inbox, &message, slice) != pdTRUE) {
            if (!connected()) {
                return ttlock::Status::Disconnected;
            }
            continue;
        }
        switch (message.kind) {
            case Message::Kind::Advert:
                if (sink_) {
                    sink_(message.advert);
                }
                break;
            case Message::Kind::Disconnected:
                if (message.link == s_link) {
                    return ttlock::Status::Disconnected;
                }
                break;
            case Message::Kind::Notification:
                if (message.link != s_link) {
                    break;
                }
                if (reassembler_.feed(message.notification.data, message.notification.length, frameWithoutCrlf)) {
                    noteFrame(frameWithoutCrlf, lastCommand_);
                    return ttlock::Status::Ok;
                }
                if (reassembler_.status() != ttlock::Status::Ok) {
                    ESP_LOGW(TAG, "reply to 0x%02x overflowed the frame buffer", lastCommand_);
                    return reassembler_.status();
                }
                break;
            case Message::Kind::Wake:
                break;
        }
    }
}

}
