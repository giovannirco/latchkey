// SPDX-License-Identifier: GPL-3.0-or-later
#pragma once

#include <atomic>
#include <chrono>
#include <functional>
#include <thread>

#define LATCHKEY_TRACK_SCALAR_ALLOCATIONS
#include "rpc_test_runtime.h"
#include "key_store_test_runtime.h"
#include "../../src/lock_manager.cpp"
#include "../../src/lock_log.cpp"
#include "../../src/access_requests.cpp"

inline std::atomic<int64_t> managerTime{0};
inline std::atomic<bool> managerBusy{false};
inline ttlock::Transport* fixtureTransport = nullptr;
inline bool fixtureConnected = false;
inline bool bluetoothReady = false;
inline size_t bluetoothCalls = 0;
inline std::function<bool(ble::Message&)> receiveAdvert;
inline ble::ScanMode bluetoothScan = ble::ScanMode::Off;

int64_t esp_timer_get_time() { return managerTime; }
void vTaskDelay(TickType_t ticks) { managerTime += 1000LL * ticks; }
uint32_t uxTaskGetStackHighWaterMark(TaskHandle_t) { return 2048; }
BaseType_t xTaskCreatePinnedToCore(void (*)(void*), const char*, uint32_t, void*, UBaseType_t,
                                  TaskHandle_t* handle, BaseType_t) {
    *handle = reinterpret_cast<void*>(1);
    return pdPASS;
}

SemaphoreHandle_t xSemaphoreCreateBinaryStatic(StaticSemaphore_t* storage) { return storage; }
BaseType_t xSemaphoreGive(SemaphoreHandle_t semaphore) {
    std::lock_guard<std::mutex> guard(semaphore->mutex);
    semaphore->given = true;
    semaphore->changed.notify_all();
    return pdTRUE;
}
BaseType_t xSemaphoreTake(SemaphoreHandle_t semaphore, TickType_t ticks) {
    std::unique_lock<std::mutex> guard(semaphore->mutex);
    return semaphore->changed.wait_for(guard, std::chrono::milliseconds(ticks),
                                       [&] { return semaphore->given; }) ? pdTRUE : 0;
}

size_t heap_caps_get_free_size(uint32_t) { return 1024 * 1024; }
size_t heap_caps_get_largest_free_block(uint32_t) { return 1024 * 1024; }

namespace wallclock {
int32_t utcOffsetSeconds() { return 0; }
int32_t utcOffsetAt(int64_t) { return 0; }
}

namespace ble {
const char* addressTypeName(uint8_t) { return "fixture"; }
bool isConnectable(const Advert&) { return true; }
bool ready() { return bluetoothReady; }
bool connected() { return fixtureConnected; }
void disconnect() { ++bluetoothCalls; fixtureConnected = false; }
int scan(ScanMode mode) { ++bluetoothCalls; bluetoothScan = mode; return 0; }
ScanMode scanMode() { return bluetoothScan; }
int connect(const Address&, uint32_t, LinkInfo&) { ++bluetoothCalls; fixtureConnected = fixtureTransport != nullptr; return fixtureConnected ? 0 : 1; }
bool receive(Message& message, uint32_t timeout) {
    ++bluetoothCalls;
    if (receiveAdvert && receiveAdvert(message)) return true;
    managerTime += 1000LL * timeout;
    return false;
}
void wake() {
    if (managerBusy.exchange(true)) return;
    while (auto* job = lock_manager::nextJob()) lock_manager::run(*job);
    managerBusy = false;
}
LinkTransport::LinkTransport(AdvertSink sink) : sink_(std::move(sink)) {}
void LinkTransport::reset() {}
ttlock::Status LinkTransport::send(const ttlock::Bytes& bytes) { ++bluetoothCalls; return fixtureTransport ? fixtureTransport->send(bytes) : ttlock::Status::Timeout; }
ttlock::Status LinkTransport::receive(ttlock::Bytes& bytes, uint32_t timeout) {
    ++bluetoothCalls;
    return fixtureTransport ? fixtureTransport->receive(bytes, timeout) : ttlock::Status::Timeout;
}
}

static std::string storedKey(std::string_view mac) {
    std::string key;
    for (char value : mac) if (value != ':') key += value;
    return key;
}

static esp_err_t eraseFixtureNamespace(const char* name) {
    return mutate([&] { s_namespaces[name].clear(); });
}

static esp_err_t eraseFixtureIdentity(const char* name, const char* mac) {
    return mutate([&] { s_namespaces[name].erase(storedKey(mac)); });
}

namespace store::locks {
esp_err_t list(std::vector<Record>& out) {
    for (const auto& [key, value] : s_namespaces["locks"]) {
        if (value.type != NVS_TYPE_BLOB || value.bytes.size() != sizeof(Record)) continue;
        Record record;
        std::memcpy(&record, value.bytes.data(), sizeof(record));
        out.push_back(record);
    }
    return ESP_OK;
}
esp_err_t count(size_t& out) { out = s_namespaces["locks"].size(); return ESP_OK; }
esp_err_t save(const Record& record) {
    return mutate([&] {
        const auto* bytes = reinterpret_cast<const uint8_t*>(&record);
        s_namespaces["locks"][storedKey(record.mac)] = {NVS_TYPE_BLOB, {bytes, bytes + sizeof(record)}};
    });
}
esp_err_t erase(const char* mac) { return eraseFixtureIdentity("locks", mac); }
esp_err_t eraseAll() { return eraseFixtureNamespace("locks"); }
}

namespace store::labels {
esp_err_t load(const char* mac, Kind kind, latchkey_util::LabelTable& out) {
    const std::string key = storedKey(mac) + static_cast<char>(kind);
    size_t length = 0;
    auto error = key_store::readBlob("labels", key.c_str(), nullptr, length);
    if (error == ESP_ERR_NVS_NOT_FOUND) { out = {}; return ESP_OK; }
    if (error != ESP_OK) return error;
    std::vector<uint8_t> bytes(length);
    error = key_store::readBlob("labels", key.c_str(), bytes.data(), length);
    if (error != ESP_OK) return error;
    return latchkey_util::LabelTable::decode(bytes.data(), length, out) ? ESP_OK : ESP_ERR_INVALID_CRC;
}
esp_err_t save(const char*, Kind, const latchkey_util::LabelTable&) { return mutate([] {}); }
bool fits(const char*, Kind, const latchkey_util::LabelTable&) { return true; }
esp_err_t erase(const char* mac) {
    return mutate([&] { for (char kind : {'p', 'f', 'c'}) s_namespaces["labels"].erase(storedKey(mac) + kind); });
}
esp_err_t eraseAll() { return eraseFixtureNamespace("labels"); }
}

namespace store::seeds {
esp_err_t save(const char*, const latchkey_util::SeedTable&) { return mutate([] {}); }
esp_err_t erase(const char* mac) { return eraseFixtureIdentity("seeds", mac); }
esp_err_t eraseAll() { return eraseFixtureNamespace("seeds"); }
}

namespace store::watch {
esp_err_t load(const char*, latchkey_util::WatchState& out) { out = {}; return ESP_OK; }
esp_err_t save(const char*, const latchkey_util::WatchState&) { return mutate([] {}); }
esp_err_t erase(const char* mac) { return eraseFixtureIdentity("watch", mac); }
esp_err_t eraseAll() { return eraseFixtureNamespace("watch"); }
}

namespace store::alerts {
esp_err_t load(const char*, latchkey_util::LockAlerts& out) { out = {}; return ESP_OK; }
esp_err_t save(const char*, const latchkey_util::LockAlerts&) { return mutate([] {}); }
esp_err_t erase(const char* mac) { return eraseFixtureIdentity("alerts", mac); }
esp_err_t eraseAll() { return eraseFixtureNamespace("alerts"); }
}

void resetManagerFixture() {
    resetRpcFixture();
    resetNvsFixture();
    lock_manager::s_link = {};
    fixtureTransport = nullptr;
    fixtureConnected = false;
    lock_manager::s_locks = {};
    lock_manager::s_lockCount = 0;
    lock_manager::s_restore = key_store::Restore{};
    lock_manager::s_queue = latchkey_util::JobQueue<lock_manager::Job*>();
    lock_manager::s_erased = false;
    managerTime = 0;
    managerBusy = false;
    bluetoothReady = false;
    bluetoothCalls = 0;
    bluetoothScan = ble::ScanMode::Off;
    receiveAdvert = {};
}

void clearManagerFixture() {
    clearRpcFixture();
    clearNvsFixture();
    lock_manager::s_locks = {};
    lock_manager::s_lockCount = 0;
}
