// SPDX-License-Identifier: GPL-3.0-or-later
#define LOG_LOCAL_LEVEL ESP_LOG_DEBUG

#include "lock_manager.h"

#include <algorithm>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <functional>
#include <memory>
#include <mutex>
#include <set>
#include <string_view>
#include <utility>
#include <vector>

#include "esp_log.h"
#include "esp_random.h"
#include "esp_timer.h"
#include "freertos/FreeRTOS.h"
#include "freertos/semphr.h"
#include "freertos/task.h"

#include "ble_central.h"
#include "clock.h"
#include "events.h"
#include "latchkey_util/ble_adv.h"
#include "latchkey_util/job_queue.h"
#include "store.h"
#include "ttlock/advert.h"
#include "ttlock/errors.h"
#include "ttlock/features.h"
#include "ttlock/session.h"
#include "ttlock/types.h"

namespace lock_manager {

namespace {

using store::locks::Record;
using ttlock::LockState;
using ttlock::Status;

constexpr const char* TAG = "locks";
constexpr uint32_t kWorkerStack = 8192;
constexpr UBaseType_t kWorkerPriority = 5;
constexpr BaseType_t kWorkerCore = portNUM_PROCESSORS > 1 ? 1 : 0;
constexpr uint32_t kIdleSliceMs = 1000;
constexpr uint32_t kEventSliceMs = 500;
constexpr uint32_t kSubmitSliceMs = 1000;
constexpr uint32_t kUserKeepAliveMs = 25000;
constexpr uint32_t kLingerMs = 3000;
constexpr uint32_t kConnectTimeoutMs = 10000;
constexpr int kConnectAttempts = 3;
constexpr uint32_t kConnectRetryMs = 2000;
constexpr uint32_t kScanRetryMs = 500;
constexpr TickType_t kNotReadyDelay = pdMS_TO_TICKS(100);
constexpr ttlock::LockVersion kV3Frames{5, 3, 1, 1, 1};

enum class Kind : uint8_t {
    Scan,
    Pair,
    Status,
    Info,
    Features,
    Unlock,
    Lock,
    TimeSync,
    FactoryReset,
};

struct Job {
    Kind kind = Kind::Status;
    std::string mac;
    std::string name;
    uint32_t seconds = 0;
    rpc::Reply reply;
    StaticSemaphore_t doneBuffer{};
    SemaphoreHandle_t done = nullptr;
};

struct Live {
    LockState state = LockState::Unknown;
    int battery = -1;
    bool hasRssi = false;
    int rssi = 0;
    int64_t lastSeen = 0;
    bool hasEvent = false;
    std::string eventAction;
    std::string eventMethod;
    int64_t eventTime = 0;
    bool timeSyncTried = false;
    bool warnedUnpaired = false;
};

struct Lock {
    Record record;
    Live live;
};

struct Link {
    bool open = false;
    std::string mac;
    std::unique_ptr<ttlock::Session> session;
    uint32_t keepUntilMs = 0;
};

class WallClock final : public ttlock::Clock {
public:
    bool synced() override { return wallclock::synced(); }

    int64_t utcSeconds() override { return wallclock::utcSeconds(); }

    int32_t utcOffsetSeconds() override { return 0; }
};

class HardwareRandom final : public ttlock::Random {
public:
    void fill(uint8_t* data, size_t len) override { esp_fill_random(data, len); }
};

void track(const ble::Advert& raw);

std::mutex s_mutex;
std::vector<Lock> s_locks;
latchkey_util::JobQueue<Job*> s_queue;
bool s_erased = false;
TaskHandle_t s_worker = nullptr;
WallClock s_clock;
HardwareRandom s_random;
ble::LinkTransport s_transport([](const ble::Advert& advert) { track(advert); });
Link s_link;

uint32_t nowMs() { return static_cast<uint32_t>(esp_timer_get_time() / 1000); }

int64_t utcNow() { return wallclock::synced() ? wallclock::utcSeconds() : 0; }

const char* kindName(Kind kind) {
    switch (kind) {
        case Kind::Scan:
            return "locks.scan";
        case Kind::Pair:
            return "locks.pair";
        case Kind::Status:
            return "lock.status";
        case Kind::Info:
            return "lock.info";
        case Kind::Features:
            return "lock.features";
        case Kind::Unlock:
            return "lock.unlock";
        case Kind::Lock:
            return "lock.lock";
        case Kind::TimeSync:
            return "lock.time.sync";
        case Kind::FactoryReset:
            return "lock.factoryReset";
    }
    return "job";
}

const char* stateName(LockState state) {
    switch (state) {
        case LockState::Locked:
            return "locked";
        case LockState::Unlocked:
            return "unlocked";
        case LockState::Unknown:
            break;
    }
    return "unknown";
}

Record blankRecord() {
    Record record;
    std::memset(static_cast<void*>(&record), 0, sizeof(record));
    record.version = store::locks::kRecordVersion;
    return record;
}

template <size_t N>
void copyText(char (&field)[N], std::string_view text) {
    const size_t length = std::min(text.size(), N - 1);
    std::memcpy(field, text.data(), length);
    std::memset(field + length, 0, N - length);
}

ttlock::LockKeys keysOf(const Record& record) {
    ttlock::LockKeys keys;
    keys.mac = record.mac;
    keys.version =
        ttlock::LockVersion{record.protocolType, record.protocolVersion, record.scene, record.groupId, record.orgId};
    std::memcpy(keys.aesKey.data(), record.aesKey, keys.aesKey.size());
    keys.adminPs = record.adminPs;
    keys.unlockKey = record.unlockKey;
    keys.lockFlagPos = record.lockFlagPos;
    keys.features = record.features;
    keys.adminPasscode = record.adminPasscode;
    return keys;
}

void storeKeys(Record& record, const ttlock::LockKeys& keys) {
    record.protocolType = keys.version.protocolType;
    record.protocolVersion = keys.version.protocolVersion;
    record.scene = keys.version.scene;
    record.groupId = keys.version.groupId;
    record.orgId = keys.version.orgId;
    std::memcpy(record.aesKey, keys.aesKey.data(), sizeof(record.aesKey));
    record.adminPs = keys.adminPs;
    record.unlockKey = keys.unlockKey;
    record.lockFlagPos = keys.lockFlagPos;
    record.features = keys.features;
    copyText(record.adminPasscode, keys.adminPasscode);
}

void copyDeviceInfo(Record& record, const ttlock::DeviceInfo& info) {
    copyText(record.model, info.model);
    copyText(record.hardware, info.hardware);
    copyText(record.firmware, info.firmware);
    copyText(record.manufactureDate, info.manufactureDate);
}

ble::Address addressOf(const Record& record) {
    ble::Address address{};
    address.type = record.addressType;
    std::memcpy(address.value, record.address, sizeof(address.value));
    return address;
}

Lock* findLocked(std::string_view mac) {
    for (Lock& lock : s_locks) {
        if (mac == lock.record.mac) {
            return &lock;
        }
    }
    return nullptr;
}

bool snapshot(std::string_view mac, Lock& out) {
    std::lock_guard<std::mutex> guard(s_mutex);
    const Lock* lock = findLocked(mac);
    if (lock == nullptr) {
        return false;
    }
    out = *lock;
    return true;
}

bool exists(std::string_view mac) {
    std::lock_guard<std::mutex> guard(s_mutex);
    return findLocked(mac) != nullptr;
}

esp_err_t persist(const Record& record) {
    std::lock_guard<std::mutex> guard(s_mutex);
    if (s_erased) {
        return ESP_ERR_INVALID_STATE;
    }
    Lock* existing = findLocked(record.mac);
    if (existing == nullptr) {
        if (s_locks.size() >= store::locks::kMaxLocks) {
            return ESP_ERR_NO_MEM;
        }
        s_locks.push_back(Lock{record, Live{}});
    } else {
        existing->record = record;
    }
    return store::locks::save(record);
}

bool updateRecord(std::string_view mac, const std::function<void(Record&)>& change) {
    std::lock_guard<std::mutex> guard(s_mutex);
    Lock* lock = findLocked(mac);
    if (lock == nullptr || s_erased) {
        return false;
    }
    change(lock->record);
    const esp_err_t error = store::locks::save(lock->record);
    if (error != ESP_OK) {
        ESP_LOGE(TAG, "cannot store the lock record: %s", esp_err_to_name(error));
        return false;
    }
    return true;
}

esp_err_t removeRecord(std::string_view mac) {
    std::lock_guard<std::mutex> guard(s_mutex);
    const std::string key(mac);
    const esp_err_t error = store::locks::erase(key.c_str());
    if (error != ESP_OK) {
        return error;
    }
    s_locks.erase(std::remove_if(s_locks.begin(), s_locks.end(),
                                 [&mac](const Lock& lock) { return mac == lock.record.mac; }),
                  s_locks.end());
    return ESP_OK;
}

void addOptionalNumber(cJSON* object, const char* key, bool present, double value) {
    if (present) {
        cJSON_AddNumberToObject(object, key, value);
    } else {
        cJSON_AddNullToObject(object, key);
    }
}

void addOptionalString(cJSON* object, const char* key, const char* value) {
    if (value != nullptr && value[0] != '\0') {
        cJSON_AddStringToObject(object, key, value);
    } else {
        cJSON_AddNullToObject(object, key);
    }
}

cJSON* summaryJson(const Lock& lock) {
    cJSON* json = cJSON_CreateObject();
    cJSON_AddStringToObject(json, "id", lock.record.mac);
    cJSON_AddStringToObject(json, "mac", lock.record.mac);
    cJSON_AddStringToObject(json, "name", lock.record.name);
    addOptionalString(json, "model", lock.record.model);
    cJSON_AddStringToObject(json, "state", stateName(lock.live.state));
    addOptionalNumber(json, "battery", lock.live.battery >= 0, lock.live.battery);
    addOptionalNumber(json, "rssi", lock.live.hasRssi, lock.live.rssi);
    addOptionalNumber(json, "lastSeen", lock.live.lastSeen > 0, static_cast<double>(lock.live.lastSeen));
    if (lock.live.hasEvent) {
        cJSON* event = cJSON_AddObjectToObject(json, "lastEvent");
        cJSON_AddStringToObject(event, "action", lock.live.eventAction.c_str());
        addOptionalString(event, "method", lock.live.eventMethod.c_str());
        cJSON_AddNumberToObject(event, "time", static_cast<double>(lock.live.eventTime));
    } else {
        cJSON_AddNullToObject(json, "lastEvent");
    }
    cJSON_AddBoolToObject(json, "hardened", false);
    cJSON_AddBoolToObject(json, "backedUp", false);
    return json;
}

cJSON* infoJson(const Record& record) {
    cJSON* json = cJSON_CreateObject();
    cJSON_AddStringToObject(json, "mac", record.mac);
    cJSON_AddStringToObject(json, "model", record.model);
    cJSON_AddStringToObject(json, "hardware", record.hardware);
    cJSON_AddStringToObject(json, "firmware", record.firmware);
    cJSON_AddStringToObject(json, "manufactureDate", record.manufactureDate);
    char protocol[8];
    std::snprintf(protocol, sizeof(protocol), "%u.%u", record.protocolVersion, record.scene);
    cJSON_AddStringToObject(json, "protocol", protocol);
    return json;
}

cJSON* featuresJson(uint64_t mask) {
    cJSON* json = cJSON_CreateObject();
    cJSON* names = cJSON_AddArrayToObject(json, "features");
    for (const ttlock::Feature feature : ttlock::kAllFeatures) {
        if (ttlock::hasFeature(mask, feature)) {
            cJSON_AddItemToArray(names, cJSON_CreateString(ttlock::toString(feature)));
        }
    }
    return json;
}

rpc::Reply notPaired() { return rpc::fail("not_paired", "the board has no keys for this lock"); }

rpc::Reply failure(Status status, uint8_t lockError) {
    switch (status) {
        case Status::Timeout:
            return rpc::fail("timeout", "the lock did not answer");
        case Status::Disconnected:
            return rpc::fail("disconnected", "the Bluetooth link to the lock dropped");
        case Status::BadResponse:
            return rpc::fail("bad_response", "the lock sent an answer the board could not read");
        case Status::BadCrc:
            return rpc::fail("bad_crc", "the lock sent a damaged answer");
        case Status::LockError: {
            const std::string message = std::string("the lock refused the command: ") + ttlock::lockErrorName(lockError);
            return rpc::fail("lock_error", message.c_str());
        }
        case Status::Unsupported:
            return rpc::fail("unsupported", "the lock does not support that");
        case Status::NotPaired:
            return notPaired();
        case Status::PairIncomplete:
            return rpc::fail("pair_incomplete", "pairing stopped before it finished; the keys received are stored");
        case Status::Busy:
            return rpc::fail("busy", "the lock is busy");
        case Status::InvalidArgument:
            return rpc::fail("invalid_argument", "the lock cannot take that value");
        case Status::TimeUnsynced:
            return rpc::fail("time_unsynced", "the board clock is not set yet");
        case Status::Ok:
            break;
    }
    return rpc::fail("internal", "unexpected lock status");
}

bool breaksLink(Status status) {
    return status == Status::Timeout || status == Status::Disconnected || status == Status::BadResponse ||
           status == Status::BadCrc;
}

void publishState(const std::string& mac, LockState state, int battery) {
    cJSON* data = cJSON_CreateObject();
    cJSON_AddStringToObject(data, "lock", mac.c_str());
    cJSON_AddStringToObject(data, "state", stateName(state));
    addOptionalNumber(data, "battery", battery >= 0, battery);
    events::publish("lock.state", data);
}

void noteState(const std::string& mac, LockState state, int battery, bool always) {
    LockState current = LockState::Unknown;
    int level = -1;
    bool changed = false;
    {
        std::lock_guard<std::mutex> guard(s_mutex);
        Lock* lock = findLocked(mac);
        if (lock == nullptr) {
            return;
        }
        if (state != LockState::Unknown && state != lock->live.state) {
            lock->live.state = state;
            changed = true;
        }
        if (battery >= 0 && battery != lock->live.battery) {
            lock->live.battery = battery;
            changed = true;
        }
        current = lock->live.state;
        level = lock->live.battery;
    }
    if (changed || always) {
        publishState(mac, current, level);
    }
}

void noteEvent(const std::string& mac, const char* action, const char* method) {
    const int64_t time = utcNow();
    {
        std::lock_guard<std::mutex> guard(s_mutex);
        Lock* lock = findLocked(mac);
        if (lock != nullptr) {
            lock->live.hasEvent = true;
            lock->live.eventAction = action;
            lock->live.eventMethod = method != nullptr ? method : "";
            lock->live.eventTime = time;
        }
    }
    cJSON* data = cJSON_CreateObject();
    cJSON_AddStringToObject(data, "lock", mac.c_str());
    cJSON_AddStringToObject(data, "action", action);
    if (method != nullptr) {
        cJSON_AddStringToObject(data, "method", method);
    }
    cJSON_AddNumberToObject(data, "time", static_cast<double>(time));
    events::publish("lock.event", data);
}

void onPush(const std::string& mac, const ttlock::LockEvent& event) {
    ESP_LOGD(TAG, "push 0x%02x status %u with %u data bytes", event.command, event.status,
             static_cast<unsigned>(event.data.size()));
    if (event.state != LockState::Unknown) {
        noteState(mac, event.state, event.battery, false);
        noteEvent(mac, event.state == LockState::Locked ? "lock" : "unlock", nullptr);
        return;
    }
    noteState(mac, LockState::Unknown, event.battery, false);
    cJSON* data = cJSON_CreateObject();
    cJSON_AddStringToObject(data, "lock", mac.c_str());
    cJSON_AddStringToObject(data, "action", "push");
    cJSON_AddNumberToObject(data, "command", event.command);
    if (event.battery >= 0) {
        cJSON_AddNumberToObject(data, "battery", event.battery);
    }
    if (event.hasRecord) {
        cJSON_AddNumberToObject(data, "record", event.recordId);
    }
    cJSON_AddNumberToObject(data, "time", static_cast<double>(utcNow()));
    events::publish("lock.event", data);
}

bool readAdvert(const ble::Advert& raw, ttlock::Advert& out, std::string* name) {
    latchkey_util::AdField field;
    if (!latchkey_util::findAdField(raw.data, raw.length, latchkey_util::kAdTypeManufacturer, field) ||
        !ttlock::parseAdvert(ttlock::Bytes(field.data, field.data + field.size), out)) {
        return false;
    }
    if (name != nullptr) {
        latchkey_util::AdField text;
        const bool named = latchkey_util::findAdField(raw.data, raw.length, latchkey_util::kAdTypeCompleteName, text) ||
                           latchkey_util::findAdField(raw.data, raw.length, latchkey_util::kAdTypeShortName, text);
        if (named) {
            name->assign(reinterpret_cast<const char*>(text.data), text.size);
        } else {
            name->clear();
        }
    }
    return true;
}

void track(const ble::Advert& raw) {
    ttlock::Advert advert;
    if (!readAdvert(raw, advert, nullptr)) {
        return;
    }
    LockState state = LockState::Unknown;
    int battery = -1;
    bool changed = false;
    bool reset = false;
    {
        std::lock_guard<std::mutex> guard(s_mutex);
        Lock* lock = findLocked(advert.mac);
        if (lock == nullptr) {
            return;
        }
        lock->live.hasRssi = true;
        lock->live.rssi = raw.rssi;
        const int64_t now = utcNow();
        if (now > 0) {
            lock->live.lastSeen = now;
        }
        if (!advert.paired && !lock->live.warnedUnpaired) {
            lock->live.warnedUnpaired = true;
            reset = true;
        }
        if (advert.hasLockState) {
            const LockState next = advert.locked ? LockState::Locked : LockState::Unlocked;
            changed = next != lock->live.state || advert.battery != lock->live.battery;
            lock->live.state = next;
            lock->live.battery = advert.battery;
            state = next;
            battery = advert.battery;
        }
    }
    if (reset) {
        ESP_LOGW(TAG, "stored lock %s advertises as unpaired: it was reset and its keys no longer work",
                 advert.mac.c_str());
    }
    if (changed) {
        publishState(advert.mac, state, battery);
    }
}

void publishScanResult(const ble::Advert& raw, const ttlock::Advert& advert, const std::string& name) {
    bool held = false;
    {
        std::lock_guard<std::mutex> guard(s_mutex);
        held = findLocked(advert.mac) != nullptr;
    }
    ESP_LOGI(TAG, "seen %s: %s address, advert type %u, rssi %d, protocol %u.%u scene %u, %s, battery %d",
             advert.mac.c_str(), ble::addressTypeName(raw.address.type), raw.eventType, raw.rssi,
             advert.version.protocolType, advert.version.protocolVersion, advert.version.scene,
             advert.paired ? "paired" : "unpaired", advert.battery);
    cJSON* data = cJSON_CreateObject();
    cJSON_AddStringToObject(data, "mac", advert.mac.c_str());
    addOptionalString(data, "name", name.c_str());
    cJSON_AddNumberToObject(data, "rssi", raw.rssi);
    cJSON_AddBoolToObject(data, "paired", advert.paired);
    if (held) {
        cJSON_AddStringToObject(data, "lock", advert.mac.c_str());
    }
    events::publish("scan.result", data);
}

void finish(Job& job, rpc::Reply reply) {
    job.reply = std::move(reply);
    xSemaphoreGive(job.done);
}

void failExpired() {
    std::vector<Job*> late;
    {
        std::lock_guard<std::mutex> guard(s_mutex);
        late = s_queue.expire(nowMs());
    }
    for (Job* job : late) {
        finish(*job, rpc::fail("busy", "the lock queue was busy for 60 s; try again"));
    }
}

Job* nextJob() {
    std::lock_guard<std::mutex> guard(s_mutex);
    const std::optional<Job*> job = s_queue.pop(nowMs());
    return job.has_value() ? *job : nullptr;
}

void closeLink() {
    ble::disconnect();
    s_link.session.reset();
    s_link.open = false;
    s_link.mac.clear();
    s_link.keepUntilMs = 0;
}

int connectWithRetries(const ble::Address& address) {
    int rc = 0;
    for (int attempt = 1; attempt <= kConnectAttempts; ++attempt) {
        ble::LinkInfo info;
        rc = ble::connect(address, kConnectTimeoutMs, info);
        if (rc == 0) {
            return 0;
        }
        ESP_LOGW(TAG, "connect attempt %d of %d failed: %d", attempt, kConnectAttempts, rc);
        if (attempt < kConnectAttempts) {
            vTaskDelay(pdMS_TO_TICKS(kConnectRetryMs));
        }
    }
    return rc;
}

std::unique_ptr<ttlock::Session> newSession(const std::string& mac) {
    auto session = std::make_unique<ttlock::Session>(s_transport, s_clock, s_random);
    session->setEventSink([mac](const ttlock::LockEvent& event) { onPush(mac, event); });
    return session;
}

void keepLink(const std::string& mac, std::unique_ptr<ttlock::Session> session, uint32_t lingerMs) {
    s_link.open = true;
    s_link.mac = mac;
    s_link.session = std::move(session);
    s_link.keepUntilMs = nowMs() + lingerMs;
}

Status openLink(const Record& record) {
    if (s_link.open && s_link.mac == record.mac && ble::connected()) {
        return Status::Ok;
    }
    closeLink();
    if (connectWithRetries(addressOf(record)) != 0) {
        return Status::Timeout;
    }
    s_transport.reset();
    std::unique_ptr<ttlock::Session> session = newSession(record.mac);
    const Status attached = session->attach(keysOf(record));
    if (attached != Status::Ok) {
        ble::disconnect();
        return attached;
    }
    keepLink(record.mac, std::move(session), kLingerMs);
    return Status::Ok;
}

void catchUp(ttlock::Session& session, const Lock& lock) {
    const std::string mac = lock.record.mac;
    if ((lock.record.flags & store::locks::kFlagTimeCalibrated) == 0 && wallclock::synced() &&
        !lock.live.timeSyncTried) {
        {
            std::lock_guard<std::mutex> guard(s_mutex);
            Lock* stored = findLocked(mac);
            if (stored != nullptr) {
                stored->live.timeSyncTried = true;
            }
        }
        const Status synced = session.syncTime();
        ESP_LOGI(TAG, "catch-up time sync: %s", ttlock::toString(synced));
        if (synced == Status::Ok) {
            updateRecord(mac, [](Record& record) { record.flags |= store::locks::kFlagTimeCalibrated; });
        }
    }
    if (lock.record.features == 0) {
        uint64_t mask = 0;
        const Status read = session.features(mask);
        ESP_LOGI(TAG, "catch-up feature read: %s", ttlock::toString(read));
        if (read == Status::Ok) {
            updateRecord(mac, [mask](Record& record) { record.features = mask; });
        }
    }
}

Status readStatus(ttlock::Session& session, const Lock& lock, rpc::Reply& reply) {
    ttlock::LockStatus out;
    const Status status = session.status(out);
    if (status != Status::Ok) {
        return status;
    }
    noteState(lock.record.mac, out.state, out.battery, false);
    cJSON* result = cJSON_CreateObject();
    cJSON_AddStringToObject(result, "state", stateName(out.state));
    addOptionalNumber(result, "battery", out.battery >= 0, out.battery);
    cJSON_AddBoolToObject(result, "adminPasscodeConfirmed",
                          (lock.record.flags & store::locks::kFlagAdminPasscodeConfirmed) != 0);
    reply = rpc::ok(result);
    return Status::Ok;
}

Status readInfo(ttlock::Session& session, const Lock& lock, rpc::Reply& reply) {
    ttlock::DeviceInfo info;
    const Status status = session.deviceInfo(info);
    if (status != Status::Ok) {
        return status;
    }
    Record record = lock.record;
    copyDeviceInfo(record, info);
    updateRecord(record.mac, [&info](Record& stored) { copyDeviceInfo(stored, info); });
    reply = rpc::ok(infoJson(record));
    return Status::Ok;
}

Status readFeatures(ttlock::Session& session, const Lock& lock, rpc::Reply& reply) {
    uint64_t mask = 0;
    const Status status = session.features(mask);
    if (status != Status::Ok) {
        return status;
    }
    updateRecord(lock.record.mac, [mask](Record& record) { record.features = mask; });
    reply = rpc::ok(featuresJson(mask));
    return Status::Ok;
}

Status operate(ttlock::Session& session, const Lock& lock, bool open, rpc::Reply& reply) {
    ttlock::OperationResult out;
    const Status status = open ? session.unlock(out) : session.lock(out);
    if (status != Status::Ok) {
        return status;
    }
    const LockState state = open ? LockState::Unlocked : LockState::Locked;
    const int battery = out.battery >= 0 ? out.battery : lock.live.battery;
    noteState(lock.record.mac, state, battery, true);
    noteEvent(lock.record.mac, open ? "unlock" : "lock", "app");
    cJSON* result = cJSON_CreateObject();
    cJSON_AddStringToObject(result, "state", stateName(state));
    addOptionalNumber(result, "battery", battery >= 0, battery);
    reply = rpc::ok(result);
    return Status::Ok;
}

Status syncClock(ttlock::Session& session, const Lock& lock, rpc::Reply& reply) {
    const Status status = session.syncTime();
    if (status != Status::Ok) {
        return status;
    }
    updateRecord(lock.record.mac, [](Record& record) { record.flags |= store::locks::kFlagTimeCalibrated; });
    cJSON* result = cJSON_CreateObject();
    cJSON_AddNumberToObject(result, "time", static_cast<double>(utcNow()));
    reply = rpc::ok(result);
    return Status::Ok;
}

Status resetLock(ttlock::Session& session, const Lock& lock, rpc::Reply& reply) {
    const Status status = session.factoryReset();
    if (status != Status::Ok) {
        return status;
    }
    closeLink();
    const esp_err_t error = removeRecord(lock.record.mac);
    if (error != ESP_OK) {
        ESP_LOGE(TAG, "the lock was reset but its keys could not be erased: %s", esp_err_to_name(error));
    }
    ESP_LOGW(TAG, "lock %s reset to factory state", lock.record.mac);
    reply = rpc::ok();
    return Status::Ok;
}

void runLockJob(Job& job) {
    Lock lock;
    if (!snapshot(job.mac, lock)) {
        finish(job, notPaired());
        return;
    }
    Status status = openLink(lock.record);
    if (status != Status::Ok) {
        ESP_LOGW(TAG, "%s: no link to %s: %s", kindName(job.kind), job.mac.c_str(), ttlock::toString(status));
        finish(job, failure(status, 0));
        return;
    }
    ttlock::Session& session = *s_link.session;
    catchUp(session, lock);
    rpc::Reply reply;
    bool userOperation = false;
    switch (job.kind) {
        case Kind::Status:
            status = readStatus(session, lock, reply);
            break;
        case Kind::Info:
            status = readInfo(session, lock, reply);
            break;
        case Kind::Features:
            status = readFeatures(session, lock, reply);
            break;
        case Kind::Unlock:
            status = operate(session, lock, true, reply);
            userOperation = true;
            break;
        case Kind::Lock:
            status = operate(session, lock, false, reply);
            userOperation = true;
            break;
        case Kind::TimeSync:
            status = syncClock(session, lock, reply);
            break;
        case Kind::FactoryReset:
            status = resetLock(session, lock, reply);
            break;
        case Kind::Scan:
        case Kind::Pair:
            break;
    }
    const uint8_t lockError = s_link.session ? s_link.session->lockErrorCode() : 0;
    if (status != Status::Ok) {
        ESP_LOGW(TAG, "%s failed: %s (lock error 0x%02x)", kindName(job.kind), ttlock::toString(status), lockError);
        reply = failure(status, lockError);
    }
    if (s_link.open && (breaksLink(status) || !ble::connected())) {
        closeLink();
    } else if (s_link.open) {
        s_link.keepUntilMs = nowMs() + (userOperation ? kUserKeepAliveMs : kLingerMs);
    }
    finish(job, std::move(reply));
}

bool frameVersion(const ttlock::LockVersion& advertised, ttlock::LockVersion& out) {
    if (advertised.protocolType != kV3Frames.protocolType || advertised.protocolVersion != kV3Frames.protocolVersion) {
        return false;
    }
    out = kV3Frames;
    return true;
}

bool awaitAdvert(const std::string& mac, uint32_t waitMs, ble::Advert& raw, ttlock::Advert& advert,
                 std::string& name) {
    const uint32_t started = nowMs();
    bool warnedUnconnectable = false;
    while (true) {
        const uint32_t elapsed = nowMs() - started;
        if (elapsed >= waitMs) {
            return false;
        }
        if (ble::scanMode() != ble::ScanMode::Fast) {
            const int rc = ble::scan(ble::ScanMode::Fast);
            if (rc != 0) {
                ESP_LOGW(TAG, "cannot start the pairing scan: %d", rc);
                vTaskDelay(pdMS_TO_TICKS(kScanRetryMs));
                continue;
            }
        }
        ble::Message message{};
        if (!ble::receive(message, std::min(waitMs - elapsed, kIdleSliceMs)) ||
            message.kind != ble::Message::Kind::Advert) {
            continue;
        }
        track(message.advert);
        ttlock::Advert parsed;
        std::string parsedName;
        if (!readAdvert(message.advert, parsed, &parsedName)) {
            continue;
        }
        const std::string address = latchkey_util::formatBleAddress(message.advert.address.value);
        if (parsed.mac != mac && address != mac) {
            continue;
        }
        if (!ble::isConnectable(message.advert)) {
            if (!warnedUnconnectable) {
                ESP_LOGW(TAG, "the lock's advert type %u is not connectable", message.advert.eventType);
                warnedUnconnectable = true;
            }
            continue;
        }
        if (parsed.mac != address) {
            ESP_LOGW(TAG, "the advert names %s but comes from %s", parsed.mac.c_str(), address.c_str());
        }
        raw = message.advert;
        advert = parsed;
        name = parsedName;
        return true;
    }
}

bool roomFor(const std::string& mac) {
    std::lock_guard<std::mutex> guard(s_mutex);
    return findLocked(mac) != nullptr || s_locks.size() < store::locks::kMaxLocks;
}

void finishPairing(Job& job, Record& record, const ttlock::PairResult& result) {
    ttlock::Session& session = *s_link.session;
    ttlock::LockStatus status;
    const Status statusRead = session.status(status);
    ESP_LOGI(TAG, "first status after pairing: %s", ttlock::toString(statusRead));
    if (!result.timeCalibrated) {
        const Status synced = session.syncTime();
        ESP_LOGI(TAG, "time sync after pairing: %s", ttlock::toString(synced));
        if (synced == Status::Ok) {
            record.flags |= store::locks::kFlagTimeCalibrated;
        }
    }
    ttlock::DeviceInfo info;
    const Status infoRead = session.deviceInfo(info);
    if (infoRead == Status::Ok) {
        copyDeviceInfo(record, info);
        ESP_LOGI(TAG, "device: model %s, hardware %s, firmware %s, made %s", record.model, record.hardware,
                 record.firmware, record.manufactureDate);
    } else {
        ESP_LOGW(TAG, "device info after pairing: %s", ttlock::toString(infoRead));
    }
    storeKeys(record, session.keys());
    const esp_err_t stored = persist(record);
    if (stored != ESP_OK) {
        ESP_LOGE(TAG, "cannot store the paired lock: %s", esp_err_to_name(stored));
    }
    ESP_LOGI(TAG, "features 0x%08x%08x", static_cast<unsigned>(record.features >> 32),
             static_cast<unsigned>(record.features & 0xFFFFFFFF));
    if (statusRead == Status::Ok) {
        noteState(job.mac, status.state, status.battery, true);
    }
    if (!ble::connected()) {
        closeLink();
    }
    Lock view;
    if (!snapshot(job.mac, view)) {
        finish(job, rpc::fail("internal", "the paired lock could not be stored"));
        return;
    }
    cJSON* reply = cJSON_CreateObject();
    cJSON_AddItemToObject(reply, "lock", summaryJson(view));
    finish(job, rpc::ok(reply));
}

void runPair(Job& job) {
    closeLink();
    if (!roomFor(job.mac)) {
        finish(job, rpc::fail("too_many_locks", "the board already holds the most locks it can"));
        return;
    }
    ble::Advert raw{};
    ttlock::Advert advert;
    std::string advertName;
    const bool seen = awaitAdvert(job.mac, job.seconds * 1000, raw, advert, advertName);
    ble::scan(ble::ScanMode::Off);
    if (!seen) {
        finish(job, rpc::fail("timeout", "no lock with that address advertised; touch its keypad to wake it"));
        return;
    }
    publishScanResult(raw, advert, advertName);
    if (advert.paired) {
        finish(job, rpc::fail("lock_error", "the lock is already paired to other keys; factory-reset it first"));
        return;
    }
    ttlock::LockVersion frames;
    if (!frameVersion(advert.version, frames)) {
        finish(job, rpc::fail("unsupported", "only TTLock protocol 3 locks can be paired"));
        return;
    }
    Record record = blankRecord();
    record.addressType = raw.address.type;
    std::memcpy(record.address, raw.address.value, sizeof(record.address));
    copyText(record.mac, job.mac);
    copyText(record.name, job.name);
    const int rc = connectWithRetries(addressOf(record));
    if (rc != 0) {
        finish(job, rpc::fail("timeout", "the lock did not accept a connection"));
        return;
    }
    s_transport.reset();
    std::unique_ptr<ttlock::Session> session = newSession(job.mac);
    bool keysTaken = false;
    const ttlock::PersistCallback persistEarly = [&record, &keysTaken](const ttlock::LockKeys& early) {
        keysTaken = true;
        storeKeys(record, early);
        const esp_err_t error = persist(record);
        if (error != ESP_OK) {
            ESP_LOGE(TAG, "cannot store the lock's keys: %s", esp_err_to_name(error));
        } else {
            ESP_LOGI(TAG, "lock keys stored");
        }
    };
    ttlock::LockKeys keys;
    keys.mac = job.mac;
    ttlock::PairResult result;
    Status paired = session->pair(frames, keys, persistEarly, result);
    if (paired != Status::Ok && paired != Status::LockError && !keysTaken) {
        ESP_LOGW(TAG, "pairing failed before the lock took keys (%s); trying once more", ttlock::toString(paired));
        if (ble::connected() || connectWithRetries(addressOf(record)) == 0) {
            s_transport.reset();
            keys = ttlock::LockKeys{};
            keys.mac = job.mac;
            paired = session->pair(frames, keys, persistEarly, result);
        }
    }
    if (paired != Status::Ok) {
        const uint8_t lockError = session->lockErrorCode();
        ESP_LOGW(TAG, "pairing failed: %s, lock error 0x%02x, %u frames dropped", ttlock::toString(paired), lockError,
                 static_cast<unsigned>(session->droppedFrames()));
        session.reset();
        ble::disconnect();
        finish(job, failure(paired, lockError));
        return;
    }
    record.flags = store::locks::kFlagPairComplete;
    if (result.adminPasscodeConfirmed) {
        record.flags |= store::locks::kFlagAdminPasscodeConfirmed;
    }
    if (result.timeCalibrated) {
        record.flags |= store::locks::kFlagTimeCalibrated;
    }
    ESP_LOGI(TAG, "paired: time %s, admin passcode %s, %u frames dropped",
             result.timeCalibrated ? "calibrated" : "not calibrated",
             result.adminPasscodeConfirmed ? "confirmed" : "not confirmed",
             static_cast<unsigned>(session->droppedFrames()));
    storeKeys(record, keys);
    keepLink(job.mac, std::move(session), kLingerMs);
    finishPairing(job, record, result);
}

void runScan(Job& job) {
    closeLink();
    const uint32_t seconds = job.seconds;
    const int rc = ble::scan(ble::ScanMode::Fast);
    if (rc != 0) {
        finish(job, rpc::fail("internal", "cannot start scanning"));
        return;
    }
    cJSON* result = cJSON_CreateObject();
    cJSON_AddNumberToObject(result, "seconds", seconds);
    finish(job, rpc::ok(result));
    std::set<std::string> reported;
    const uint32_t waitMs = seconds * 1000;
    const uint32_t started = nowMs();
    for (uint32_t elapsed = 0; elapsed < waitMs; elapsed = nowMs() - started) {
        ble::Message message{};
        if (!ble::receive(message, std::min(waitMs - elapsed, kIdleSliceMs)) ||
            message.kind != ble::Message::Kind::Advert) {
            continue;
        }
        track(message.advert);
        ttlock::Advert advert;
        std::string name;
        if (!readAdvert(message.advert, advert, &name) || !reported.insert(advert.mac).second) {
            continue;
        }
        publishScanResult(message.advert, advert, name);
    }
    ble::scan(ble::ScanMode::Off);
}

void run(Job& job) {
    if (!ble::ready()) {
        finish(job, rpc::fail("unavailable", "Bluetooth is not ready"));
        return;
    }
    switch (job.kind) {
        case Kind::Scan:
            runScan(job);
            return;
        case Kind::Pair:
            runPair(job);
            return;
        default:
            runLockJob(job);
            return;
    }
}

void keepAlive() {
    if (!ble::connected()) {
        closeLink();
        return;
    }
    const auto left = static_cast<int32_t>(s_link.keepUntilMs - nowMs());
    if (left <= 0) {
        closeLink();
        return;
    }
    const Status status = s_link.session->receiveEvent(std::min(static_cast<uint32_t>(left), kEventSliceMs));
    if (status == Status::Disconnected || status == Status::NotPaired) {
        closeLink();
    }
}

void idle() {
    if (!ble::ready()) {
        vTaskDelay(kNotReadyDelay);
        return;
    }
    bool wanted = false;
    {
        std::lock_guard<std::mutex> guard(s_mutex);
        wanted = !s_locks.empty();
    }
    const ble::ScanMode target = wanted ? ble::ScanMode::Background : ble::ScanMode::Off;
    if (ble::scanMode() != target) {
        const int rc = ble::scan(target);
        if (rc != 0) {
            ESP_LOGW(TAG, "background scan: %d", rc);
        }
    }
    ble::Message message{};
    if (ble::receive(message, kIdleSliceMs) && message.kind == ble::Message::Kind::Advert) {
        track(message.advert);
    }
}

void worker(void*) {
    while (true) {
        failExpired();
        Job* job = nextJob();
        if (job != nullptr) {
            run(*job);
            continue;
        }
        if (s_link.open) {
            keepAlive();
            continue;
        }
        idle();
    }
}

rpc::Reply submit(Kind kind, const std::string& mac, const std::string& name, uint32_t seconds) {
    Job job;
    job.kind = kind;
    job.mac = mac;
    job.name = name;
    job.seconds = seconds;
    job.done = xSemaphoreCreateBinaryStatic(&job.doneBuffer);
    {
        std::lock_guard<std::mutex> guard(s_mutex);
        if (!s_queue.push(&job, nowMs())) {
            return rpc::fail("busy", "the lock queue is full; try again");
        }
    }
    ble::wake();
    while (xSemaphoreTake(job.done, pdMS_TO_TICKS(kSubmitSliceMs)) != pdTRUE) {
        failExpired();
    }
    return std::move(job.reply);
}

rpc::Reply submitFor(Kind kind, const std::string& mac) {
    if (!exists(mac)) {
        return notPaired();
    }
    return submit(kind, mac, {}, 0);
}

}

void start() {
    std::vector<Record> records;
    const esp_err_t error = store::locks::list(records);
    if (error != ESP_OK) {
        ESP_LOGE(TAG, "cannot read the stored locks: %s", esp_err_to_name(error));
    }
    size_t stored = 0;
    if (store::locks::count(stored) == ESP_OK && stored != records.size()) {
        ESP_LOGW(TAG, "%u stored lock entries could not be read", static_cast<unsigned>(stored - records.size()));
    }
    {
        std::lock_guard<std::mutex> guard(s_mutex);
        for (const Record& record : records) {
            s_locks.push_back(Lock{record, Live{}});
        }
    }
    ESP_LOGI(TAG, "%u lock(s) stored", static_cast<unsigned>(records.size()));
    const BaseType_t created =
        xTaskCreatePinnedToCore(worker, "lock_worker", kWorkerStack, nullptr, kWorkerPriority, &s_worker, kWorkerCore);
    if (created != pdPASS) {
        ESP_LOGE(TAG, "cannot start the lock worker");
        abort();
    }
}

rpc::Reply scan(uint32_t seconds) { return submit(Kind::Scan, {}, {}, seconds); }

rpc::Reply pair(const std::string& mac, const std::string& name, uint32_t waitSeconds) {
    return submit(Kind::Pair, mac, name, waitSeconds);
}

rpc::Reply list() {
    cJSON* result = cJSON_CreateObject();
    cJSON* locks = cJSON_AddArrayToObject(result, "locks");
    std::lock_guard<std::mutex> guard(s_mutex);
    for (const Lock& lock : s_locks) {
        cJSON_AddItemToArray(locks, summaryJson(lock));
    }
    return rpc::ok(result);
}

rpc::Reply rename(const std::string& mac, const std::string& name) {
    std::lock_guard<std::mutex> guard(s_mutex);
    Lock* lock = findLocked(mac);
    if (lock == nullptr) {
        return notPaired();
    }
    Record record = lock->record;
    copyText(record.name, name);
    if (store::locks::save(record) != ESP_OK) {
        return rpc::fail("internal", "cannot store the new name");
    }
    lock->record = record;
    cJSON* result = cJSON_CreateObject();
    cJSON_AddItemToObject(result, "lock", summaryJson(*lock));
    return rpc::ok(result);
}

rpc::Reply forget(const std::string& mac) {
    if (!exists(mac)) {
        return notPaired();
    }
    if (removeRecord(mac) != ESP_OK) {
        return rpc::fail("internal", "cannot erase the lock's keys");
    }
    ESP_LOGW(TAG, "forgot lock %s", mac.c_str());
    return rpc::ok();
}

rpc::Reply status(const std::string& mac) { return submitFor(Kind::Status, mac); }

rpc::Reply info(const std::string& mac) {
    {
        std::lock_guard<std::mutex> guard(s_mutex);
        const Lock* lock = findLocked(mac);
        if (lock == nullptr) {
            return notPaired();
        }
        if (lock->record.model[0] != '\0') {
            return rpc::ok(infoJson(lock->record));
        }
    }
    return submit(Kind::Info, mac, {}, 0);
}

rpc::Reply features(const std::string& mac) {
    {
        std::lock_guard<std::mutex> guard(s_mutex);
        const Lock* lock = findLocked(mac);
        if (lock == nullptr) {
            return notPaired();
        }
        if (lock->record.features != 0) {
            return rpc::ok(featuresJson(lock->record.features));
        }
    }
    return submit(Kind::Features, mac, {}, 0);
}

rpc::Reply unlock(const std::string& mac) { return submitFor(Kind::Unlock, mac); }

rpc::Reply lock(const std::string& mac) { return submitFor(Kind::Lock, mac); }

rpc::Reply syncTime(const std::string& mac) { return submitFor(Kind::TimeSync, mac); }

rpc::Reply factoryReset(const std::string& mac) { return submitFor(Kind::FactoryReset, mac); }

esp_err_t storedCount(size_t& out) { return store::locks::count(out); }

esp_err_t eraseAll() {
    std::lock_guard<std::mutex> guard(s_mutex);
    s_erased = true;
    s_locks.clear();
    return store::locks::eraseAll();
}

uint32_t workerStackFree() { return s_worker != nullptr ? uxTaskGetStackHighWaterMark(s_worker) : 0; }

}
