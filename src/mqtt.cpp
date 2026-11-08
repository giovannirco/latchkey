// SPDX-License-Identifier: GPL-3.0-or-later
#include "mqtt.h"

#include <algorithm>
#include <atomic>
#include <cmath>
#include <map>
#include <mutex>
#include <optional>
#include <set>
#include <string>
#include <string_view>
#include <utility>
#include <vector>

#include "cJSON.h"
#include "esp_app_desc.h"
#include "esp_log.h"
#include "esp_mac.h"
#include "esp_timer.h"
#include "freertos/FreeRTOS.h"
#include "freertos/task.h"
#include "mbedtls/platform_util.h"
#include "mqtt_client.h"

#include "audit.h"
#include "clock.h"
#include "events.h"
#include "latchkey_util/ha_discovery.h"
#include "latchkey_util/ha_state.h"
#include "latchkey_util/poll_schedule.h"
#include "latchkey_util/rate_limit.h"
#include "lock_manager.h"
#include "rpc.h"
#include "wifi.h"

namespace mqtt {

namespace {

constexpr const char* TAG = "mqtt";
constexpr uint32_t kTaskStack = 4096;
constexpr UBaseType_t kTaskPriority = 5;
constexpr int kClientStack = 3072;
constexpr int kClientPriority = 5;
constexpr int kKeepAliveSeconds = 60;
constexpr int kNetworkTimeoutMs = 10000;
constexpr int kBufferSize = 256;
constexpr uint64_t kOutboxLimit = 2048;
constexpr TickType_t kTick = pdMS_TO_TICKS(1000);
constexpr int64_t kReconcileMs = 5000;
constexpr int64_t kPollIntervalMs = 6LL * 3600 * 1000;
constexpr int64_t kPollRetryMs = 15LL * 60 * 1000;
constexpr size_t kMaxInbox = 32;
constexpr int kMaxTopic = 128;
constexpr int kMaxPayload = 16;
constexpr int kAtLeastOnce = 1;
constexpr int kAtMostOnce = 0;
constexpr const char* kManufacturer = "TTLock";
constexpr latchkey_util::RateLimiter::Policy kBackoff{1, 1, 120};
constexpr std::string_view kWatchedEvents[] = {
    R"({"event":"lock.state",)",
    R"({"event":"lock.event",)",
    R"({"event":"lock.alert",)",
};

enum class Kind : uint8_t {
    Event,
    Received,
    Connected,
    Disconnected,
    CommandDone,
    PollDone,
};

struct Item {
    Kind kind = Kind::Event;
    uint32_t generation = 0;
    std::string text;
    std::string payload;
    int length = 0;
    bool retained = false;
    bool answered = false;
};

struct View {
    std::string mac;
    std::string id;
    std::string name;
    std::string model;
    std::string state;
    int battery = -1;
    int64_t lastSeen = 0;
    bool hasEvent = false;
    std::string action;
    std::string method;
};

struct Announced {
    std::string mac;
    std::string name;
    std::string model;
    bool described = false;
    std::string state;
    std::string battery;
    std::string lastEvent;
    std::string link;
};

struct State {
    store::cfg::Mqtt settings;
    std::string board;
    std::string availability;
    esp_mqtt_client_handle_t client = nullptr;
    uint32_t generation = 0;
    bool connected = false;
    bool waiting = false;
    latchkey_util::RateLimiter backoff{kBackoff};
    int64_t reconcileAtMs = 0;
    int64_t watchedSinceUtc = 0;
    std::map<std::string, Announced> announced;
    std::map<std::string, latchkey_util::PollSchedule> polls;
    std::set<std::string> polling;
};

std::mutex s_mutex;
std::vector<Item> s_inbox;
std::optional<store::cfg::Mqtt> s_pending;
size_t s_dropped = 0;
std::atomic<bool> s_active{false};
TaskHandle_t s_task = nullptr;

int64_t nowMs() { return esp_timer_get_time() / 1000; }

int64_t utcNow() { return wallclock::synced() ? wallclock::utcSeconds() : 0; }

void wipe(std::string& secret) {
    mbedtls_platform_zeroize(secret.data(), secret.size());
    secret.clear();
}

bool droppable(Kind kind) { return kind == Kind::Event || kind == Kind::Received; }

void post(Item item) {
    TaskHandle_t task = nullptr;
    {
        std::lock_guard<std::mutex> guard(s_mutex);
        if (droppable(item.kind) && s_inbox.size() >= kMaxInbox) {
            ++s_dropped;
            return;
        }
        s_inbox.push_back(std::move(item));
        task = s_task;
    }
    if (task != nullptr) {
        xTaskNotifyGive(task);
    }
}

std::vector<Item> takeInbox() {
    std::vector<Item> items;
    size_t dropped = 0;
    {
        std::lock_guard<std::mutex> guard(s_mutex);
        items.swap(s_inbox);
        std::swap(dropped, s_dropped);
    }
    if (dropped > 0) {
        ESP_LOGW(TAG, "the queue was full: dropped %u messages and events", static_cast<unsigned>(dropped));
    }
    return items;
}

std::optional<store::cfg::Mqtt> takePending() {
    std::lock_guard<std::mutex> guard(s_mutex);
    std::optional<store::cfg::Mqtt> settings = std::move(s_pending);
    s_pending.reset();
    return settings;
}

const cJSON* member(const cJSON* object, const char* key) { return cJSON_GetObjectItemCaseSensitive(object, key); }

std::string text(const cJSON* object, const char* key) {
    const cJSON* item = member(object, key);
    return cJSON_IsString(item) && item->valuestring != nullptr ? std::string(item->valuestring) : std::string();
}

int64_t whole(const cJSON* object, const char* key, int64_t fallback) {
    const cJSON* item = member(object, key);
    return cJSON_IsNumber(item) ? static_cast<int64_t>(std::llround(item->valuedouble)) : fallback;
}

std::string boardId() {
    uint8_t mac[6] = {};
    ESP_ERROR_CHECK(esp_read_mac(mac, ESP_MAC_WIFI_STA));
    return latchkey_util::haBoardId(mac);
}

bool publish(State& state, const std::string& topic, const std::string& payload, bool retain, int qos) {
    const int length = static_cast<int>(payload.size());
    const int id = esp_mqtt_client_publish(state.client, topic.c_str(), payload.c_str(), length, qos, retain ? 1 : 0);
    if (id < 0) {
        ESP_LOGW(TAG, "could not publish to %s (%d)", topic.c_str(), id);
        return false;
    }
    return true;
}

bool publishMessage(State& state, const latchkey_util::MqttMessage& message, int qos) {
    return publish(state, message.topic, message.payload, message.retain, qos);
}

void publishState(State& state, const std::string& topic, const std::string& payload, std::string& last) {
    if (last == payload) {
        return;
    }
    if (publish(state, topic, payload, true, kAtMostOnce)) {
        last = payload;
    }
}

latchkey_util::HaLockTopics topicsOf(const State& state, const std::string& id) {
    latchkey_util::HaLockTopics topics;
    latchkey_util::haLockTopics(state.board, id, topics);
    return topics;
}

void subscribe(State& state, const std::string& filter, int qos) {
    if (esp_mqtt_client_subscribe_single(state.client, filter.c_str(), qos) < 0) {
        ESP_LOGW(TAG, "could not subscribe to %s", filter.c_str());
    }
}

std::optional<std::vector<View>> snapshot() {
    const rpc::Reply reply = lock_manager::list();
    const cJSON* locks = member(reply.result.get(), "locks");
    if (!reply.error.empty() || !cJSON_IsArray(locks)) {
        ESP_LOGW(TAG, "cannot list the locks; trying again later");
        return std::nullopt;
    }
    std::vector<View> views;
    const cJSON* lock = nullptr;
    cJSON_ArrayForEach(lock, locks) {
        View view;
        view.mac = text(lock, "mac");
        if (!latchkey_util::haLockId(view.mac, view.id)) {
            continue;
        }
        view.name = text(lock, "name");
        view.model = text(lock, "model");
        view.state = text(lock, "state");
        view.battery = static_cast<int>(whole(lock, "battery", -1));
        view.lastSeen = whole(lock, "lastSeen", 0);
        const cJSON* event = member(lock, "lastEvent");
        view.hasEvent = cJSON_IsObject(event);
        view.action = text(event, "action");
        view.method = text(event, "method");
        views.push_back(std::move(view));
    }
    return views;
}

std::string storedFirmware(const View& view) {
    if (view.model.empty()) {
        return {};
    }
    const rpc::Reply info = lock_manager::info(view.mac);
    return info.error.empty() ? text(info.result.get(), "firmware") : std::string();
}

bool describe(State& state, const View& view, Announced& entry) {
    const std::string firmware = storedFirmware(view);
    const latchkey_util::HaLock lock{state.settings.prefix, state.board,   view.id,
                                     view.name,             view.model,    kManufacturer,
                                     firmware,              esp_app_get_description()->version};
    std::vector<latchkey_util::MqttMessage> configs;
    if (!latchkey_util::haDiscovery(lock, configs)) {
        ESP_LOGE(TAG, "cannot describe lock %s to Home Assistant: its name or details are not valid UTF-8",
                 view.mac.c_str());
        entry.described = false;
        return true;
    }
    for (const latchkey_util::MqttMessage& config : configs) {
        if (!publishMessage(state, config, kAtMostOnce)) {
            return false;
        }
    }
    entry.described = true;
    ESP_LOGI(TAG, "announced lock %s to Home Assistant", view.mac.c_str());
    return true;
}

Announced* announce(State& state, const View& view) {
    const auto known = state.announced.find(view.id);
    if (known != state.announced.end() && known->second.name == view.name && known->second.model == view.model) {
        return known->second.described ? &known->second : nullptr;
    }
    Announced entry;
    entry.mac = view.mac;
    entry.name = view.name;
    entry.model = view.model;
    if (!describe(state, view, entry)) {
        return nullptr;
    }
    Announced& stored = state.announced[view.id] = std::move(entry);
    return stored.described ? &stored : nullptr;
}

void report(State& state, Announced& lock, const View& view) {
    const latchkey_util::HaLockTopics topics = topicsOf(state, view.id);
    if (const std::optional<std::string> payload = latchkey_util::haLockState(view.state)) {
        publishState(state, topics.state, *payload, lock.state);
    }
    if (const std::optional<std::string> payload = latchkey_util::haBattery(view.battery)) {
        publishState(state, topics.battery, *payload, lock.battery);
    }
    const std::optional<std::string> event = latchkey_util::haEventText(view.action, view.method);
    if (view.hasEvent && event.has_value()) {
        publishState(state, topics.lastEvent, *event, lock.lastEvent);
    }
    const std::optional<std::string> link = latchkey_util::haLinkState(view.lastSeen, utcNow(), state.watchedSinceUtc);
    if (link.has_value()) {
        publishState(state, topics.link, *link, lock.link);
    }
}

void retire(State& state, const std::string& id) {
    const auto entry = state.announced.find(id);
    std::vector<latchkey_util::MqttMessage> removal;
    if (latchkey_util::haRemoval(state.settings.prefix, state.board, id, removal)) {
        for (const latchkey_util::MqttMessage& message : removal) {
            publishMessage(state, message, kAtMostOnce);
        }
    }
    ESP_LOGI(TAG, "removed lock %s from Home Assistant", entry->second.mac.c_str());
    state.polls.erase(id);
    state.announced.erase(entry);
}

void auditCommand(const char* method, const std::string& mac, const rpc::Reply& reply) {
    const uint32_t utc = wallclock::synced() ? static_cast<uint32_t>(wallclock::utcSeconds()) : 0;
    audit::append({utc, rpc::Transport::Mqtt, method, mac, reply.error.empty() ? "ok" : reply.error});
}

bool startPoll(const std::string& id, const std::string& mac) {
    rpc::JobSpec spec;
    spec.action = "lock.status";
    spec.context = rpc::Context{rpc::Transport::Mqtt, std::nullopt};
    spec.run = [mac] { return lock_manager::status(mac); };
    spec.finish = [id](const rpc::Reply& reply) {
        Item done;
        done.kind = Kind::PollDone;
        done.text = id;
        done.answered = reply.error.empty();
        post(std::move(done));
    };
    const rpc::Reply queued = rpc::startJob(std::move(spec));
    if (!queued.error.empty()) {
        ESP_LOGW(TAG, "cannot start the status poll of %s: %s", mac.c_str(), queued.error.c_str());
        return false;
    }
    ESP_LOGI(TAG, "polling the status of %s", mac.c_str());
    return true;
}

void schedulePoll(State& state, const View& view) {
    latchkey_util::PollSchedule& plan = state.polls.try_emplace(view.id, kPollIntervalMs, kPollRetryMs).first->second;
    if (state.polling.count(view.id) > 0 || !plan.due(nowMs())) {
        return;
    }
    if (startPoll(view.id, view.mac)) {
        state.polling.insert(view.id);
    } else {
        plan.attempted(nowMs(), false);
    }
}

void reconcile(State& state) {
    if (state.watchedSinceUtc == 0) {
        state.watchedSinceUtc = utcNow();
    }
    const std::optional<std::vector<View>> views = snapshot();
    if (!views.has_value()) {
        return;
    }
    std::set<std::string> present;
    for (const View& view : *views) {
        present.insert(view.id);
        Announced* lock = announce(state, view);
        if (lock == nullptr) {
            continue;
        }
        report(state, *lock, view);
        schedulePoll(state, view);
    }
    std::vector<std::string> gone;
    for (const auto& [id, entry] : state.announced) {
        if (present.count(id) == 0 && !lock_manager::holds(entry.mac)) {
            gone.push_back(id);
        }
    }
    for (const std::string& id : gone) {
        retire(state, id);
    }
}

void runCommand(const std::string& mac, bool unlock) {
    const char* method = unlock ? "lock.unlock" : "lock.lock";
    ESP_LOGI(TAG, "%s for %s", unlock ? "UNLOCK" : "LOCK", mac.c_str());
    rpc::JobSpec spec;
    spec.action = method;
    spec.context = rpc::Context{rpc::Transport::Mqtt, std::nullopt};
    spec.run = [mac, unlock] { return unlock ? lock_manager::unlock(mac) : lock_manager::lock(mac); };
    spec.finish = [mac, method](const rpc::Reply& reply) {
        auditCommand(method, mac, reply);
        Item done;
        done.kind = Kind::CommandDone;
        done.text = mac;
        post(std::move(done));
    };
    const rpc::Reply queued = rpc::startJob(std::move(spec));
    if (!queued.error.empty()) {
        auditCommand(method, mac, queued);
    }
}

void handleCommand(const std::string& id, const Item& item) {
    if (item.length == 0) {
        return;
    }
    std::string mac;
    latchkey_util::haLockMac(id, mac);
    const bool complete = item.length == static_cast<int>(item.payload.size());
    const std::string_view payload = complete ? std::string_view(item.payload) : std::string_view();
    switch (latchkey_util::parseHaCommand(payload, item.retained)) {
        case latchkey_util::HaCommand::Lock:
            runCommand(mac, false);
            return;
        case latchkey_util::HaCommand::Unlock:
            runCommand(mac, true);
            return;
        case latchkey_util::HaCommand::Replayed:
            ESP_LOGW(TAG, "ignored a retained command for %s: the broker replays it on every connection", mac.c_str());
            return;
        case latchkey_util::HaCommand::Unknown:
            break;
    }
    ESP_LOGW(TAG, "ignored a command for %s: not LOCK or UNLOCK (%d bytes)", mac.c_str(), item.length);
}

void pruneConfig(State& state, const std::string& id, const Item& item) {
    std::string mac;
    latchkey_util::haLockMac(id, mac);
    if (item.length == 0 || lock_manager::holds(mac)) {
        return;
    }
    if (publish(state, item.text, std::string(), true, kAtMostOnce)) {
        ESP_LOGI(TAG, "removed a Home Assistant config of lock %s, which the board does not hold", mac.c_str());
    }
}

void handleReceived(State& state, const Item& item) {
    if (const std::optional<std::string> lock = latchkey_util::haCommandLock(item.text, state.board)) {
        handleCommand(*lock, item);
        return;
    }
    if (const std::optional<std::string> lock =
            latchkey_util::haConfigLock(item.text, state.settings.prefix, state.board)) {
        pruneConfig(state, *lock, item);
    }
}

void handleEvent(State& state, const std::string& line) {
    const rpc::Json event(cJSON_Parse(line.c_str()));
    const cJSON* data = member(event.get(), "data");
    const std::string name = text(event.get(), "event");
    const std::string mac = text(data, "lock");
    std::string id;
    if (!latchkey_util::haLockId(mac, id)) {
        return;
    }
    const auto entry = state.announced.find(id);
    if (entry == state.announced.end() || !entry->second.described) {
        return;
    }
    Announced& lock = entry->second;
    const latchkey_util::HaLockTopics topics = topicsOf(state, id);
    if (name == "lock.state") {
        if (const std::optional<std::string> payload = latchkey_util::haLockState(text(data, "state"))) {
            publishState(state, topics.state, *payload, lock.state);
        }
        if (const std::optional<std::string> payload =
                latchkey_util::haBattery(static_cast<int>(whole(data, "battery", -1)))) {
            publishState(state, topics.battery, *payload, lock.battery);
            const auto plan = state.polls.find(id);
            if (plan != state.polls.end()) {
                plan->second.refreshed(nowMs());
            }
        }
    } else if (name == "lock.event") {
        if (const std::optional<std::string> payload =
                latchkey_util::haEventText(text(data, "action"), text(data, "method"))) {
            publishState(state, topics.lastEvent, *payload, lock.lastEvent);
        }
    } else if (name == "lock.alert") {
        latchkey_util::MqttMessage alert;
        if (latchkey_util::haAlert(topics, text(data, "method"), whole(data, "time", 0), alert)) {
            publishMessage(state, alert, kAtLeastOnce);
        } else {
            ESP_LOGW(TAG, "dropped an unlock alert for %s: its method is not a plain name", mac.c_str());
        }
    }
}

void handleConnected(State& state) {
    state.connected = true;
    state.waiting = false;
    state.backoff.recordSuccess();
    state.announced.clear();
    s_active = true;
    publish(state, state.availability, latchkey_util::kHaOnline, true, kAtLeastOnce);
    subscribe(state, "latchkey/" + state.board + "/+/set", kAtLeastOnce);
    subscribe(state, state.settings.prefix + "/+/" + state.board + "/+/config", kAtMostOnce);
    state.reconcileAtMs = 0;
    ESP_LOGI(TAG, "connected to the broker, topics under latchkey/%s/", state.board.c_str());
}

void handleDisconnected(State& state) {
    const bool wasConnected = state.connected;
    state.connected = false;
    state.waiting = true;
    s_active = false;
    state.backoff.recordFailure(nowMs());
    const uint32_t wait = state.backoff.retryAfterSeconds(nowMs());
    ESP_LOGW(TAG, "%s; trying again in %u s", wasConnected ? "lost the broker" : "cannot reach the broker",
             static_cast<unsigned>(wait));
}

void handle(State& state, const Item& item) {
    switch (item.kind) {
        case Kind::Event:
            if (state.connected) {
                handleEvent(state, item.text);
            }
            return;
        case Kind::CommandDone:
            state.reconcileAtMs = 0;
            return;
        case Kind::PollDone:
            state.polling.erase(item.text);
            if (const auto plan = state.polls.find(item.text); plan != state.polls.end()) {
                plan->second.attempted(nowMs(), item.answered);
            }
            state.reconcileAtMs = 0;
            return;
        case Kind::Received:
        case Kind::Connected:
        case Kind::Disconnected:
            break;
    }
    if (item.generation != state.generation || state.client == nullptr) {
        return;
    }
    if (item.kind == Kind::Connected) {
        handleConnected(state);
    } else if (item.kind == Kind::Disconnected) {
        handleDisconnected(state);
    } else if (state.connected) {
        handleReceived(state, item);
    }
}

void onClientEvent(void* arg, esp_event_base_t, int32_t id, void* data) {
    const auto generation = static_cast<uint32_t>(reinterpret_cast<uintptr_t>(arg));
    const auto* event = static_cast<const esp_mqtt_event_t*>(data);
    Item item;
    item.generation = generation;
    switch (static_cast<esp_mqtt_event_id_t>(id)) {
        case MQTT_EVENT_CONNECTED:
            item.kind = Kind::Connected;
            break;
        case MQTT_EVENT_DISCONNECTED:
            item.kind = Kind::Disconnected;
            break;
        case MQTT_EVENT_ERROR:
            if (event->error_handle != nullptr &&
                event->error_handle->error_type == MQTT_ERROR_TYPE_CONNECTION_REFUSED) {
                ESP_LOGE(TAG, "the broker refused the connection (code %d): check the username and password",
                         static_cast<int>(event->error_handle->connect_return_code));
            }
            return;
        case MQTT_EVENT_DATA:
            if (event->current_data_offset != 0 || event->topic == nullptr || event->topic_len <= 0 ||
                event->topic_len > kMaxTopic) {
                return;
            }
            item.kind = Kind::Received;
            item.text.assign(event->topic, event->topic_len);
            if (event->data != nullptr && event->data_len > 0) {
                item.payload.assign(event->data, std::min(event->data_len, kMaxPayload));
            }
            item.length = event->total_data_len;
            item.retained = event->retain;
            break;
        default:
            return;
    }
    post(std::move(item));
}

void stopClient(State& state) {
    if (state.client == nullptr) {
        return;
    }
    s_active = false;
    if (state.connected) {
        publish(state, state.availability, latchkey_util::kHaOffline, true, kAtLeastOnce);
    }
    esp_mqtt_client_stop(state.client);
    esp_mqtt_client_destroy(state.client);
    state.client = nullptr;
    state.connected = false;
    state.waiting = false;
    ++state.generation;
    state.announced.clear();
    ESP_LOGI(TAG, "disconnected from the broker");
}

void startClient(State& state) {
    esp_mqtt_client_config_t config{};
    config.broker.address.hostname = state.settings.host.c_str();
    config.broker.address.port = state.settings.port;
    config.broker.address.transport = MQTT_TRANSPORT_OVER_TCP;
    config.credentials.client_id = state.board.c_str();
    if (!state.settings.username.empty()) {
        config.credentials.username = state.settings.username.c_str();
    }
    if (!state.settings.password.empty()) {
        config.credentials.authentication.password = state.settings.password.c_str();
    }
    config.session.last_will.topic = state.availability.c_str();
    config.session.last_will.msg = latchkey_util::kHaOffline;
    config.session.last_will.qos = kAtLeastOnce;
    config.session.last_will.retain = 1;
    config.session.keepalive = kKeepAliveSeconds;
    config.network.disable_auto_reconnect = true;
    config.network.timeout_ms = kNetworkTimeoutMs;
    config.task.stack_size = kClientStack;
    config.task.priority = kClientPriority;
    config.buffer.size = kBufferSize;
    config.outbox.limit = kOutboxLimit;
    ++state.generation;
    state.client = esp_mqtt_client_init(&config);
    if (state.client == nullptr) {
        ESP_LOGE(TAG, "cannot create the MQTT client");
        state.backoff.recordFailure(nowMs());
        return;
    }
    esp_mqtt_client_register_event(state.client, MQTT_EVENT_ANY, onClientEvent,
                                   reinterpret_cast<void*>(static_cast<uintptr_t>(state.generation)));
    if (esp_mqtt_client_start(state.client) != ESP_OK) {
        ESP_LOGE(TAG, "cannot start the MQTT client");
        esp_mqtt_client_destroy(state.client);
        state.client = nullptr;
        state.backoff.recordFailure(nowMs());
        return;
    }
    ESP_LOGI(TAG, "connecting to the broker at %s:%u", state.settings.host.c_str(),
             static_cast<unsigned>(state.settings.port));
}

void reconfigure(State& state, store::cfg::Mqtt settings) {
    stopClient(state);
    wipe(state.settings.password);
    state.settings = std::move(settings);
    state.backoff.recordSuccess();
    if (!state.settings.enabled) {
        ESP_LOGI(TAG, "MQTT is off");
    }
}

void maintain(State& state) {
    if (!state.settings.enabled || state.backoff.retryAfterSeconds(nowMs()) > 0 || wifi::address() == 0) {
        return;
    }
    if (state.client == nullptr) {
        startClient(state);
        return;
    }
    if (state.waiting) {
        state.waiting = esp_mqtt_client_reconnect(state.client) != ESP_OK;
        return;
    }
    if (state.connected && nowMs() >= state.reconcileAtMs) {
        reconcile(state);
        state.reconcileAtMs = nowMs() + kReconcileMs;
    }
}

void run(void*) {
    State state;
    state.board = boardId();
    state.availability = "latchkey/" + state.board + "/availability";
    while (true) {
        ulTaskNotifyTake(pdTRUE, kTick);
        if (std::optional<store::cfg::Mqtt> settings = takePending()) {
            reconfigure(state, std::move(*settings));
            wipe(settings->password);
        }
        for (const Item& item : takeInbox()) {
            handle(state, item);
        }
        maintain(state);
    }
}

bool launch() {
    if (s_task != nullptr) {
        return true;
    }
    if (xTaskCreate(run, "mqtt", kTaskStack, nullptr, kTaskPriority, &s_task) != pdPASS) {
        s_task = nullptr;
        ESP_LOGE(TAG, "cannot start the MQTT task");
        return false;
    }
    return true;
}

bool watched(const std::string& line) {
    return std::any_of(std::begin(kWatchedEvents), std::end(kWatchedEvents),
                       [&line](std::string_view prefix) { return line.rfind(prefix, 0) == 0; });
}

}

void start() {
    events::addSink([](const std::string& line) {
        if (s_active && watched(line)) {
            Item item;
            item.kind = Kind::Event;
            item.text = line;
            post(std::move(item));
        }
    });
    store::cfg::Mqtt settings;
    const esp_err_t error = store::cfg::loadMqtt(settings);
    if (error != ESP_OK) {
        ESP_LOGE(TAG, "cannot read the MQTT settings (%s): MQTT stays off", esp_err_to_name(error));
        return;
    }
    if (settings.enabled) {
        apply(settings);
    }
    wipe(settings.password);
}

bool apply(const store::cfg::Mqtt& settings) {
    TaskHandle_t task = nullptr;
    {
        std::lock_guard<std::mutex> guard(s_mutex);
        if (s_pending.has_value()) {
            wipe(s_pending->password);
        }
        s_pending = settings;
        if (settings.enabled && !launch()) {
            wipe(s_pending->password);
            s_pending.reset();
            return false;
        }
        task = s_task;
    }
    if (task != nullptr) {
        xTaskNotifyGive(task);
    }
    return true;
}

uint32_t stackFree() {
    std::lock_guard<std::mutex> guard(s_mutex);
    return s_task != nullptr ? uxTaskGetStackHighWaterMark(s_task) : 0;
}

}
