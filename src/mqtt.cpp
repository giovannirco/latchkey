// SPDX-License-Identifier: GPL-3.0-or-later
#include "mqtt.h"

#include <algorithm>
#include <atomic>
#include <cmath>
#include <cstdint>
#include <deque>
#include <map>
#include <memory>
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
#include "freertos/semphr.h"
#include "freertos/task.h"
#include "mbedtls/platform_util.h"
#include "mqtt_client.h"

#include "audit.h"
#include "clock.h"
#include "events.h"
#include "jobs.h"
#include "latchkey_util/connection_backoff.h"
#include "latchkey_util/ha_discovery.h"
#include "latchkey_util/ha_state.h"
#include "latchkey_util/mqtt_settings.h"
#include "latchkey_util/poll_planner.h"
#include "latchkey_util/refusal_tally.h"
#include "lock_manager.h"
#include "rpc.h"
#include "wifi.h"

namespace mqtt {

namespace {

constexpr const char* TAG = "mqtt";
constexpr uint32_t kTaskStack = 4608;
constexpr UBaseType_t kTaskPriority = 5;
constexpr int kClientStack = 3584;
constexpr int kClientPriority = 5;
constexpr int kKeepAliveSeconds = 60;
constexpr int kNetworkTimeoutMs = 10000;
constexpr int kBufferSize = 256;
constexpr uint64_t kOutboxLimit = 2048;
constexpr TickType_t kTick = pdMS_TO_TICKS(1000);
constexpr TickType_t kForgetWait = pdMS_TO_TICKS(5000);
constexpr int64_t kLeaveWaitMs = 3000;
constexpr int64_t kAvailabilityWaitMs = 1000;
constexpr TickType_t kDrainPoll = pdMS_TO_TICKS(20);
constexpr int64_t kReconcileMs = 30 * 1000;
constexpr int64_t kPollIntervalMs = 6LL * 3600 * 1000;
constexpr int64_t kPollRetryMs = 15LL * 60 * 1000;
constexpr int64_t kPollGapMs = 60 * 1000;
constexpr int64_t kStableMs = 60 * 1000;
constexpr int64_t kTallyWindowMs = 60 * 1000;
constexpr size_t kMaxInbox = 32;
constexpr size_t kMaxPruned = 32;
constexpr int kMaxTopic = 128;
constexpr int kMaxPayload = 16;
constexpr int kAtLeastOnce = 1;
constexpr int kAtMostOnce = 0;
constexpr const char* kManufacturer = "TTLock";
constexpr const char* kRefusedMethod = "mqtt.command";
constexpr char kDropped[] = "dropped";
constexpr char kQueued[] = "queued";
constexpr char kUnknown[] = "unknown";
constexpr char kReplayed[] = "replayed";
constexpr const char* kUnreachable = "cannot reach the broker";
constexpr const char* kRefusedLogin = "the broker refused the username or password";
constexpr const char* kRefusedSubscription = "the broker refused a subscription";
constexpr latchkey_util::RateLimiter::Policy kBackoff{1, 1, 120};
constexpr std::string_view kWatchedEvents[] = {
    R"({"event":"lock.state",)",
    R"({"event":"lock.event",)",
    R"({"event":"lock.alert",)",
};

enum class Kind : uint8_t {
    Event,
    Command,
    StaleConfig,
    Connected,
    Disconnected,
    Refused,
    SubscribeFailed,
    CommandDone,
    PollDone,
    Forget,
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

struct ClientContext {
    uint32_t generation = 0;
    std::string board;
    std::string prefix;
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
    bool subscribed = false;
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
    std::unique_ptr<ClientContext> context;
    uint32_t generation = 0;
    bool connected = false;
    bool waiting = false;
    const char* problem = nullptr;
    latchkey_util::ConnectionBackoff backoff{kBackoff, kStableMs};
    int64_t reconcileAtMs = 0;
    int64_t watchedSinceUtc = 0;
    std::map<std::string, Announced> announced;
    std::deque<std::string> pruned;
    std::set<std::string> commanding;
    latchkey_util::PollPlanner polls{kPollIntervalMs, kPollRetryMs, kPollGapMs};
    latchkey_util::RefusalTally refusals{kTallyWindowMs};
    latchkey_util::RefusalTally ignored{kTallyWindowMs};
};

std::mutex s_mutex;
std::vector<Item> s_inbox;
std::optional<store::cfg::Mqtt> s_pending;
size_t s_dropped = 0;
uint32_t s_droppedCommands = 0;
Status s_status;
TaskHandle_t s_task = nullptr;
SemaphoreHandle_t s_forgotten = nullptr;
std::atomic<bool> s_active{false};
std::atomic<uint32_t> s_clientStackLow{UINT32_MAX};

int64_t nowMs() { return esp_timer_get_time() / 1000; }

int64_t utcNow() { return wallclock::synced() ? wallclock::utcSeconds() : 0; }

void wipe(std::string& secret) {
    secret.resize(secret.capacity());
    mbedtls_platform_zeroize(secret.data(), secret.size());
    secret.clear();
}

bool droppable(Kind kind) { return kind == Kind::Event || kind == Kind::Command || kind == Kind::StaleConfig; }

void post(Item item) {
    TaskHandle_t task = nullptr;
    {
        std::lock_guard<std::mutex> guard(s_mutex);
        if (droppable(item.kind) && s_inbox.size() >= kMaxInbox) {
            if (item.kind == Kind::Command) {
                ++s_droppedCommands;
            } else {
                ++s_dropped;
            }
            return;
        }
        s_inbox.push_back(std::move(item));
        task = s_task;
    }
    if (task != nullptr) {
        xTaskNotifyGive(task);
    }
}

std::vector<Item> takeInbox(State& state) {
    std::vector<Item> items;
    size_t dropped = 0;
    uint32_t droppedCommands = 0;
    {
        std::lock_guard<std::mutex> guard(s_mutex);
        items.swap(s_inbox);
        std::swap(dropped, s_dropped);
        std::swap(droppedCommands, s_droppedCommands);
    }
    if (droppedCommands > 0) {
        state.refusals.note(kDropped, droppedCommands);
    }
    if (dropped > 0) {
        ESP_LOGW(TAG, "the queue was full: dropped %u events and messages", static_cast<unsigned>(dropped));
    }
    return items;
}

std::optional<store::cfg::Mqtt> takePending() {
    std::lock_guard<std::mutex> guard(s_mutex);
    if (!s_pending.has_value()) {
        return std::nullopt;
    }
    std::optional<store::cfg::Mqtt> settings = s_pending;
    wipe(s_pending->password);
    s_pending.reset();
    return settings;
}

void setStatus(bool connected, const char* problem) {
    std::lock_guard<std::mutex> guard(s_mutex);
    s_status.connected = connected;
    s_status.problem = problem != nullptr ? problem : "";
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

std::string macOf(const std::string& id) {
    std::string mac;
    latchkey_util::haLockMac(id, mac);
    return mac;
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

bool publishAll(State& state, const std::vector<latchkey_util::MqttMessage>& messages, int qos) {
    bool all = true;
    for (const latchkey_util::MqttMessage& message : messages) {
        all = publish(state, message.topic, message.payload, message.retain, qos) && all;
    }
    return all;
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

void fault(State& state, const char* problem) {
    ESP_LOGE(TAG, "%s: reconnecting", problem);
    state.problem = problem;
    esp_mqtt_client_disconnect(state.client);
}

bool removeLock(State& state, const std::string& prefix, const std::string& id, int qos) {
    std::vector<latchkey_util::MqttMessage> removal;
    return latchkey_util::haRemoval(prefix, state.board, id, removal) && publishAll(state, removal, qos);
}

bool drained(State& state, int64_t deadlineMs) {
    while (esp_mqtt_client_get_outbox_size(state.client) > 0) {
        if (nowMs() >= deadlineMs) {
            return false;
        }
        vTaskDelay(kDrainPoll);
    }
    return true;
}

bool removeBeforeLeaving(State& state, const std::string& prefix, int64_t deadlineMs) {
    bool confirmed = true;
    for (const auto& [id, entry] : state.announced) {
        const bool sent = removeLock(state, prefix, id, kAtLeastOnce);
        confirmed = sent && drained(state, deadlineMs) && confirmed;
    }
    return confirmed;
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
    if (!publishAll(state, configs, kAtMostOnce)) {
        return false;
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
    entry.subscribed = known != state.announced.end() && known->second.subscribed;
    if (!describe(state, view, entry)) {
        return nullptr;
    }
    Announced& stored = state.announced[view.id] = std::move(entry);
    return stored.described ? &stored : nullptr;
}

bool subscribeCommands(State& state, const std::string& id, Announced& lock) {
    if (lock.subscribed) {
        return true;
    }
    const std::string topic = topicsOf(state, id).command;
    if (esp_mqtt_client_subscribe_single(state.client, topic.c_str(), kAtLeastOnce) < 0) {
        fault(state, kRefusedSubscription);
        return false;
    }
    lock.subscribed = true;
    return true;
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
    if (entry->second.subscribed) {
        esp_mqtt_client_unsubscribe(state.client, topicsOf(state, id).command.c_str());
    }
    entry->second.subscribed = false;
    if (!removeLock(state, state.settings.prefix, id, kAtMostOnce)) {
        ESP_LOGW(TAG, "could not remove lock %s from Home Assistant yet; trying again", entry->second.mac.c_str());
        return;
    }
    ESP_LOGI(TAG, "removed lock %s from Home Assistant", entry->second.mac.c_str());
    state.polls.forget(id);
    state.announced.erase(entry);
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
        if (lock == nullptr || !subscribeCommands(state, view.id, *lock)) {
            continue;
        }
        report(state, *lock, view);
        state.polls.track(view.id);
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

void auditCommand(const char* method, const std::string& mac, const rpc::Reply& reply) {
    const uint32_t utc = wallclock::synced() ? static_cast<uint32_t>(wallclock::utcSeconds()) : 0;
    audit::append({utc, rpc::Transport::Mqtt, method, mac, reply.error.empty() ? "ok" : reply.error});
}

void startPoll(State& state, int64_t now) {
    const std::optional<std::string> id = state.polls.next(now, jobs::idle());
    if (!id.has_value()) {
        return;
    }
    const auto lock = state.announced.find(*id);
    if (lock == state.announced.end()) {
        return;
    }
    const std::string mac = lock->second.mac;
    rpc::JobSpec spec;
    spec.action = "lock.status";
    spec.context = rpc::Context{rpc::Transport::Mqtt, std::nullopt};
    spec.run = [mac](const cJSON*, const rpc::Context&) { return lock_manager::status(mac); };
    spec.finish = [lockId = *id](const rpc::JobSpec&, const rpc::Reply& reply) {
        Item done;
        done.kind = Kind::PollDone;
        done.text = lockId;
        done.answered = reply.error.empty();
        post(std::move(done));
    };
    const rpc::Reply queued = rpc::startJob(std::move(spec));
    if (!queued.error.empty()) {
        ESP_LOGW(TAG, "cannot start the status poll of %s: %s", mac.c_str(), queued.error.c_str());
        state.polls.finished(*id, now, false);
        return;
    }
    state.polls.started(*id);
    ESP_LOGI(TAG, "polling the status of %s", mac.c_str());
}

void runCommand(State& state, const std::string& id, bool unlock) {
    if (state.commanding.count(id) > 0) {
        state.refusals.note(kQueued);
        return;
    }
    const std::string mac = macOf(id);
    const char* method = unlock ? "lock.unlock" : "lock.lock";
    rpc::JobSpec spec;
    spec.action = method;
    spec.context = rpc::Context{rpc::Transport::Mqtt, std::nullopt};
    spec.run = [mac, unlock](const cJSON*, const rpc::Context&) {
        return unlock ? lock_manager::unlock(mac) : lock_manager::lock(mac);
    };
    spec.finish = [id, mac, method](const rpc::JobSpec&, const rpc::Reply& reply) {
        auditCommand(method, mac, reply);
        Item done;
        done.kind = Kind::CommandDone;
        done.text = id;
        post(std::move(done));
    };
    const rpc::Reply queued = rpc::startJob(std::move(spec));
    if (!queued.error.empty()) {
        state.refusals.note(queued.error);
        return;
    }
    state.commanding.insert(id);
    ESP_LOGI(TAG, "%s for %s", unlock ? "UNLOCK" : "LOCK", mac.c_str());
}

void handleCommand(State& state, const Item& item) {
    if (item.length == 0) {
        return;
    }
    const bool complete = item.length == static_cast<int>(item.payload.size());
    const std::string_view payload = complete ? std::string_view(item.payload) : std::string_view();
    switch (latchkey_util::parseHaCommand(payload, item.retained)) {
        case latchkey_util::HaCommand::Lock:
            runCommand(state, item.text, false);
            return;
        case latchkey_util::HaCommand::Unlock:
            runCommand(state, item.text, true);
            return;
        case latchkey_util::HaCommand::Replayed:
            state.ignored.note(kReplayed);
            return;
        case latchkey_util::HaCommand::Unknown:
            state.ignored.note(kUnknown);
            return;
    }
}

void pruneStale(State& state, const std::string& id) {
    if (std::find(state.pruned.begin(), state.pruned.end(), id) != state.pruned.end() ||
        state.announced.count(id) > 0 || lock_manager::holds(macOf(id))) {
        return;
    }
    if (removeLock(state, state.settings.prefix, id, kAtMostOnce)) {
        if (state.pruned.size() == kMaxPruned) state.pruned.pop_front();
        state.pruned.push_back(id);
        ESP_LOGI(TAG, "removed the Home Assistant entities of lock %s, which the board does not hold",
                 macOf(id).c_str());
    }
}

void handleEvent(State& state, const std::string& line) {
    const rpc::Json event(cJSON_Parse(line.c_str()));
    const cJSON* data = member(event.get(), "data");
    const std::string name = text(event.get(), "event");
    std::string id;
    if (!latchkey_util::haLockId(text(data, "lock"), id)) {
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
            state.polls.refreshed(id, nowMs());
        }
    } else if (name == "lock.event") {
        if (const std::optional<std::string> payload =
                latchkey_util::haEventText(text(data, "action"), text(data, "method"))) {
            publishState(state, topics.lastEvent, *payload, lock.lastEvent);
        }
    } else if (name == "lock.alert") {
        latchkey_util::MqttMessage alert;
        if (latchkey_util::haAlert(topics, text(data, "method"), whole(data, "time", 0), alert)) {
            publish(state, alert.topic, alert.payload, alert.retain, kAtLeastOnce);
        } else {
            ESP_LOGW(TAG, "dropped an unlock alert for %s: its method is not a plain name", lock.mac.c_str());
        }
    }
}

void handleConnected(State& state) {
    state.connected = true;
    state.waiting = false;
    state.problem = nullptr;
    state.backoff.connected(nowMs());
    state.announced.clear();
    state.pruned.clear();
    s_active = true;
    setStatus(true, nullptr);
    publish(state, state.availability, latchkey_util::kHaOnline, true, kAtLeastOnce);
    const std::string configs = state.settings.prefix + "/+/" + state.board + "/+/config";
    if (esp_mqtt_client_subscribe_single(state.client, configs.c_str(), kAtMostOnce) < 0) {
        fault(state, kRefusedSubscription);
        return;
    }
    state.reconcileAtMs = 0;
    ESP_LOGI(TAG, "connected to the broker, topics under latchkey/%s/", state.board.c_str());
}

void handleDisconnected(State& state) {
    const bool wasConnected = state.connected;
    state.connected = false;
    state.waiting = true;
    s_active = false;
    state.backoff.disconnected(nowMs());
    const char* problem = state.problem != nullptr ? state.problem : kUnreachable;
    setStatus(false, problem);
    const uint32_t wait = state.backoff.retryAfterSeconds(nowMs());
    ESP_LOGW(TAG, "%s (%s); trying again in %u s", wasConnected ? "lost the broker" : "cannot connect", problem,
             static_cast<unsigned>(wait));
}

void stopClient(State& state, const char* availability) {
    if (state.client == nullptr) {
        return;
    }
    s_active = false;
    if (state.connected && availability != nullptr) {
        publish(state, state.availability, availability, true, kAtLeastOnce);
        if (!drained(state, nowMs() + kAvailabilityWaitMs)) {
            ESP_LOGW(TAG, "the broker did not confirm the availability update before the board left");
        }
    }
    esp_mqtt_client_stop(state.client);
    esp_mqtt_client_destroy(state.client);
    state.client = nullptr;
    state.context.reset();
    state.connected = false;
    state.waiting = false;
    state.problem = nullptr;
    ++state.generation;
    state.announced.clear();
    ESP_LOGI(TAG, "disconnected from the broker");
}

void forget(State& state) {
    if (state.connected) {
        const int64_t deadline = nowMs() + kLeaveWaitMs;
        const bool removed = removeBeforeLeaving(state, state.settings.prefix, deadline);
        publish(state, state.availability, std::string(), true, kAtLeastOnce);
        if (drained(state, deadline) && removed) {
            ESP_LOGI(TAG, "removed the board's entities from Home Assistant");
        } else {
            ESP_LOGW(TAG,
                     "the broker did not confirm the removal of the board's entities: Home Assistant may keep them");
        }
    }
    stopClient(state, nullptr);
    state.settings.enabled = false;
    wipe(state.settings.password);
    setStatus(false, nullptr);
    xSemaphoreGive(s_forgotten);
}

void flushTallies(State& state, int64_t now) {
    for (const latchkey_util::RefusalCount& refused : state.refusals.due(now)) {
        ESP_LOGW(TAG, "refused %u commands (%s)", static_cast<unsigned>(refused.count), refused.kind.c_str());
        const uint32_t utc = wallclock::synced() ? static_cast<uint32_t>(wallclock::utcSeconds()) : 0;
        audit::append({utc, rpc::Transport::Mqtt, kRefusedMethod, "",
                       refused.kind + " x" + std::to_string(refused.count)});
    }
    for (const latchkey_util::RefusalCount& skipped : state.ignored.due(now)) {
        ESP_LOGW(TAG, "ignored %u %s", static_cast<unsigned>(skipped.count),
                 skipped.kind == kReplayed ? "retained commands: the broker replays them on every connection"
                                           : "commands that were not LOCK or UNLOCK");
    }
}

void handle(State& state, const Item& item) {
    switch (item.kind) {
        case Kind::Event:
            if (state.connected) {
                handleEvent(state, item.text);
            }
            return;
        case Kind::CommandDone:
            state.commanding.erase(item.text);
            state.reconcileAtMs = 0;
            return;
        case Kind::PollDone:
            state.polls.finished(item.text, nowMs(), item.answered);
            state.reconcileAtMs = 0;
            return;
        case Kind::Forget:
            forget(state);
            return;
        case Kind::Command:
        case Kind::StaleConfig:
        case Kind::Connected:
        case Kind::Disconnected:
        case Kind::Refused:
        case Kind::SubscribeFailed:
            break;
    }
    if (item.generation != state.generation || state.client == nullptr) {
        return;
    }
    switch (item.kind) {
        case Kind::Connected:
            handleConnected(state);
            return;
        case Kind::Disconnected:
            handleDisconnected(state);
            return;
        case Kind::Refused:
            ESP_LOGE(TAG, "the broker refused the connection (code %d): check the username and password", item.length);
            state.problem = kRefusedLogin;
            return;
        case Kind::SubscribeFailed:
            if (state.connected) {
                fault(state, kRefusedSubscription);
            }
            return;
        case Kind::Command:
            if (state.connected) {
                handleCommand(state, item);
            }
            return;
        case Kind::StaleConfig:
            if (state.connected) {
                pruneStale(state, item.text);
            }
            return;
        default:
            return;
    }
}

void received(const ClientContext& context, const esp_mqtt_event_t& event) {
    if (event.current_data_offset != 0 || event.topic == nullptr || event.topic_len <= 0 ||
        event.topic_len > kMaxTopic) {
        return;
    }
    const std::string topic(event.topic, event.topic_len);
    Item item;
    item.generation = context.generation;
    if (std::optional<std::string> lock = latchkey_util::haCommandLock(topic, context.board)) {
        item.kind = Kind::Command;
        item.text = std::move(*lock);
        if (event.data != nullptr && event.data_len > 0) {
            item.payload.assign(event.data, std::min(event.data_len, kMaxPayload));
        }
        item.length = event.total_data_len;
        item.retained = event.retain;
    } else if (std::optional<std::string> stale = latchkey_util::haConfigLock(topic, context.prefix, context.board)) {
        if (event.total_data_len == 0 || lock_manager::holds(macOf(*stale))) {
            return;
        }
        item.kind = Kind::StaleConfig;
        item.text = std::move(*stale);
    } else {
        return;
    }
    post(std::move(item));
}

void onClientEvent(void* arg, esp_event_base_t, int32_t id, void* data) {
    const auto& context = *static_cast<const ClientContext*>(arg);
    const auto* event = static_cast<const esp_mqtt_event_t*>(data);
    const uint32_t free = uxTaskGetStackHighWaterMark(nullptr);
    uint32_t low = s_clientStackLow;
    while (free < low && !s_clientStackLow.compare_exchange_weak(low, free)) {
    }
    Item item;
    item.generation = context.generation;
    switch (static_cast<esp_mqtt_event_id_t>(id)) {
        case MQTT_EVENT_CONNECTED:
            item.kind = Kind::Connected;
            break;
        case MQTT_EVENT_DISCONNECTED:
            item.kind = Kind::Disconnected;
            break;
        case MQTT_EVENT_ERROR:
            if (event->error_handle == nullptr ||
                event->error_handle->error_type != MQTT_ERROR_TYPE_CONNECTION_REFUSED) {
                return;
            }
            item.kind = Kind::Refused;
            item.length = static_cast<int>(event->error_handle->connect_return_code);
            break;
        case MQTT_EVENT_SUBSCRIBED:
            if (event->error_handle == nullptr ||
                event->error_handle->error_type != MQTT_ERROR_TYPE_SUBSCRIBE_FAILED) {
                return;
            }
            item.kind = Kind::SubscribeFailed;
            break;
        case MQTT_EVENT_DATA:
            received(context, *event);
            return;
        default:
            return;
    }
    post(std::move(item));
}

void startClient(State& state) {
    ++state.generation;
    state.context = std::make_unique<ClientContext>();
    state.context->generation = state.generation;
    state.context->board = state.board;
    state.context->prefix = state.settings.prefix;
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
    state.client = esp_mqtt_client_init(&config);
    if (state.client == nullptr) {
        ESP_LOGE(TAG, "cannot create the MQTT client");
        state.context.reset();
        state.backoff.disconnected(nowMs());
        return;
    }
    esp_mqtt_client_register_event(state.client, MQTT_EVENT_ANY, onClientEvent, state.context.get());
    if (esp_mqtt_client_start(state.client) != ESP_OK) {
        ESP_LOGE(TAG, "cannot start the MQTT client");
        esp_mqtt_client_destroy(state.client);
        state.client = nullptr;
        state.context.reset();
        state.backoff.disconnected(nowMs());
        return;
    }
    ESP_LOGI(TAG, "connecting to the broker at %s:%u", state.settings.host.c_str(),
             static_cast<unsigned>(state.settings.port));
}

void reconfigure(State& state, const store::cfg::Mqtt& settings) {
    const store::cfg::Mqtt& old = state.settings;
    const bool sameBroker = latchkey_util::keepsPassword({old.host, old.port, old.username},
                                                         {settings.host, settings.port, settings.username});
    const bool samePlace = sameBroker && old.prefix == settings.prefix;
    if (state.connected && !samePlace) {
        if (removeBeforeLeaving(state, old.prefix, nowMs() + kLeaveWaitMs)) {
            ESP_LOGI(TAG, "removed the board's entities under the previous broker or prefix");
        } else {
            ESP_LOGW(TAG, "the broker did not confirm the removal of the board's entities under the previous broker or "
                          "prefix: they may stay there");
        }
    }
    stopClient(state, sameBroker ? latchkey_util::kHaOffline : "");
    wipe(state.settings.password);
    state.settings = settings;
    if (!state.settings.enabled) {
        wipe(state.settings.password);
        ESP_LOGI(TAG, "MQTT is off");
    }
    state.backoff.reset();
    setStatus(false, nullptr);
}

void maintain(State& state) {
    const int64_t now = nowMs();
    flushTallies(state, now);
    if (!state.settings.enabled) {
        return;
    }
    if (state.connected) {
        if (now >= state.reconcileAtMs) {
            reconcile(state);
            state.reconcileAtMs = now + kReconcileMs;
        }
        if (state.connected) {
            startPoll(state, now);
        }
        return;
    }
    if (state.backoff.retryAfterSeconds(now) > 0 || wifi::address() == 0) {
        return;
    }
    if (state.client == nullptr) {
        startClient(state);
        return;
    }
    if (state.waiting) {
        state.waiting = esp_mqtt_client_reconnect(state.client) != ESP_OK;
    }
}

void run(void*) {
    State state;
    state.board = boardId();
    state.availability = "latchkey/" + state.board + "/availability";
    while (true) {
        ulTaskNotifyTake(pdTRUE, kTick);
        if (std::optional<store::cfg::Mqtt> settings = takePending()) {
            reconfigure(state, *settings);
            wipe(settings->password);
        }
        for (const Item& item : takeInbox(state)) {
            handle(state, item);
        }
        maintain(state);
    }
}

bool launch() {
    if (s_task != nullptr) {
        return true;
    }
    if (s_forgotten == nullptr) {
        s_forgotten = xSemaphoreCreateBinary();
    }
    if (s_forgotten == nullptr || xTaskCreate(run, "mqtt", kTaskStack, nullptr, kTaskPriority, &s_task) != pdPASS) {
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
            s_pending.reset();
        }
        if (!settings.enabled && s_task == nullptr) return true;
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

bool forgetAll() {
    {
        std::lock_guard<std::mutex> guard(s_mutex);
        if (s_task == nullptr) {
            return true;
        }
        xSemaphoreTake(s_forgotten, 0);
    }
    Item item;
    item.kind = Kind::Forget;
    post(std::move(item));
    return xSemaphoreTake(s_forgotten, kForgetWait) == pdTRUE;
}

Status status() {
    std::lock_guard<std::mutex> guard(s_mutex);
    return s_status;
}

uint32_t stackFree() {
    std::lock_guard<std::mutex> guard(s_mutex);
    return s_task != nullptr ? uxTaskGetStackHighWaterMark(s_task) : 0;
}

uint32_t clientStackFree() {
    const uint32_t low = s_clientStackLow;
    return low == UINT32_MAX ? 0 : low;
}

}
