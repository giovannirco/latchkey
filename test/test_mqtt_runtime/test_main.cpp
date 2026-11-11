// SPDX-License-Identifier: GPL-3.0-or-later
#include "latchkey_util/ha_discovery.h"
#include "rpc_test_runtime.h"
#include "../../src/mqtt.cpp"

static bool taskStarts;
static size_t publications;
static bool publishSucceeds;
static StaticSemaphore_t semaphore;

int64_t esp_timer_get_time() { return 0; }
void vTaskDelay(TickType_t) {}
uint32_t uxTaskGetStackHighWaterMark(TaskHandle_t) { return 2048; }
void xTaskNotifyGive(TaskHandle_t) {}
uint32_t ulTaskNotifyTake(BaseType_t, TickType_t) { return 0; }
BaseType_t xTaskCreate(void (*)(void*), const char*, uint32_t, void*, UBaseType_t, TaskHandle_t* task) {
    *task = taskStarts ? reinterpret_cast<void*>(1) : nullptr;
    return taskStarts ? pdPASS : 0;
}
SemaphoreHandle_t xSemaphoreCreateBinary() { return &semaphore; }
BaseType_t xSemaphoreGive(SemaphoreHandle_t) { return pdTRUE; }
BaseType_t xSemaphoreTake(SemaphoreHandle_t, TickType_t) { return pdTRUE; }
const esp_app_desc_t* esp_app_get_description() { static const esp_app_desc_t desc{"fixture"}; return &desc; }
esp_err_t esp_read_mac(uint8_t* mac, int) { std::memset(mac, 0, 6); return ESP_OK; }
int esp_mqtt_client_publish(esp_mqtt_client_handle_t, const char*, const char*, int, int, int) {
    ++publications;
    return publishSucceeds ? 1 : -1;
}
int esp_mqtt_client_subscribe_single(esp_mqtt_client_handle_t, const char*, int) { return 1; }
int esp_mqtt_client_unsubscribe(esp_mqtt_client_handle_t, const char*) { return 1; }
int esp_mqtt_client_get_outbox_size(esp_mqtt_client_handle_t) { return 0; }
esp_err_t esp_mqtt_client_disconnect(esp_mqtt_client_handle_t) { return ESP_OK; }
esp_err_t esp_mqtt_client_stop(esp_mqtt_client_handle_t) { return ESP_OK; }
esp_err_t esp_mqtt_client_destroy(esp_mqtt_client_handle_t) { return ESP_OK; }
esp_err_t esp_mqtt_client_reconnect(esp_mqtt_client_handle_t) { return ESP_OK; }
esp_err_t esp_mqtt_client_start(esp_mqtt_client_handle_t) { return ESP_OK; }
esp_mqtt_client_handle_t esp_mqtt_client_init(const esp_mqtt_client_config_t*) { return reinterpret_cast<void*>(1); }
esp_err_t esp_mqtt_client_register_event(esp_mqtt_client_handle_t, esp_mqtt_event_id_t,
                                      void (*)(void*, esp_event_base_t, int32_t, void*), void*) { return ESP_OK; }
namespace wifi { uint32_t address() { return 0; } }
namespace store::cfg { esp_err_t loadMqtt(Mqtt&) { return ESP_OK; } }
namespace lock_manager {
bool holds(const std::string&) { return false; }
rpc::Reply list() { return rpc::ok(); }
rpc::Reply info(const std::string&) { return rpc::ok(); }
rpc::Reply status(const std::string&) { return rpc::ok(); }
rpc::Reply unlock(const std::string&) { return rpc::ok(); }
rpc::Reply lock(const std::string&) { return rpc::ok(); }
}

void setUp() {
    resetRpcFixture();
    mqtt::s_pending.reset();
    mqtt::s_task = nullptr;
    mqtt::s_forgotten = nullptr;
    taskStarts = publishSucceeds = true;
    publications = 0;
}
void tearDown() { mqtt::s_pending.reset(); clearRpcFixture(); }

static void test_disabled_mqtt_without_a_task_retains_no_pending_password() {
    store::cfg::Mqtt settings;
    settings.password = "fixture-pass";
    TEST_ASSERT_TRUE(mqtt::apply(settings));
    TEST_ASSERT_NULL(mqtt::s_task);
    TEST_ASSERT_FALSE(mqtt::s_pending.has_value());
}

static void test_failed_task_start_drops_pending_settings() {
    store::cfg::Mqtt settings;
    settings.enabled = true;
    settings.password = "fixture-pass";
    taskStarts = false;
    TEST_ASSERT_FALSE(mqtt::apply(settings));
    TEST_ASSERT_FALSE(mqtt::s_pending.has_value());
}

static void test_running_task_receives_disable_without_retaining_password() {
    mqtt::s_task = reinterpret_cast<void*>(1);
    store::cfg::Mqtt settings;
    settings.password = "fixture-pass";
    TEST_ASSERT_TRUE(mqtt::apply(settings));
    auto pending = mqtt::takePending();
    TEST_ASSERT_TRUE(pending.has_value());
    mqtt::State state;
    mqtt::reconfigure(state, *pending);
    TEST_ASSERT_TRUE(state.settings.password.empty());
    TEST_ASSERT_FALSE(mqtt::s_pending.has_value());
}

static void test_stale_discovery_ids_have_a_bounded_deduplication_cache() {
    mqtt::State state;
    state.board = "00005e005300";
    for (unsigned id = 0; id < 1024; ++id) {
        char text[13];
        std::snprintf(text, sizeof(text), "00005e00%04x", id);
        mqtt::pruneStale(state, text);
    }
    TEST_ASSERT_GREATER_THAN(0, publications);
    TEST_ASSERT_LESS_OR_EQUAL_UINT(32, state.pruned.size());
    const size_t before = publications;
    mqtt::pruneStale(state, "00005e0003ff");
    TEST_ASSERT_EQUAL_UINT(before, publications);
}

static void test_failed_stale_removal_remains_retryable() {
    mqtt::State state;
    state.board = "00005e005300";
    publishSucceeds = false;
    mqtt::pruneStale(state, "00005e005309");
    TEST_ASSERT_TRUE(state.pruned.empty());
    publishSucceeds = true;
    mqtt::pruneStale(state, "00005e005309");
    TEST_ASSERT_EQUAL_UINT(1, state.pruned.size());
}

int main() {
    rpc::init();
    UNITY_BEGIN();
    RUN_TEST(test_disabled_mqtt_without_a_task_retains_no_pending_password);
    RUN_TEST(test_failed_task_start_drops_pending_settings);
    RUN_TEST(test_running_task_receives_disable_without_retaining_password);
    RUN_TEST(test_stale_discovery_ids_have_a_bounded_deduplication_cache);
    RUN_TEST(test_failed_stale_removal_remains_retryable);
    return UNITY_END();
}
