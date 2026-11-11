// SPDX-License-Identifier: GPL-3.0-or-later
#include "latchkey_util/key_restore.h"
#include "rpc_test_runtime.h"
#include "store_test_runtime.h"
#include "../../src/methods_system.cpp"

static std::optional<uint32_t> serverWatermark;
static bool taskStarts;
static bool passwordHashes;
static size_t wifiPasswordWipes;
static size_t ownerWipes;

const esp_app_desc_t* esp_app_get_description() { static const esp_app_desc_t desc{"fixture"}; return &desc; }
const char* esp_get_idf_version() { return "fixture"; }
int64_t esp_timer_get_time() { return 0; }
esp_err_t esp_timer_create(const esp_timer_create_args_t*, esp_timer_handle_t* timer) { *timer = nullptr; return ESP_OK; }
esp_err_t esp_timer_start_once(esp_timer_handle_t, uint64_t) { return ESP_OK; }
esp_err_t esp_timer_stop(esp_timer_handle_t) { return ESP_OK; }
void esp_restart() {}
uint32_t esp_get_free_heap_size() { return 65536; }
uint32_t esp_get_minimum_free_heap_size() { return 32768; }
size_t heap_caps_get_largest_free_block(uint32_t) { return 16384; }
void esp_log_level_set(const char*, esp_log_level_t) {}
TaskHandle_t xTaskGetHandle(const char*) { return nullptr; }
uint32_t uxTaskGetStackHighWaterMark(TaskHandle_t) { return 2048; }
void vTaskDelay(TickType_t) {}
void vTaskDelete(TaskHandle_t) {}
BaseType_t xTaskCreate(void (*)(void*), const char*, uint32_t, void*, UBaseType_t, TaskHandle_t* handle) {
    *handle = taskStarts ? reinterpret_cast<void*>(1) : nullptr;
    return taskStarts ? pdPASS : 0;
}
namespace auth { bool hashPassword(std::string_view, latchkey_util::PasswordRecord&) { return passwordHashes; } }
namespace audit {
Page list(uint32_t, size_t) { return {}; }
cJSON* toJson(const StoredEntry&) { return cJSON_CreateObject(); }
esp_err_t clear() { return ESP_OK; }
}
namespace board {
const char* name() { return "fixture"; }
int buttonGpio() { return 0; }
bool buttonPressed() { return false; }
uint32_t buttonPresses() { return 0; }
}
namespace ble { Stats stats() { return {}; } }
namespace certs { std::optional<std::string> fingerprint() { return std::nullopt; } }
namespace console { void flush() {} }
namespace http {
std::optional<uint32_t> serverStackFree() { return serverWatermark; }
uint32_t workerStackFree() { return 2048; }
}
namespace jobs { uint32_t stackFree() { return 2048; } }
namespace lock_manager {
uint32_t workerStackFree() { return 2048; }
cJSON* warnings() { return cJSON_CreateArray(); }
esp_err_t checkEraseAll() { return ESP_OK; }
esp_err_t storedCount(size_t& out) { out = 0; return ESP_OK; }
esp_err_t eraseAll() { return ESP_OK; }
void cancelErase() {}
}
namespace mqtt {
uint32_t stackFree() { return 0; }
uint32_t clientStackFree() { return 0; }
bool forgetAll() { return true; }
}
namespace syslog_client { uint32_t stackFree() { return 0; } }
namespace wifi {
Status status() { return {}; }
esp_err_t apply(const store::cfg::Wifi&) { return ESP_OK; }
}
namespace wallclock {
std::string timezone() { return "UTC0"; }
int32_t utcOffsetAt(int64_t) { return 0; }
int32_t utcOffsetSeconds() { return 0; }
esp_err_t setTimezone(std::string_view) { return ESP_OK; }
bool set(int64_t) { return true; }
}
namespace methods { void addLoggingInfo(cJSON*) {} }

void setUp() {
    resetRpcFixture();
    resetNvsFixture();
    serverWatermark.reset();
    taskStarts = true;
    passwordHashes = true;
    methods::s_pendingWifi = {};
    methods::s_wifiSwitch = nullptr;
    wifiPasswordWipes = 0;
    ownerWipes = 0;
    zeroize_fixture::observe = [](void* data, size_t length) {
        if (length == 12 && std::memcmp(data, "fixture-pass", length) == 0) ++wifiPasswordWipes;
        if (length == sizeof(store::auth::Owner) && static_cast<store::auth::Owner*>(data)->totpSecret[0] == 1) ++ownerWipes;
    };
}
void tearDown() { zeroize_fixture::observe = nullptr; clearRpcFixture(); clearNvsFixture(); }

static rpc::Json wifiParams() {
    return rpc::Json(cJSON_Parse(R"({"ssid":"fixture","password":"fixture-pass","ip":"192.0.2.10",
        "gateway":"192.0.2.1","netmask":"255.255.255.0","dns":"192.0.2.53"})"));
}

static void test_wifi_validation_wipes_its_local_password_on_success_and_failure() {
    for (bool valid : {true, false}) {
        auto params = wifiParams();
        if (!valid) cJSON_DeleteItemFromObjectCaseSensitive(params.get(), "gateway");
        store::cfg::Wifi settings;
        wifiPasswordWipes = 0;
        TEST_ASSERT_EQUAL_INT(valid, methods::readWifi(params.get(), settings));
        TEST_ASSERT_EQUAL_UINT(1, wifiPasswordWipes);
        if (valid) TEST_ASSERT_TRUE(settings.password == "fixture-pass");
    }
}

static void test_wifi_task_start_failure_drops_pending_password() {
    taskStarts = false;
    auto params = wifiParams();
    const auto reply = methods::wifiSet(params.get(), {});
    TEST_ASSERT_EQUAL_STRING("internal", reply.error.c_str());
    TEST_ASSERT_TRUE(methods::s_pendingWifi.password.empty());
}

static void test_claiming_wipes_wifi_password_after_applying_configuration() {
    auto wifi = wifiParams();
    rpc::Json params(cJSON_CreateObject());
    cJSON_AddItemToObject(params.get(), "wifi", wifi.release());
    cJSON_AddStringToObject(params.get(), "password", "owner-fixture-pass");
    const auto reply = methods::setup(params.get(), {});
    TEST_ASSERT_TRUE(reply.error.empty());
    TEST_ASSERT_EQUAL_UINT(2, wifiPasswordWipes);
}

static void test_claiming_wipes_wifi_password_when_owner_validation_or_hashing_fails() {
    for (bool validPassword : {false, true}) {
        auto wifi = wifiParams();
        rpc::Json params(cJSON_CreateObject());
        cJSON_AddItemToObject(params.get(), "wifi", wifi.release());
        cJSON_AddStringToObject(params.get(), "password", validPassword ? "owner-fixture-pass" : "short");
        passwordHashes = false;
        wifiPasswordWipes = 0;
        const auto reply = methods::setup(params.get(), {});
        TEST_ASSERT_FALSE(reply.error.empty());
        TEST_ASSERT_EQUAL_UINT(2, wifiPasswordWipes);
        TEST_ASSERT_EQUAL_UINT(validPassword ? 1 : 0, ownerWipes);
    }
}

static void test_https_stack_watermark_reports_null_until_observed_and_preserves_zero() {
    for (auto watermark : {std::optional<uint32_t>{}, std::optional<uint32_t>{0}, std::optional<uint32_t>{4096}}) {
        serverWatermark = watermark;
        const auto response = dispatchRequest(request(R"({"method":"system.info"})"), rpc::Transport::Serial, {});
        rpc::Json body(cJSON_Parse(response.json.c_str()));
        const auto* result = cJSON_GetObjectItemCaseSensitive(body.get(), "result");
        const auto* stacks = cJSON_GetObjectItemCaseSensitive(result, "stackFree");
        const auto* value = cJSON_GetObjectItemCaseSensitive(stacks, "httpsServer");
        if (!watermark) TEST_ASSERT_TRUE(cJSON_IsNull(value));
        else {
            TEST_ASSERT_TRUE(cJSON_IsNumber(value));
            TEST_ASSERT_EQUAL_UINT(*watermark, value->valuedouble);
        }
    }
}

int main() {
    rpc::init();
    methods::registerSystem();
    UNITY_BEGIN();
    RUN_TEST(test_https_stack_watermark_reports_null_until_observed_and_preserves_zero);
    RUN_TEST(test_wifi_validation_wipes_its_local_password_on_success_and_failure);
    RUN_TEST(test_wifi_task_start_failure_drops_pending_password);
    RUN_TEST(test_claiming_wipes_wifi_password_after_applying_configuration);
    RUN_TEST(test_claiming_wipes_wifi_password_when_owner_validation_or_hashing_fails);
    return UNITY_END();
}
