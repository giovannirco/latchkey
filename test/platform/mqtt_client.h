// SPDX-License-Identifier: GPL-3.0-or-later
#pragma once
#include <cstdint>
#include "esp_err.h"

using esp_mqtt_client_handle_t = void*;
using esp_event_base_t = const char*;
enum esp_mqtt_event_id_t {
    MQTT_EVENT_ANY, MQTT_EVENT_CONNECTED, MQTT_EVENT_DISCONNECTED, MQTT_EVENT_ERROR,
    MQTT_EVENT_SUBSCRIBED, MQTT_EVENT_DATA,
};
inline constexpr int MQTT_ERROR_TYPE_CONNECTION_REFUSED = 1;
inline constexpr int MQTT_ERROR_TYPE_SUBSCRIBE_FAILED = 2;
inline constexpr int MQTT_TRANSPORT_OVER_TCP = 1;
struct esp_mqtt_error_codes_t { int error_type; int connect_return_code; };
struct esp_mqtt_event_t {
    int current_data_offset = 0;
    const char* topic = nullptr;
    int topic_len = 0;
    const char* data = nullptr;
    int data_len = 0;
    int total_data_len = 0;
    bool retain = false;
    esp_mqtt_error_codes_t* error_handle = nullptr;
};
struct esp_mqtt_client_config_t {
    struct { struct { const char* hostname; int port; int transport; } address; } broker;
    struct {
        const char* client_id;
        const char* username;
        struct { const char* password; } authentication;
    } credentials;
    struct {
        struct { const char* topic; const char* msg; int qos; int retain; } last_will;
        int keepalive;
    } session;
    struct { bool disable_auto_reconnect; int timeout_ms; } network;
    struct { int stack_size; int priority; } task;
    struct { int size; } buffer;
    struct { uint64_t limit; } outbox;
};
int esp_mqtt_client_publish(esp_mqtt_client_handle_t, const char*, const char*, int, int, int);
int esp_mqtt_client_subscribe_single(esp_mqtt_client_handle_t, const char*, int);
int esp_mqtt_client_unsubscribe(esp_mqtt_client_handle_t, const char*);
int esp_mqtt_client_get_outbox_size(esp_mqtt_client_handle_t);
esp_err_t esp_mqtt_client_disconnect(esp_mqtt_client_handle_t);
esp_err_t esp_mqtt_client_stop(esp_mqtt_client_handle_t);
esp_err_t esp_mqtt_client_destroy(esp_mqtt_client_handle_t);
esp_err_t esp_mqtt_client_reconnect(esp_mqtt_client_handle_t);
esp_err_t esp_mqtt_client_start(esp_mqtt_client_handle_t);
esp_mqtt_client_handle_t esp_mqtt_client_init(const esp_mqtt_client_config_t*);
esp_err_t esp_mqtt_client_register_event(esp_mqtt_client_handle_t, esp_mqtt_event_id_t,
                                      void (*)(void*, esp_event_base_t, int32_t, void*), void*);
