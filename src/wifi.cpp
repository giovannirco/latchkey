// SPDX-License-Identifier: GPL-3.0-or-later
#include "wifi.h"

#include <algorithm>
#include <atomic>
#include <cstring>
#include <mutex>

#include "esp_event.h"
#include "esp_log.h"
#include "esp_netif.h"
#include "esp_timer.h"
#include "esp_wifi.h"
#include "lwip/inet.h"

namespace wifi {

namespace {

constexpr const char* TAG = "wifi";
constexpr uint32_t kFirstRetryMs = 1000;
constexpr uint32_t kMaxRetryMs = 30000;

esp_netif_t* s_netif = nullptr;
esp_timer_handle_t s_retryTimer = nullptr;
std::mutex s_mutex;
std::mutex s_applyMutex;
std::string s_ssid;
bool s_configured = false;
std::atomic<bool> s_running{false};
std::atomic<bool> s_connected{false};
std::atomic<uint32_t> s_retryMs{kFirstRetryMs};

bool configured() {
    std::lock_guard<std::mutex> lock(s_mutex);
    return s_configured;
}

void connect() {
    const esp_err_t error = esp_wifi_connect();
    if (error != ESP_OK) {
        ESP_LOGW(TAG, "connect: %s", esp_err_to_name(error));
    }
}

void onRetry(void*) { connect(); }

void scheduleRetry() {
    const uint32_t delayMs = s_retryMs;
    s_retryMs = std::min(delayMs * 2, kMaxRetryMs);
    esp_timer_stop(s_retryTimer);
    const esp_err_t error = esp_timer_start_once(s_retryTimer, static_cast<uint64_t>(delayMs) * 1000);
    if (error != ESP_OK) {
        ESP_LOGE(TAG, "retry timer: %s", esp_err_to_name(error));
    }
}

void onWifiEvent(void*, esp_event_base_t, int32_t id, void* data) {
    if (id == WIFI_EVENT_STA_START) {
        s_running = true;
        s_retryMs = kFirstRetryMs;
        if (configured()) {
            connect();
        }
    } else if (id == WIFI_EVENT_STA_STOP) {
        s_running = false;
        s_connected = false;
        esp_timer_stop(s_retryTimer);
    } else if (id == WIFI_EVENT_STA_DISCONNECTED) {
        s_connected = false;
        const auto* event = static_cast<const wifi_event_sta_disconnected_t*>(data);
        ESP_LOGW(TAG, "disconnected, reason %d", event->reason);
        if (s_running && configured()) {
            scheduleRetry();
        }
    }
}

void onGotIp(void*, esp_event_base_t, int32_t, void* data) {
    const auto* event = static_cast<const ip_event_got_ip_t*>(data);
    s_connected = true;
    s_retryMs = kFirstRetryMs;
    ESP_LOGI(TAG, "connected, ip " IPSTR, IP2STR(&event->ip_info.ip));
}

esp_err_t configureInterface(const store::cfg::Wifi& config) {
    const esp_err_t stopped = esp_netif_dhcpc_stop(s_netif);
    if (stopped != ESP_OK && stopped != ESP_ERR_ESP_NETIF_DHCP_ALREADY_STOPPED) {
        return stopped;
    }
    esp_netif_ip_info_t ip{};
    ip.ip.addr = htonl(config.ip);
    ip.gw.addr = htonl(config.gateway);
    ip.netmask.addr = htonl(config.netmask);
    esp_err_t error = esp_netif_set_ip_info(s_netif, &ip);
    if (error != ESP_OK) {
        return error;
    }
    esp_netif_dns_info_t dns{};
    dns.ip.type = ESP_IPADDR_TYPE_V4;
    dns.ip.u_addr.ip4.addr = htonl(config.dns);
    error = esp_netif_set_dns_info(s_netif, ESP_NETIF_DNS_MAIN, &dns);
    if (error != ESP_OK) {
        return error;
    }
    wifi_config_t station{};
    std::memcpy(station.sta.ssid, config.ssid.data(), std::min(config.ssid.size(), sizeof(station.sta.ssid)));
    std::memcpy(station.sta.password, config.password.data(),
                std::min(config.password.size(), sizeof(station.sta.password)));
    station.sta.threshold.authmode = config.password.empty() ? WIFI_AUTH_OPEN : WIFI_AUTH_WPA2_PSK;
    return esp_wifi_set_config(WIFI_IF_STA, &station);
}

void remember(const store::cfg::Wifi& config) {
    std::lock_guard<std::mutex> lock(s_mutex);
    s_ssid = config.ssid;
    s_configured = true;
}

}

void start(const store::cfg::Wifi* config) {
    s_netif = esp_netif_create_default_wifi_sta();
    const wifi_init_config_t init = WIFI_INIT_CONFIG_DEFAULT();
    ESP_ERROR_CHECK(esp_wifi_init(&init));
    ESP_ERROR_CHECK(esp_wifi_set_storage(WIFI_STORAGE_RAM));
    ESP_ERROR_CHECK(esp_event_handler_register(WIFI_EVENT, ESP_EVENT_ANY_ID, onWifiEvent, nullptr));
    ESP_ERROR_CHECK(esp_event_handler_register(IP_EVENT, IP_EVENT_STA_GOT_IP, onGotIp, nullptr));
    const esp_timer_create_args_t retry = {
        .callback = onRetry,
        .arg = nullptr,
        .dispatch_method = ESP_TIMER_TASK,
        .name = "wifi_retry",
        .skip_unhandled_events = true,
    };
    ESP_ERROR_CHECK(esp_timer_create(&retry, &s_retryTimer));
    ESP_ERROR_CHECK(esp_wifi_set_mode(WIFI_MODE_STA));
    if (config != nullptr) {
        const esp_err_t error = configureInterface(*config);
        if (error == ESP_OK) {
            remember(*config);
        } else {
            ESP_LOGE(TAG, "stored config not applied: %s", esp_err_to_name(error));
        }
    }
    ESP_ERROR_CHECK(esp_wifi_start());
}

esp_err_t apply(const store::cfg::Wifi& config) {
    std::lock_guard<std::mutex> lock(s_applyMutex);
    esp_err_t error = esp_wifi_stop();
    if (error == ESP_OK) {
        error = configureInterface(config);
    }
    if (error == ESP_OK) {
        remember(config);
    }
    const esp_err_t started = esp_wifi_start();
    if (error == ESP_OK) {
        error = started;
    }
    if (error != ESP_OK) {
        ESP_LOGE(TAG, "apply: %s", esp_err_to_name(error));
    }
    return error;
}

uint32_t address() {
    esp_netif_ip_info_t ip{};
    return s_connected && esp_netif_get_ip_info(s_netif, &ip) == ESP_OK ? ntohl(ip.ip.addr) : 0;
}

Status status() {
    Status result;
    {
        std::lock_guard<std::mutex> lock(s_mutex);
        result.configured = s_configured;
        result.ssid = s_ssid;
    }
    result.connected = s_connected;
    if (!result.connected) {
        return result;
    }
    esp_netif_ip_info_t ip{};
    if (esp_netif_get_ip_info(s_netif, &ip) == ESP_OK) {
        result.ip = ntohl(ip.ip.addr);
    }
    wifi_ap_record_t ap{};
    if (esp_wifi_sta_get_ap_info(&ap) == ESP_OK) {
        result.rssi = ap.rssi;
    }
    return result;
}

}
