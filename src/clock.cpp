// SPDX-License-Identifier: GPL-3.0-or-later
#include "clock.h"

#include <atomic>
#include <sys/time.h>

#include "esp_event.h"
#include "esp_log.h"
#include "esp_netif_sntp.h"

namespace wallclock {

namespace {

constexpr const char* TAG = "clock";

std::atomic<bool> s_synced{false};

void onSntpSync(struct timeval* tv) {
    s_synced = true;
    ESP_LOGI(TAG, "SNTP synced, utc %lld", static_cast<long long>(tv->tv_sec));
}

void onGotIp(void*, esp_event_base_t, int32_t, void*) {
    const esp_err_t error = esp_netif_sntp_start();
    if (error != ESP_OK) {
        ESP_LOGE(TAG, "SNTP start: %s", esp_err_to_name(error));
    }
}

}

void init() {
    esp_sntp_config_t config =
        ESP_NETIF_SNTP_DEFAULT_CONFIG_MULTIPLE(2, ESP_SNTP_SERVER_LIST("pool.ntp.org", "time.cloudflare.com"));
    config.start = false;
    config.wait_for_sync = false;
    config.sync_cb = onSntpSync;
    ESP_ERROR_CHECK(esp_netif_sntp_init(&config));
    ESP_ERROR_CHECK(esp_event_handler_register(IP_EVENT, IP_EVENT_STA_GOT_IP, onGotIp, nullptr));
}

bool synced() { return s_synced; }

int64_t utcSeconds() {
    struct timeval now {};
    gettimeofday(&now, nullptr);
    return now.tv_sec;
}

bool set(int64_t utc) {
    if (utc < kMinUtc || utc > kMaxUtc) {
        return false;
    }
    const struct timeval now = {static_cast<time_t>(utc), 0};
    if (settimeofday(&now, nullptr) != 0) {
        return false;
    }
    s_synced = true;
    ESP_LOGI(TAG, "clock set over serial, utc %lld", static_cast<long long>(utc));
    return true;
}

}
