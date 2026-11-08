// SPDX-License-Identifier: GPL-3.0-or-later
#include <cstdlib>

#include "esp_app_desc.h"
#include "esp_event.h"
#include "esp_idf_version.h"
#include "esp_log.h"
#include "esp_netif.h"
#include "psa/crypto.h"
#include "sdkconfig.h"

#include "audit.h"
#include "auth.h"
#include "ble_central.h"
#include "board.h"
#include "certs.h"
#include "clock.h"
#include "console.h"
#include "http.h"
#include "jobs.h"
#include "lock_manager.h"
#include "methods.h"
#include "store.h"
#include "wifi.h"

namespace {

constexpr const char* TAG = "latchkey";

}

extern "C" void app_main() {
    console::begin();
    esp_log_write(ESP_LOG_INFO, TAG, "latchkey %s board=%s chip=%s idf=%s\n", esp_app_get_description()->version,
                  board::name(), CONFIG_IDF_TARGET, esp_get_idf_version());
    if (psa_crypto_init() != PSA_SUCCESS) {
        ESP_LOGE(TAG, "PSA crypto init failed");
        abort();
    }
    store::init();
    audit::init();
    auth::init();
    certs::init();
    board::init();
    ESP_ERROR_CHECK(esp_netif_init());
    ESP_ERROR_CHECK(esp_event_loop_create_default());
    wallclock::init();
    store::cfg::Wifi config;
    const bool configured = store::cfg::loadWifi(config);
    wifi::start(configured ? &config : nullptr);
    ble::init();
    lock_manager::start();
    methods::registerSystem();
    methods::registerAuth();
    methods::registerLocks();
    jobs::start();
    http::start();
    console::start();
}
