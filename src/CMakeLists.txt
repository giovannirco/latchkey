# SPDX-License-Identifier: GPL-3.0-or-later
idf_component_register(
    SRCS
        "access_requests.cpp"
        "audit.cpp"
        "auth.cpp"
        "ble_central.cpp"
        "board.cpp"
        "certs.cpp"
        "clock.cpp"
        "console.cpp"
        "events.cpp"
        "hmac.cpp"
        "http.cpp"
        "jobs.cpp"
        "lock_manager.cpp"
        "main.cpp"
        "methods_admin_passcode.cpp"
        "methods_auth.cpp"
        "methods_credentials.cpp"
        "methods_locks.cpp"
        "methods_passcodes.cpp"
        "methods_system.cpp"
        "ota.cpp"
        "rpc.cpp"
        "store.cpp"
        "wifi.cpp"
        "ws.cpp"
    INCLUDE_DIRS "."
    PRIV_REQUIRES
        app_update
        bt
        esp_app_format
        esp_driver_gpio
        esp_driver_uart
        esp_driver_usb_serial_jtag
        esp_event
        esp_http_server
        esp_https_server
        esp_netif
        esp_timer
        esp_wifi
        latchkey_util
        lwip
        mbedtls
        nvs_flash
        ttlock
        vfs
)

target_add_binary_data(${COMPONENT_LIB} "${CMAKE_BINARY_DIR}/web/index.html.gz" BINARY)
target_add_binary_data(${COMPONENT_LIB} "${CMAKE_BINARY_DIR}/web/index.html.gz.csp.txt" TEXT)
