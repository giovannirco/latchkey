// SPDX-License-Identifier: GPL-3.0-or-later
#include "console.h"

#include <algorithm>
#include <cstdarg>
#include <cstdint>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <mutex>
#include <string>

#include "esp_log.h"
#include "freertos/FreeRTOS.h"
#include "freertos/task.h"
#include "sdkconfig.h"

#include "events.h"
#include "latchkey_util/line_buffer.h"
#include "rpc.h"

#if CONFIG_ESP_CONSOLE_UART
#include "driver/uart.h"
#include "driver/uart_vfs.h"
#elif CONFIG_ESP_CONSOLE_USB_SERIAL_JTAG
#include "driver/usb_serial_jtag.h"
#include "driver/usb_serial_jtag_vfs.h"
#else
#error "the console needs UART or USB-Serial/JTAG"
#endif

namespace console {

namespace {

constexpr size_t kMaxRequest = 2048;
constexpr size_t kReadChunk = 256;
constexpr size_t kLogLine = 256;
constexpr uint32_t kRxBuffer = 2048;
constexpr uint32_t kTxBuffer = 2048;
constexpr uint32_t kTaskStack = 8192;
constexpr UBaseType_t kTaskPriority = 5;
constexpr TickType_t kFlushTimeout = pdMS_TO_TICKS(200);

std::recursive_mutex s_output;
bool s_atLineStart = true;

#if CONFIG_ESP_CONSOLE_UART
constexpr uart_port_t kPort = static_cast<uart_port_t>(CONFIG_ESP_CONSOLE_UART_NUM);

void installDriver() {
    ESP_ERROR_CHECK(uart_driver_install(kPort, kRxBuffer, kTxBuffer, 0, nullptr, 0));
    uart_vfs_dev_use_driver(kPort);
}

size_t readSome(uint8_t* buffer, size_t capacity) {
    const int first = uart_read_bytes(kPort, buffer, 1, portMAX_DELAY);
    if (first <= 0) {
        return 0;
    }
    size_t waiting = 0;
    uart_get_buffered_data_len(kPort, &waiting);
    const size_t more = std::min(waiting, capacity - 1);
    const int rest = more > 0 ? uart_read_bytes(kPort, buffer + 1, more, 0) : 0;
    return 1 + static_cast<size_t>(std::max(rest, 0));
}

void waitTxDone() { uart_wait_tx_done(kPort, kFlushTimeout); }
#else
void installDriver() {
    usb_serial_jtag_driver_config_t config = {.tx_buffer_size = kTxBuffer, .rx_buffer_size = kRxBuffer};
    ESP_ERROR_CHECK(usb_serial_jtag_driver_install(&config));
    usb_serial_jtag_vfs_use_driver();
}

size_t readSome(uint8_t* buffer, size_t capacity) {
    const int count = usb_serial_jtag_read_bytes(buffer, capacity, portMAX_DELAY);
    return count > 0 ? static_cast<size_t>(count) : 0;
}

void waitTxDone() { usb_serial_jtag_wait_tx_done(kFlushTimeout); }
#endif

void writeLocked(const char* data, size_t length) {
    if (length == 0) {
        return;
    }
    fwrite(data, 1, length, stdout);
    s_atLineStart = data[length - 1] == '\n';
}

void writePrefixed(const char* text, size_t length) {
    size_t start = 0;
    while (start < length) {
        if (s_atLineStart) {
            writeLocked("# ", 2);
        }
        const auto* newline = static_cast<const char*>(std::memchr(text + start, '\n', length - start));
        const size_t end = newline != nullptr ? static_cast<size_t>(newline - text) + 1 : length;
        writeLocked(text + start, end - start);
        start = end;
    }
}

void flushLocked() {
    fflush(stdout);
    clearerr(stdout);
}

int logToConsole(const char* format, va_list args) {
    char text[kLogLine];
    const int formatted = vsnprintf(text, sizeof(text), format, args);
    if (formatted <= 0) {
        return formatted;
    }
    const size_t length = std::min(static_cast<size_t>(formatted), sizeof(text) - 1);
    std::lock_guard<std::recursive_mutex> lock(s_output);
    writePrefixed(text, length);
    if (static_cast<size_t>(formatted) > length && !s_atLineStart) {
        writeLocked("\n", 1);
    }
    flushLocked();
    return formatted;
}

void serveRequests(void*) {
    latchkey_util::LineBuffer lines(
        kMaxRequest,
        [](std::string_view line) {
            const std::string request(line);
            writeLine(rpc::dispatch(request.c_str(), rpc::Transport::Serial, {}).json);
        },
        []() { writeLine(rpc::errorLine("bad_request", "request line too long")); });
    uint8_t chunk[kReadChunk];
    while (true) {
        const size_t count = readSome(chunk, sizeof(chunk));
        lines.feed(reinterpret_cast<const char*>(chunk), count);
    }
}

}

void begin() {
    installDriver();
    esp_log_set_vprintf(logToConsole);
}

void start() {
    events::addSink([](const std::string& line) { writeLine(line); });
    const BaseType_t created = xTaskCreate(serveRequests, "console", kTaskStack, nullptr, kTaskPriority, nullptr);
    if (created != pdPASS) {
        ESP_LOGE("console", "cannot start the console task");
        abort();
    }
}

void writeLine(std::string_view json) {
    std::lock_guard<std::recursive_mutex> lock(s_output);
    if (!s_atLineStart) {
        writeLocked("\n", 1);
    }
    writeLocked(json.data(), json.size());
    writeLocked("\n", 1);
    flushLocked();
}

void flush() {
    {
        std::lock_guard<std::recursive_mutex> lock(s_output);
        flushLocked();
    }
    waitTxDone();
}

}
