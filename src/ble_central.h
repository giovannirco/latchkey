// SPDX-License-Identifier: GPL-3.0-or-later
#pragma once

#include <cstddef>
#include <cstdint>
#include <functional>

#include "sdkconfig.h"
#include "ttlock/bytes.h"
#include "ttlock/frame.h"
#include "ttlock/status.h"
#include "ttlock/transport.h"

namespace ble {

inline constexpr size_t kAdvertMax = 31;
inline constexpr size_t kNotificationMax = CONFIG_BT_NIMBLE_ATT_PREFERRED_MTU - 3;

struct Address {
    uint8_t type;
    uint8_t value[6];
};

struct Advert {
    Address address;
    int8_t rssi;
    uint8_t eventType;
    uint8_t length;
    uint8_t data[kAdvertMax];
};

struct Notification {
    uint16_t length;
    uint8_t data[kNotificationMax];
};

struct Message {
    enum class Kind : uint8_t {
        Wake,
        Advert,
        Notification,
        Disconnected,
    };

    Kind kind;
    uint32_t link;
    union {
        Advert advert;
        Notification notification;
        int reason;
    };
};

enum class ScanMode : uint8_t {
    Off,
    Background,
    Fast,
};

struct LinkInfo {
    uint16_t mtu = 0;
    uint8_t writeProperties = 0;
    bool writeWithoutResponse = false;
};

struct Stats {
    bool ready = false;
    bool connected = false;
    ScanMode scan = ScanMode::Off;
    uint32_t reports = 0;
    uint32_t frames = 0;
    uint32_t badCrc = 0;
    uint32_t dropped = 0;
};

const char* addressTypeName(uint8_t type);

bool isConnectable(const Advert& advert);

void init();

bool ready();

bool receive(Message& out, uint32_t timeoutMs);

void wake();

int scan(ScanMode mode);

ScanMode scanMode();

int connect(const Address& address, uint32_t timeoutMs, LinkInfo& info);

void disconnect();

bool connected();

Stats stats();

class LinkTransport : public ttlock::Transport {
public:
    using AdvertSink = std::function<void(const Advert&)>;

    explicit LinkTransport(AdvertSink sink);

    void reset();

    ttlock::Status send(const ttlock::Bytes& wireFrameWithCrlf) override;

    ttlock::Status receive(ttlock::Bytes& frameWithoutCrlf, uint32_t timeoutMs) override;

private:
    AdvertSink sink_;
    ttlock::Reassembler reassembler_;
    uint8_t lastCommand_ = 0;
};

}
