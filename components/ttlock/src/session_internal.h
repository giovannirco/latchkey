// SPDX-License-Identifier: GPL-3.0-or-later
#pragma once

#include <cstddef>
#include <cstdint>
#include <utility>
#include <vector>

#include "ttlock/bytes.h"
#include "ttlock/frame.h"
#include "ttlock/session.h"
#include "ttlock/status.h"

namespace ttlock {

inline bool usesV3Frames(const LockVersion& version) {
    constexpr uint8_t kFirstV3ProtocolType = 5;
    return version.protocolType >= kFirstV3ProtocolType;
}

inline Bytes noPayload() {
    return Bytes{};
}

template <typename Page, typename Item, typename Fetch>
Status collectPages(Fetch&& fetch, std::vector<Item>& out) {
    std::vector<Item> items;
    uint16_t sequence = 0;
    for (size_t pages = 0; pages < kMaxListPages; ++pages) {
        Page page;
        const Status status = fetch(sequence, page);
        if (status != Status::Ok) {
            return status;
        }
        items.insert(items.end(), page.items.begin(), page.items.end());
        if (page.last) {
            out = std::move(items);
            return Status::Ok;
        }
        if (page.next == sequence) {
            return Status::BadResponse;
        }
        sequence = page.next;
    }
    return Status::BadResponse;
}

}
