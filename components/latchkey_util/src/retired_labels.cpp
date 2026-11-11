// SPDX-License-Identifier: GPL-3.0-or-later
#include "latchkey_util/retired_labels.h"

#include <algorithm>
#include <utility>

#include "big_endian.h"

namespace latchkey_util {

const RetiredLabel* RetiredLabels::find(char kind, uint64_t id) const {
    const auto found = std::find_if(entries_.begin(), entries_.end(), [kind, id](const RetiredLabel& label) {
        return label.kind == kind && label.id == id;
    });
    return found == entries_.end() ? nullptr : &*found;
}

bool RetiredLabels::remember(char kind, uint64_t id, std::string_view name) {
    if ((kind != 'p' && kind != 'f' && kind != 'c') || name.size() > kMaxLabelNameBytes) return false;
    if (name.empty()) return true;
    remove(kind, id);
    if (entries_.size() == kMaxRetiredLabels) entries_.erase(entries_.begin());
    entries_.push_back({kind, id, std::string(name)});
    return true;
}

bool RetiredLabels::remove(char kind, uint64_t id) {
    const size_t before = entries_.size();
    entries_.erase(std::remove_if(entries_.begin(), entries_.end(), [kind, id](const RetiredLabel& label) {
        return label.kind == kind && label.id == id;
    }), entries_.end());
    return before != entries_.size();
}

std::vector<uint8_t> RetiredLabels::encode() const {
    std::vector<uint8_t> bytes{1, static_cast<uint8_t>(entries_.size())};
    for (const auto& label : entries_) {
        bytes.push_back(static_cast<uint8_t>(label.kind));
        big_endian::append(bytes, label.id, 8);
        bytes.push_back(static_cast<uint8_t>(label.name.size()));
        bytes.insert(bytes.end(), label.name.begin(), label.name.end());
    }
    return bytes;
}

bool RetiredLabels::decode(const uint8_t* data, size_t size, RetiredLabels& out) {
    if (data == nullptr || size < 2 || size > kRetiredLabelsBytes || data[0] != 1 || data[1] > kMaxRetiredLabels) {
        return false;
    }
    RetiredLabels decoded;
    size_t offset = 2;
    for (size_t index = 0; index < data[1]; ++index) {
        if (size - offset < 10) return false;
        const char kind = static_cast<char>(data[offset]);
        const uint64_t id = big_endian::read(data + offset + 1, 8);
        const size_t length = data[offset + 9];
        offset += 10;
        if (length == 0 || length > size - offset || decoded.find(kind, id) != nullptr ||
            !decoded.remember(kind, id, {reinterpret_cast<const char*>(data + offset), length})) return false;
        offset += length;
    }
    if (offset != size) return false;
    out = std::move(decoded);
    return true;
}

}
