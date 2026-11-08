// SPDX-License-Identifier: GPL-3.0-or-later
#include "latchkey_util/label_table.h"

#include <algorithm>
#include <utility>

#include "big_endian.h"

namespace latchkey_util {

namespace {

constexpr uint8_t kVersion = 1;
constexpr uint8_t kManaged = 0x01;
constexpr uint8_t kCycled = 0x02;
constexpr size_t kIdSize = 8;
constexpr size_t kCycleSize = 5;

bool saysSomething(const Label& label) { return label.managed || !label.name.empty() || label.cycle.has_value(); }

bool isStorable(const Label& label) {
    return label.name.size() <= kMaxLabelNameBytes && (!label.cycle.has_value() || isWeeklyWindow(*label.cycle));
}

class Reader {
public:
    Reader(const uint8_t* data, size_t size) : data_(data), size_(size) {}

    bool take(size_t count, const uint8_t*& out) {
        if (size_ - offset_ < count) {
            return false;
        }
        out = data_ + offset_;
        offset_ += count;
        return true;
    }

    bool done() const { return offset_ == size_; }

private:
    const uint8_t* data_;
    size_t size_;
    size_t offset_ = 0;
};

bool readLabel(Reader& reader, Label& out) {
    const uint8_t* head = nullptr;
    if (!reader.take(kIdSize + 2, head)) {
        return false;
    }
    const uint8_t flags = head[kIdSize];
    const size_t nameSize = head[kIdSize + 1];
    if ((flags & ~(kManaged | kCycled)) != 0 || nameSize > kMaxLabelNameBytes) {
        return false;
    }
    const uint8_t* name = nullptr;
    if (!reader.take(nameSize, name)) {
        return false;
    }
    Label label;
    label.id = big_endian::read(head, kIdSize);
    label.managed = (flags & kManaged) != 0;
    label.name.assign(reinterpret_cast<const char*>(name), nameSize);
    if ((flags & kCycled) != 0) {
        const uint8_t* cycle = nullptr;
        if (!reader.take(kCycleSize, cycle)) {
            return false;
        }
        label.cycle = WeeklyWindow{cycle[0], static_cast<uint16_t>(big_endian::read(cycle + 1, 2)),
                                   static_cast<uint16_t>(big_endian::read(cycle + 3, 2))};
    }
    if (!saysSomething(label) || !isStorable(label)) {
        return false;
    }
    out = std::move(label);
    return true;
}

}

const Label* LabelTable::find(uint64_t id) const {
    const auto entry = std::find_if(labels_.begin(), labels_.end(), [id](const Label& label) { return label.id == id; });
    return entry == labels_.end() ? nullptr : &*entry;
}

bool LabelTable::hasRoomFor(uint64_t id) const { return find(id) != nullptr || labels_.size() < kMaxLabels; }

bool LabelTable::put(Label label) {
    if (!isStorable(label)) {
        return false;
    }
    if (!saysSomething(label)) {
        remove(label.id);
        return true;
    }
    for (Label& existing : labels_) {
        if (existing.id == label.id) {
            existing = std::move(label);
            return true;
        }
    }
    if (labels_.size() >= kMaxLabels) {
        return false;
    }
    labels_.push_back(std::move(label));
    return true;
}

bool LabelTable::remove(uint64_t id) {
    const size_t before = labels_.size();
    labels_.erase(std::remove_if(labels_.begin(), labels_.end(), [id](const Label& label) { return label.id == id; }),
                  labels_.end());
    return labels_.size() != before;
}

bool LabelTable::keepOnly(const std::vector<uint64_t>& ids) {
    const size_t before = labels_.size();
    labels_.erase(std::remove_if(labels_.begin(), labels_.end(),
                                 [&ids](const Label& label) {
                                     return std::find(ids.begin(), ids.end(), label.id) == ids.end();
                                 }),
                  labels_.end());
    return labels_.size() != before;
}

size_t LabelTable::size() const { return labels_.size(); }

const std::vector<Label>& LabelTable::entries() const { return labels_; }

std::vector<uint8_t> LabelTable::encode() const {
    std::vector<uint8_t> out{kVersion, static_cast<uint8_t>(labels_.size())};
    for (const Label& label : labels_) {
        big_endian::append(out, label.id, kIdSize);
        out.push_back(static_cast<uint8_t>((label.managed ? kManaged : 0) | (label.cycle.has_value() ? kCycled : 0)));
        out.push_back(static_cast<uint8_t>(label.name.size()));
        out.insert(out.end(), label.name.begin(), label.name.end());
        if (label.cycle.has_value()) {
            out.push_back(label.cycle->days);
            big_endian::append(out, label.cycle->startMinute, 2);
            big_endian::append(out, label.cycle->endMinute, 2);
        }
    }
    return out;
}

bool LabelTable::decode(const uint8_t* data, size_t size, LabelTable& out) {
    if (data == nullptr || size < 2 || data[0] != kVersion || data[1] > kMaxLabels) {
        return false;
    }
    Reader reader(data + 2, size - 2);
    LabelTable table;
    for (size_t i = 0; i < data[1]; ++i) {
        Label label;
        if (!readLabel(reader, label) || table.find(label.id) != nullptr) {
            return false;
        }
        table.labels_.push_back(std::move(label));
    }
    if (!reader.done()) {
        return false;
    }
    out = std::move(table);
    return true;
}

}
