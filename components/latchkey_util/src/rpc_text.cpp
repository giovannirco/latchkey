// SPDX-License-Identifier: GPL-3.0-or-later
#include "latchkey_util/rpc_text.h"

#include <algorithm>
#include <cstring>
#include <new>
#include <utility>

namespace latchkey_util {

RpcText::RpcText(Limit limit) : limit_(limit == Limit::Request ? kMaxRpcText : kMaxRpcResponse) {}
RpcText::~RpcText() { clear(); }
RpcText::RpcText(RpcText&& other) noexcept { *this = std::move(other); }

RpcText& RpcText::operator=(RpcText&& other) noexcept {
    if (this == &other) return *this;
    clear();
    data_ = std::exchange(other.data_, nullptr);
    size_ = std::exchange(other.size_, 0);
    capacity_ = std::exchange(other.capacity_, 0);
    limit_ = other.limit_;
    return *this;
}

bool RpcText::reserve(size_t capacity) {
    if (capacity > limit_) return false;
    if (capacity <= capacity_) return true;
    char* data = new (std::nothrow) char[capacity + 1]{};
    if (data == nullptr) return false;
    if (size_ != 0) std::memcpy(data, data_, size_);
    const size_t size = size_;
    clear();
    data_ = data;
    capacity_ = capacity;
    size_ = size;
    return true;
}

bool RpcText::resize(size_t size) {
    if (!reserve(size)) return false;
    if (size < size_) {
        auto* bytes = static_cast<volatile char*>(data_);
        for (size_t i = size; i <= capacity_; ++i) bytes[i] = 0;
    }
    size_ = size;
    if (data_ != nullptr) data_[size_] = '\0';
    return true;
}

bool RpcText::assign(std::string_view text) {
    RpcText value;
    value.limit_ = limit_;
    if (!value.resize(text.size())) return false;
    if (!text.empty()) std::memcpy(value.data_, text.data(), text.size());
    *this = std::move(value);
    return true;
}

bool RpcText::append(char value) {
    if (size_ == limit_) return false;
    if (size_ == capacity_ && !reserve(std::min(limit_, std::max(size_t{128}, capacity_ * 2)))) return false;
    data_[size_++] = value;
    data_[size_] = '\0';
    return true;
}

void RpcText::clear() {
    if (data_ != nullptr) {
        auto* bytes = static_cast<volatile char*>(data_);
        for (size_t i = 0; i <= capacity_; ++i) bytes[i] = 0;
        delete[] data_;
    }
    data_ = nullptr;
    size_ = capacity_ = 0;
}

char* RpcText::data() { return data_; }
const char* RpcText::c_str() const { return data_ != nullptr ? data_ : ""; }
size_t RpcText::size() const { return size_; }
size_t RpcText::capacity() const { return capacity_; }
bool RpcText::empty() const { return size_ == 0; }
std::string_view RpcText::view() const { return {c_str(), size_}; }

}
