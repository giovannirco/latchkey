// SPDX-License-Identifier: GPL-3.0-or-later
#pragma once

#include <cstddef>
#include <string_view>

namespace latchkey_util {

inline constexpr size_t kMaxRpcText = 16 * 1024;
inline constexpr size_t kMaxRpcResponse = 32 * 1024;

class RpcText {
public:
    enum class Limit { Request, Response };
    RpcText() = default;
    explicit RpcText(Limit limit);
    ~RpcText();
    RpcText(const RpcText&) = delete;
    RpcText& operator=(const RpcText&) = delete;
    RpcText(RpcText&& other) noexcept;
    RpcText& operator=(RpcText&& other) noexcept;
    bool reserve(size_t capacity);
    bool resize(size_t size);
    bool assign(std::string_view text);
    bool append(char value);
    void clear();
    char* data();
    const char* c_str() const;
    size_t size() const;
    size_t capacity() const;
    bool empty() const;
    std::string_view view() const;

private:
    char* data_ = nullptr;
    size_t size_ = 0;
    size_t capacity_ = 0;
    size_t limit_ = kMaxRpcText;
};

}
