// SPDX-License-Identifier: GPL-3.0-or-later
#pragma once
#include "nexus/network_location_core.hpp"
#include <cstring>

namespace nexus::smbmount {
constexpr std::uint64_t GenerationBit = UINT64_C(1) << 63;
enum class State : std::uint32_t { Empty, Ready, Fault };
struct Status {
    std::uint32_t magic{}, version{};
    State state{};
    std::uint32_t error{};
    std::uint64_t generation{}, size{}, leases{};
    bool Valid() const {
        if (magic != 0x3153544d || version != 1) return false;
        switch (state) {
            case State::Empty: return !generation && !size && !leases;
            case State::Ready: return (generation & GenerationBit) && size && !error;
            case State::Fault: return !generation || (generation & GenerationBit);
        }
        return false;
    }
};
struct Config {
    char host[256]{}, share[128]{}, user[128]{}, password[256]{}, path[769]{};
    Config() = default;
    Config(const Config&) = delete;
    Config& operator=(const Config&) = delete;
    ~Config() {
        volatile char* secret = password;
        for (size_t i = 0; i < sizeof(password); ++i) secret[i] = 0;
    }
};
static_assert(sizeof(Status) == 40 && sizeof(Config) == 1537);
inline bool Supported(const std::string& path) {
    return files::Canonical(path) && files::Fold(path).ends_with(".xci");
}
inline bool Configure(Config& out, const network::Connection& c,
                      std::string_view password, const std::string& path) {
    if (c.protocol != "SMB" || !network::Valid(c) || !c.domain.empty() || !Supported(path) ||
        c.host.size() >= sizeof(out.host) || c.share.size() >= sizeof(out.share) ||
        c.user.size() >= sizeof(out.user) || password.size() >= sizeof(out.password) ||
        password.find('\0') != password.npos || path.size() - 1 >= sizeof(out.path)) return false;
    auto copy = [](auto& target, std::string_view value) {
        value.copy(target, sizeof(target) - 1);
        target[value.size()] = 0;
    };
    copy(out.host, c.host); copy(out.share, c.share); copy(out.user, c.user);
    copy(out.password, password); copy(out.path, std::string_view(path).substr(1));
    return true;
}

// Check the beginning, middle and end through two independent file handles.
template<class BrowserRead, class RuntimeRead>
bool SameSamples(std::uint64_t size, BrowserRead browser, RuntimeRead runtime) {
    std::array<unsigned char, 512> selected{}, mounted{};
    if (size < selected.size()) return false;
    const auto last = size - selected.size();
    for (auto offset : std::array<std::uint64_t, 3>{0, last / 2, last}) {
        if (!browser(offset, selected.data(), selected.size()) ||
            !runtime(offset, mounted.data(), mounted.size()) || selected != mounted) return false;
    }
    return true;
}
}
