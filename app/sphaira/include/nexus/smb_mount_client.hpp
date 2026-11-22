// SPDX-License-Identifier: GPL-3.0-or-later
#pragma once
#include "nexus/smb_mount.hpp"
#include "nexus/nx_Client.hpp"

namespace nexus::smbmount {
// mt:store v1 is provided by the resident SMB image service.
class Store {
    Service service{};
public:
    Store() = default;
    Store(const Store&) = delete;
    Store& operator=(const Store&) = delete;
    ~Store() { serviceClose(&service); }
    Result Query(Status& status) {
        if (!serviceIsActive(&service)) {
            const auto name = smEncodeName("mt:store");
            u8 present{};
            const Result rc = hosversionAtLeast(12,0,0)
                ? tipcDispatchInOut(smGetServiceSessionTipc(), 65100, name, present)
                : serviceDispatchInOut(smGetServiceSession(), 65100, name, present);
            R_TRY(rc);
            R_UNLESS(present, Unavailable);
            R_TRY(smGetService(&service, "mt:store"));
        }
        R_TRY(serviceDispatchOut(&service, 0, status));
        return status.Valid() ? 0 : Invalid;
    }
    Result Attach(const Config& config, Status& status) {
        R_TRY(serviceDispatchOut(&service, 100, status,
            .buffer_attrs={SfBufferAttr_HipcMapAlias | SfBufferAttr_In},
            .buffers={{&config, sizeof(config)}}));
        return status.Valid() && status.state == State::Ready ? 0 : Invalid;
    }
    Result Detach(u64 generation) { return serviceDispatchIn(&service, 101, generation); }
};
}
