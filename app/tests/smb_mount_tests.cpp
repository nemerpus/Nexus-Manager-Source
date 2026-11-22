// SPDX-License-Identifier: GPL-3.0-or-later
#include "nexus/smb_mount.hpp"
#include <cassert>

int main() {
    using namespace nexus::smbmount;
    nexus::network::Connection c{"Home", "SMB", "nas", "Games", "reader", ""};
    Config config;
    assert(Configure(config, c, "example", "/folder/Game.XCI"));
    assert(std::string(config.path) == "folder/Game.XCI");
    assert(std::string(config.password) == "example");
    assert(!Configure(config, c, "example", "/folder/../Game.xci"));
    assert(!Configure(config, c, std::string("a\0b",3), "/game.xci"));
    assert(!Configure(config, c, std::string(256,'x'), "/game.xci"));
    assert(!Supported("/game.xcz") && !Supported("/game.nsp"));
    c.domain = "WORKGROUP";
    assert(!Configure(config, c, "example", "/game.xci"));
    c.domain.clear(); c.protocol = "NFS";
    assert(!Configure(config, c, "example", "/game.xci"));
    Status status{0x3153544d,1,State::Ready,0,GenerationBit|1,4096,0};
    assert(status.Valid());
    status.generation = 1; assert(!status.Valid());
    status.state = State::Empty; assert(!status.Valid());
    status = {0x3153544d,1,State::Fault,99,0,0,0}; assert(status.Valid());
    ++status.version; assert(!status.Valid());
    std::size_t reads = 0;
    auto read = [&reads](std::uint64_t offset, unsigned char* data, std::size_t size) {
        ++reads;
        for(std::size_t i=0;i<size;++i) data[i]=(offset+i)%251;
        return true;
    };
    assert(SameSamples(UINT64_C(1)<<35,read,read) && reads==6);
    assert(!SameSamples(4096,read,[&](auto offset,auto data,auto size){
        read(offset,data,size);if(offset>0)++data[3];return true;
    }));
    assert(!SameSamples(4096,read,[](auto...){return false;}));
    assert(!SameSamples(511,read,read));
}
