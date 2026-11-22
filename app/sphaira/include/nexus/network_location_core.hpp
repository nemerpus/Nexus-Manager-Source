// SPDX-License-Identifier: GPL-3.0-or-later
#pragma once
#include "nexus/file_manager_core.hpp"
namespace nexus::network {
struct Connection {
    std::string name,protocol{"SMB"},host,share,user,domain;
    bool remember_password{true};
    std::string initial_folder{"/"};
};
inline bool Plain(std::string_view s,size_t limit){
    return s.size()<=limit&&files::Utf8(s)&&std::all_of(s.begin(),s.end(),[](unsigned char c){return c>=32&&c!=127;});
}
inline bool Valid(const Connection& c){
    if(c.name.empty()||!Plain(c.name,64)||c.name.find_first_of("[]=;")!=c.name.npos||
       c.host.empty()||c.host.size()>253||!std::all_of(c.host.begin(),c.host.end(),[](unsigned char x){return (x>='a'&&x<='z')||(x>='A'&&x<='Z')||(x>='0'&&x<='9')||x=='.'||x=='-';})||
       !Plain(c.user,128)||!Plain(c.domain,128)||!files::Canonical(c.initial_folder))return false;
    if(c.protocol=="SMB")return !c.share.empty()&&c.share.find('/')==c.share.npos&&files::Canonical("/"+c.share);
    return c.protocol=="NFS"&&files::Canonical(c.share);
}
inline std::string Url(const Connection& c){return Valid(c)?(c.protocol=="SMB"?"smb://":"nfs://")+c.host+(c.protocol=="SMB"?"/":"")+c.share:std::string{};}
}
