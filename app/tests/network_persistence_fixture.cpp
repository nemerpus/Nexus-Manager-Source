// SPDX-License-Identifier: GPL-3.0-or-later
#include <cassert>
#include <cerrno>
#include <cstdio>
#include <cstring>
#include <filesystem>
#include <fstream>
#include <iostream>
#include <iterator>
#include <string>
#include <vector>
#include "nexus/network_location_core.hpp"
#include "nexus/network_session_passwords.hpp"
#include <minIni.h>
using Result=unsigned;
using Connection=nexus::network::Connection;
constexpr Result IoError=10,DirectoryError=11;
namespace nexus {constexpr Result Invalid=20;}
#define R_UNLESS(expression,result) do {if(!(expression))return (result);}while(false)
#define R_TRY(expression) do {const auto result=(expression);if(result)return result;}while(false)

// Use a temporary Unix directory named sdmc: to exercise the exact Switch path.
// Only the platform directory-creation call is replaced; minIni's file I/O is real.
// CONFIG_PATH_PRODUCTION
static Result directory_result{};
namespace fs {
struct FsNativeSd {
    Result CreateDirectoryRecursively(const char* path){
        assert(std::string(path)=="/config/nexusmanager");
        if(directory_result)return directory_result;
        std::filesystem::create_directories(std::string("sdmc:")+path);return 0;
    }
};
}
static std::string dropped_key,dropped_delete;
static bool fail_rename{};
static unsigned writes{};
extern "C" int real_ini_puts(const char*,const char*,const char*,const char*);
extern "C" int ini_puts(const char* section,const char* key,const char* value,const char* path){
    assert(std::string(path)==ConfigPath);++writes;
    if(key&&((value&&dropped_key==key)||(!value&&dropped_delete==key)))return 1;
    return real_ini_puts(section,key,value,path);
}
extern "C" int test_rename(const char* source,const char* destination){
    if(fail_rename){errno=EACCES;return -1;}
    return std::rename(source,destination);
}
// NETWORK_PERSISTENCE_PRODUCTION

std::string File(){std::ifstream in(ConfigPath,std::ios::binary);return {std::istreambuf_iterator<char>(in),{}};}
void Same(const Connection& a,const Connection& b){
    assert(a.initial_folder==b.initial_folder);
    assert(a.name==b.name&&a.protocol==b.protocol&&a.host==b.host&&a.share==b.share&&a.user==b.user&&a.domain==b.domain&&a.remember_password==b.remember_password);
}
void Reopens(const Connection& expected){
    const auto entries=Load();const auto row=std::find_if(entries.begin(),entries.end(),[&](const auto& c){return c.name==expected.name;});
    assert(row!=entries.end());Same(*row,expected);
    assert(!ini_haskey(expected.name.c_str(),"pass",ConfigPath)&&!ini_haskey(expected.name.c_str(),"password",ConfigPath));
}
int main(){
    const Connection original{"Living room NAS","SMB","192.168.1.20","Games","player","WORKGROUP"};
    {
        auto nested=original;nested.name="Nested";nested.initial_folder="/Library/My Games";
        std::string secret="test",loaded;
        assert(Save(nested,&secret)==0);Reopens(nested);
        assert(ReadSavedPassword(nested,loaded)&&loaded==secret);
        nested.initial_folder="/Library/../Games";assert(Save(nested)==nexus::Invalid);
        nested.initial_folder="/Other";assert(Save(nested)==0);Reopens(nested);
        assert(ReadSavedPassword(nested,loaded)&&loaded==secret);
        assert(Forget(nested)==0);
    }
    assert(Save(original)==0);Reopens(original);
    auto edited=original;edited.host="nas.example.test";edited.share="Switch Games";edited.user="second-user";edited.domain="HOME";
    assert(Save(edited)==0);Reopens(edited);
    const Connection nfs{"Linux export","NFS","192.168.1.21","/srv/games","",""};
    assert(Save(nfs)==0);Reopens(nfs);Reopens(edited);assert(Load().size()==2);
    const Connection user_smb{"NAS","SMB","192.168.4.152","Public","admin",""},user_nfs{"Nas1","NFS","192.168.4.152","/Public","admin",""};
    assert(Save(user_smb)==0&&Save(user_nfs)==0);Reopens(user_smb);Reopens(user_nfs);assert(nexus::network::Url(user_nfs)=="nfs://192.168.4.152/Public");
    auto anonymous=edited;anonymous.user.clear();anonymous.domain.clear();assert(Save(anonymous)==0);Reopens(anonymous);
    auto longest=original;longest.name="Long address";longest.host=std::string(249,'a')+".nas";
    assert(Save(longest)==0);Reopens(longest);
    auto quoted=original;quoted.name="Quoted fields";quoted.user="name; \"quoted\"";quoted.domain="domain = example";
    assert(Save(quoted)==0);Reopens(quoted);

    for(const auto& field:{"protocol","host","share","user","domain"}){
        assert(Save(original)==0);auto next=original;
        if(std::string(field)=="protocol"){next.protocol="NFS";next.share="/srv/games";}
        if(std::string(field)=="host")next.host="changed.example.test";
        if(std::string(field)=="share")next.share="New Games";
        if(std::string(field)=="user")next.user.clear();
        if(std::string(field)=="domain")next.domain.clear();
        dropped_key=field;assert(Save(next)==IoError);dropped_key.clear();
        assert(Save(next)==0);Reopens(next);
    }
    for(const auto& key:{"pass","password"}){
        assert(real_ini_puts(original.name.c_str(),key,"legacy-test-password",ConfigPath)==1);
        dropped_delete=key;assert(Save(original)==IoError);dropped_delete.clear();
        assert(Save(original)==0);Reopens(original);assert(File().find("legacy-test-password")==std::string::npos);
    }
    const auto unchanged=File();const auto write_count=writes;
    auto invalid=original;invalid.name=" Living room NAS ";assert(Save(invalid)==nexus::Invalid);
    invalid=original;invalid.host="smb://wrong-field";assert(Save(invalid)==nexus::Invalid);
    assert(File()==unchanged&&writes==write_count);
    directory_result=DirectoryError;assert(Save(original)==DirectoryError);directory_result=0;
    assert(File()==unchanged&&writes==write_count);

    // Exercise minIni's real false-success behavior on a failed publish rename.
    fail_rename=true;edited=original;edited.host="longer.changed.host.example.test";
    assert(Save(edited)==IoError);fail_rename=false;
    assert(Save(edited)==0);Reopens(edited);
    // Exact saved-password round trips, including blank and INI metacharacters.
    auto credentials=original;credentials.name="Credentials";std::string readback;
    const std::vector<std::string> passwords{"", " leading ; # = \" quotes \\\\ trailing ",std::string(510,'x')+"!", "caf\xc3\xa9 \xe6\x97\xa5\xe6\x9c\xac"};
    for(const auto& password:passwords){assert(Save(credentials,&password)==0);session_passwords.Clear();assert(KnownPassword(credentials,readback)&&readback==password);assert(ReadSavedPassword(credentials,readback)&&readback==password);}
    const std::string secret="test secret should not appear literally";assert(Save(credentials,&secret)==0);assert(File().find(secret)==std::string::npos);
    // A changed metadata endpoint must not activate old credentials, even if
    // the file is externally edited without going through Save.
    for(const auto& field:{"protocol","host","share","user","domain"}){
        assert(Save(credentials,&secret)==0);auto changed=credentials;
        std::string replacement="changed";if(std::string(field)=="protocol"){changed.protocol="NFS";replacement="NFS";}
        if(std::string(field)=="host")changed.host=replacement;
        if(std::string(field)=="share")changed.share=replacement;
        if(std::string(field)=="user")changed.user=replacement;
        if(std::string(field)=="domain")changed.domain=replacement;
        assert(real_ini_puts(credentials.name.c_str(),field,replacement.c_str(),ConfigPath));assert(!ReadSavedPassword(changed,readback));assert(!ReadSavedPassword(credentials,readback));
    }
    assert(Save(credentials,&secret)==0);auto disabled=credentials;disabled.remember_password=false;assert(Save(disabled)==0);Reopens(disabled);
    for(const auto* field:PasswordFields)assert(!ini_haskey(disabled.name.c_str(),field,ConfigPath));assert(!ReadSavedPassword(disabled,readback));
    for(const auto* field:{"password_protocol","password_host","password_share","password_user","password_domain","password_hex_0","password_hex_1","password_saved"}){
        assert(Save(credentials)==0&&ClearSavedPassword(credentials)==0);dropped_key=field;assert(SavePassword(credentials,secret)==IoError);dropped_key.clear();assert(!ReadSavedPassword(credentials,readback));
        assert(SavePassword(credentials,secret)==0);
    }
    for(const auto* field:PasswordFields){
        assert(Save(credentials,&secret)==0);assert(real_ini_puts(credentials.name.c_str(),field,"synthetic",ConfigPath));dropped_delete=field;assert(Save(disabled)==IoError);dropped_delete.clear();assert(Save(disabled)==0);
    }
    assert(Save(credentials,&secret)==0);assert(Forget(credentials)==0);assert(!SavedEndpoint(credentials)&&!ReadSavedPassword(credentials,readback));
    assert(!ini_haskey(credentials.name.c_str(),"password_hex_0",ConfigPath));
    std::cout<<"Production network Save/Load + real minIni: reopen/edit, SD path, all-field readback, legacy-password removal, write/rename faults, invalid names and retry passed\n";
}
