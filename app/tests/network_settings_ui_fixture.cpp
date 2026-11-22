// SPDX-License-Identifier: GPL-3.0-or-later
#include <algorithm>
#include <cassert>
#include <cstdint>
#include <cstring>
#include <functional>
#include <iostream>
#include <limits.h>
#include <map>
#include <memory>
#include <optional>
#include <string>
#include <type_traits>
#include <vector>
#include "nexus/network_location_core.hpp"
#include "nexus/network_session_passwords.hpp"
using Result=std::uint32_t;using u32=std::uint32_t;using s64=std::int64_t;
constexpr Result Fault=123,Cancelled=456;
#include "network_socket_ui_mock.hpp"
#define MAKERESULT(module,description) (Result((module)*100+(description)))
#define R_FAILED(rc) ((rc)!=0)
#define R_SUCCEEDED(rc) ((rc)==0)
#define R_TRY(expression) do {const auto checked=(expression);if(R_FAILED(checked))return checked;} while(false)
#define R_UNLESS(expression,result) do {if(!(expression))return (result);} while(false)
std::string operator""_i18n(const char* text,size_t size){return {text,size};}
namespace state {
Result save_result{},connect_result{},keyboard_result{};
unsigned saves{},connects{},browses{},opens{},closes{},unmounts{},keyboard_opens{},keyboard_shows{};
unsigned startup_stops{};bool startup_network_active{true};std::vector<std::string> network_events;
bool transfer{},applet{};std::string keyboard_text,keyboard_initial,keyboard_header,keyboard_subtext,keyboard_guide,connected_password,connected_url,notification,error;
nexus::network::Connection saved,connected;
std::vector<nexus::network::Connection> locations;unsigned loads{};
}
namespace nexus {
constexpr Result Invalid=99;constexpr Result Unavailable=11;namespace safety{enum class Operation{ReadOnly,MayWrite};}
namespace transfer{enum class Mode{Off,Active};Mode Active(){return state::transfer?Mode::Active:Mode::Off;}}}
namespace nexus::updates {
void StopStartupCheck(){++state::startup_stops;state::startup_network_active=false;state::network_events.push_back("startup stopped");}
}
namespace fs{struct FsPath:std::string{using std::string::string;using std::string::operator=;};}
constexpr int NifmServiceType_User=1;
Result socketInitialize(const SocketInitConfig* config){assert(config->tcp_rx_buf_size==512*1024);assert(!state::startup_network_active&&state::startup_stops);state::network_events.push_back("sockets opened");++state::opens;return 0;}
Result nifmInitialize(int){assert(!state::startup_network_active);state::network_events.push_back("network opened");return 0;}
Result nifmGetCurrentIpAddress(u32* address){*address=1;return 0;}void nifmExit(){}void socketExit(){++state::closes;}
struct SwkbdConfig{};Result swkbdCreate(SwkbdConfig*,int){++state::keyboard_opens;return 0;}void swkbdConfigMakePresetPassword(SwkbdConfig*){}
void swkbdConfigSetStringLenMax(SwkbdConfig*,int){}void swkbdConfigSetInitialText(SwkbdConfig*,const char* value){state::keyboard_initial=value;}
void swkbdConfigSetHeaderText(SwkbdConfig*,const char* value){state::keyboard_header=value;}void swkbdConfigSetGuideText(SwkbdConfig*,const char* value){state::keyboard_guide=value;}
void swkbdConfigSetSubText(SwkbdConfig*,const char* value){state::keyboard_subtext=value;}
Result swkbdShow(SwkbdConfig*,char* text,size_t capacity){++state::keyboard_shows;assert(state::keyboard_text.size()<capacity);std::strcpy(text,state::keyboard_text.c_str());return state::keyboard_result;}
void swkbdClose(SwkbdConfig*){}
namespace sphaira {
namespace swkbd {
Result ShowText(std::string& out,const char*,const char*,const char* initial,s64,s64){state::keyboard_initial=initial;out=state::keyboard_text;return state::keyboard_result;}
Result ShowNumPad(s64&,const char*,const char*,const char*,s64,s64){return Cancelled;}
}
namespace ui {
enum class Button{A};struct Action{std::string title;std::function<void()> callback;};
struct SidebarEntryBase{
    std::string title,info;bool pop{},enabled{true},dirty{};std::function<void()> action;
    SidebarEntryBase(const std::string& title,const std::string& info):title(title),info(info){}virtual ~SidebarEntryBase()=default;
    void SetAction(Button,Action next){action=std::move(next.callback);}void SetPop(){pop=true;}bool ShouldPop()const{return pop;}
    bool IsEnabled()const{return enabled;}void DependsClick(){}void SetDirty(){dirty=true;}
    void Press(){assert(action);action();}
};
// PRODUCTION_ROW_CLASSES
// PRODUCTION_ROW_CONSTRUCTORS
struct SidebarEntryArray:SidebarEntryBase{
    using Items=std::vector<std::string>;using Callback=std::function<void(s64&)>;Callback callback;
    SidebarEntryArray(const std::string& title,Items,Callback cb,s64,const std::string& info):SidebarEntryBase(title,info),callback(std::move(cb)){}
};
struct SidebarEntryBool:SidebarEntryBase{
    bool value;std::function<void(bool&)> callback;
    SidebarEntryBool(const std::string& title,bool value,std::function<void(bool&)> callback,const std::string& info):SidebarEntryBase(title,info),value(value),callback(std::move(callback)){action=[this]{this->value=!this->value;this->callback(this->value);};}
};
struct FormSidebar {
    std::string title;bool pop{};std::vector<std::unique_ptr<SidebarEntryBase>> entries;
    explicit FormSidebar(std::string title):title(std::move(title)){}virtual ~FormSidebar()=default;
    template<class T,class... Args>T* Add(Args&&... args){auto row=std::make_unique<T>(std::forward<Args>(args)...);auto* result=row.get();entries.push_back(std::move(row));return result;}
    SidebarEntryBase& Row(const std::string& name){for(auto& row:entries)if(row->title==name)return *row;assert(false);return *entries.front();}
    void Press(const std::string& name){auto& row=Row(name);row.Press();if(row.ShouldPop())pop=true;}
};
enum class ProgressBoxOption{None};
struct ProgressBox {
    std::function<Result(ProgressBox*)> work;std::function<void(Result)> done;bool cancelled{};
    ProgressBox(int,const std::string&,const std::string&,std::function<Result(ProgressBox*)> work,std::function<void(Result)> done,
        ProgressBoxOption,nexus::safety::Operation):work(std::move(work)),done(std::move(done)){}
    Result ShouldExitResult(){return cancelled?Cancelled:0;}bool ShouldExit(){return cancelled;}
};
}
struct App {
    static inline std::unique_ptr<ui::ProgressBox> progress;
    static inline std::unique_ptr<ui::FormSidebar> form;
    static bool IsApplet(){return state::applet;}
    static void Notify(const std::string& text){state::notification=text;}
    static void PushErrorBox(Result rc,const std::string& text){assert(rc);state::error=text;}
    template<class T,class... Args>static void Push(Args&&... args){if constexpr(std::is_same_v<T,ui::ProgressBox>){assert(!progress);progress=std::make_unique<T>(std::forward<Args>(args)...);}else{static_assert(std::is_base_of_v<ui::FormSidebar,T>);form=std::make_unique<T>(std::forward<Args>(args)...);}}
    static void Run(bool cancel=false){assert(progress);auto worker=std::move(progress);worker->cancelled=cancel;worker->done(worker->work(worker.get()));}
};
}
namespace sphaira::devoptab {
void UmountNeworkDevice(const fs::FsPath&){++state::unmounts;}
namespace common {
struct MountConfig{std::string name,url,user,pass;bool read_only{},no_stat_file{},no_stat_dir{};int timeout{};std::map<std::string,std::string> extra;};
Result ConnectSmbShare(const MountConfig& config,fs::FsPath& mount,std::string& detail){assert(config.read_only);++state::connects;state::connected_password=config.pass;state::connected_url=config.url;if(state::connect_result){detail="Connection failed";return state::connect_result;}mount="nexusnet1:/";return 0;}
Result ConnectNfsShare(const MountConfig& config,fs::FsPath& mount,std::string& detail){return ConnectSmbShare(config,mount,detail);}
}
namespace {
using namespace ui;using Connection=nexus::network::Connection;
nexus::network::SessionPasswords session_passwords;
nexus::network::SessionPasswords disk_passwords;
void Message(const std::string& text){state::error=text;}
// PRODUCTION_SESSION
using SessionPtr=std::shared_ptr<Session>;
std::string last_browsed_path;
void Browse(SessionPtr,const std::string& path){last_browsed_path=path;++state::browses;}
std::vector<Connection> Load(){++state::loads;return state::locations;}
bool SavedEndpoint(const Connection& c){const auto rows=Load();return std::any_of(rows.begin(),rows.end(),[&](const auto& row){return row.name==c.name&&row.remember_password==c.remember_password&&nexus::network::SameEndpoint(row,c);});}
bool ReadSavedPassword(const Connection& c,std::string& password){return c.remember_password&&SavedEndpoint(c)&&disk_passwords.Find(c,password);}
bool KnownPassword(const Connection& c,std::string& password){return session_passwords.Find(c,password)||ReadSavedPassword(c,password);}
Result SavePassword(const Connection& c,const std::string& password){assert(SavedEndpoint(c)&&c.remember_password);if(state::save_result)return state::save_result;disk_passwords.Remember(c,password);return 0;}
Result Save(const Connection& connection,const std::string* password=nullptr){++state::saves;state::saved=connection;if(state::save_result)return state::save_result;auto found=std::find_if(state::locations.begin(),state::locations.end(),[&](const auto& c){return c.name==connection.name;});if(found==state::locations.end())state::locations.push_back(connection);else *found=connection;if(connection.remember_password&&password)disk_passwords.Remember(connection,*password);else if(!connection.remember_password)disk_passwords.Forget(connection);return 0;}
void EditConnectionAfterFailure(const Connection&,bool);
// PRODUCTION_CONNECT
// PRODUCTION_PASSWORD_PROMPT
void BrowseServerShares(Connection,const std::string&,bool){}
// PRODUCTION_FORM
// PRODUCTION_FAILURE_FORM
}
}
using namespace sphaira::devoptab;using sphaira::App;
using sphaira::ui::SidebarEntryTextBase;using sphaira::ui::SidebarEntryCallback;
void Reset(){App::progress.reset();App::form.reset();session_passwords.Clear();disk_passwords.Clear();state::locations.clear();state::loads=0;state::save_result=state::connect_result=state::keyboard_result=0;state::saves=state::connects=state::browses=state::opens=state::closes=state::unmounts=state::keyboard_opens=state::keyboard_shows=0;state::transfer=state::applet=false;state::keyboard_text=state::keyboard_initial=state::keyboard_header=state::keyboard_guide=state::connected_password=state::connected_url=state::notification=state::error={};state::saved={};state::connected={};state::startup_stops=0;state::startup_network_active=true;state::network_events.clear();}
void Edit(ConnectionForm& form,const std::string& label,const std::string& value,bool cancel=false){state::keyboard_text=value;state::keyboard_result=cancel?Cancelled:0;form.Press(label);state::keyboard_result=0;assert(!form.pop);}
std::string Value(ConnectionForm& form,const std::string& label){return dynamic_cast<SidebarEntryTextBase&>(form.Row(label)).GetValue();}
void Fill(ConnectionForm& form){Edit(form,"Name","Test NAS");Edit(form,"Server","192.168.1.10");Edit(form,"Share / export","Games");Edit(form,"Username","testuser");Edit(form,"Domain","WORKGROUP");Edit(form,"Password","test-only-password");}
void AssertValues(ConnectionForm& form){assert(!form.pop);assert(Value(form,"Name")=="Test NAS");assert(Value(form,"Server")=="192.168.1.10");assert(Value(form,"Share / export")=="Games");assert(Value(form,"Username")=="testuser");assert(Value(form,"Domain")=="WORKGROUP");assert(Value(form,"Password")=="Entered");}
int main(int argc,char**){
    const bool legacy=argc>1;
    // Verify the real explicit navigation overload still pops, while a string
    // object supplies help rather than navigation. The form must never pop.
    {unsigned called{};SidebarEntryCallback row("Next",[&]{++called;},true,"help");row.Press();assert(called==1&&row.ShouldPop());}
    {unsigned called{};SidebarEntryCallback row("Stay",[&]{++called;},std::string("help"));row.Press();assert(called==1&&!row.ShouldPop()&&row.info=="help");}
    if(!legacy){
        unsigned called{};SidebarEntryCallback literal("Stay",[&]{++called;},"literal help");literal.Press();assert(called==1&&!literal.ShouldPop()&&literal.info=="literal help");
        SidebarEntryCallback explicit_stay("Stay",[&]{++called;},false,"explicit help");explicit_stay.Press();assert(called==2&&!explicit_stay.ShouldPop()&&explicit_stay.info=="explicit help");
        SidebarEntryCallback disabled("Disabled",[&]{++called;},true);disabled.enabled=false;disabled.Press();assert(called==2&&!disabled.ShouldPop());
    }
    Reset();ConnectionForm form({},true);Fill(form);form.Press("Save location");
    if(legacy){assert(form.pop);assert(state::saves==1);std::cout<<"Reproduced: production Save callback selected pop-on-click and discarded the entered form\n";return 0;}
    AssertValues(form);assert(state::saves==1&&state::notification.find("Test NAS")!=std::string::npos);
    // Repeated save attempts preserve every field, including a session password.
    for(Result result:{Result(0),Fault,Result(0)}){state::save_result=result;form.Press("Save location");AssertValues(form);}
    assert(state::saves==4&&state::saved.name=="Test NAS"&&state::saved.share=="Games"&&!state::error.empty());
    Edit(form,"Server","discarded.example",true);assert(state::keyboard_initial=="192.168.1.10");AssertValues(form);
    Edit(form,"Password","discarded-password",true);assert(state::keyboard_initial=="test-only-password");AssertValues(form);
    for(bool cancel:{false,true}){state::connect_result=Fault;form.Press("Browse SMB");AssertValues(form);assert(App::progress);App::Run(cancel);AssertValues(form);}
    assert(state::connected_password=="test-only-password");
    state::connect_result=0;form.Press("Browse SMB");App::Run();AssertValues(form);assert(state::browses==1&&state::connected_password=="test-only-password");
    // Generic File manager connection form uses a different caption and must
    // keep the same lifetime on invalid input, network failure and save failure.
    Reset();ConnectionForm generic({},false);Fill(generic);state::connect_result=Fault;
    generic.Press("Connect and browse");App::Run();AssertValues(generic);state::save_result=Fault;generic.Press("Save location");AssertValues(generic);
    Edit(generic,"Server","");generic.Press("Connect and browse");assert(!generic.pop&&!App::progress&&!state::error.empty());assert(Value(generic,"Name")=="Test NAS");
    assert(state::opens==state::closes);
    Reset();ConnectionForm automatic_name({},true);Fill(automatic_name);Edit(automatic_name,"Name","   ");Edit(automatic_name,"Server"," 192.168.1.10\t");Edit(automatic_name,"Password"," session password ");
    automatic_name.Press("Save location");assert(!automatic_name.pop&&Value(automatic_name,"Name")=="192.168.1.10"&&Value(automatic_name,"Server")=="192.168.1.10");
    assert(state::saved.name=="192.168.1.10"&&state::saved.host=="192.168.1.10");
    automatic_name.Press("Browse SMB");App::Run();assert(!automatic_name.pop&&state::connected_password==" session password ");
    // Successful connections persist without pressing Save, across session
    // restart, and a second share cannot overwrite the first share's login.
    Reset();state::locations.clear();Connection first{"NAS","SMB","192.168.1.10","Games","user",""};
    auto nested=first;nested.initial_folder="/Library/My Games";
    Connect(nested,"remember me",true,true);App::Run();assert(last_browsed_path==nested.initial_folder);
    Connect(first,"remember me",true,true);App::Run();assert(last_browsed_path=="/"&&state::locations.size()==1);session_passwords.Clear();std::string restored;
    assert(ReadSavedPassword(state::locations[0],restored)&&restored=="remember me");
    auto second=first;second.share="Backups";Connect(second,"second password",true,true);App::Run();assert(state::locations.size()==2&&state::locations[0].share=="Games"&&state::locations[1].name!="NAS");
    session_passwords.Clear();assert(ReadSavedPassword(state::locations[0],restored)&&restored=="remember me");assert(ReadSavedPassword(state::locations[1],restored)&&restored=="second password");
    Reset();state::locations.clear();state::save_result=Fault;Connect(first,"private",true,true);App::Run();assert(state::browses==1&&!state::error.empty()&&state::error.find("private")==std::string::npos);
    // The real Connect entry point releases the startup worker's process-wide
    // sockets before its queued NAS worker can enter Session::Open. Exercise
    // both protocols, including failure and cancellation before service opens.
    for(const std::string protocol:{"SMB","NFS"})for(unsigned outcome=0;outcome<3;++outcome){
        Reset();Connection connection{"Startup handoff",protocol,"192.168.1.10",protocol=="SMB"?"Games":"/srv/games","testuser","WORKGROUP"};
        state::connect_result=outcome==1?Fault:0;Connect(connection,"password",true,true);
        assert(App::progress&&state::startup_stops==1&&!state::startup_network_active&&state::opens==0);
        assert(state::network_events==std::vector<std::string>{"startup stopped"});
        App::Run(outcome==2);
        const auto expected=outcome==2?0u:1u;
        assert(state::opens==expected&&state::closes==expected&&state::connects==expected);
        assert(state::browses==(outcome==0?1u:0u));
        if(outcome!=2)assert((state::network_events==std::vector<std::string>{"startup stopped","sockets opened","network opened"}));
    }
    std::cout<<"Production SMB form and sidebar actions: save success/failure, reconnect/cancel, session password and keyboard cancellation preserve entered settings\n";
}
