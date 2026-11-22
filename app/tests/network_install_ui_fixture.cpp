// SPDX-License-Identifier: GPL-3.0-or-later
#include "nexus/task_progress.hpp"
#include <algorithm>
#include <cassert>
#include <cstdint>
#include <cstring>
#include <functional>
#include <iostream>
#include <map>
#include <memory>
#include <optional>
#include <set>
#include <cstdio>
#include <string>
#include <type_traits>
#include <vector>
#include "nexus/network_location_core.hpp"
#include "nexus/smb_mount.hpp"
#include "nexus/package.hpp"
#include "nexus/network_browser_model.hpp"
#include "nexus/network_session_passwords.hpp"
using Result=std::uint32_t;using u32=std::uint32_t;using u64=std::uint64_t;using s64=std::int64_t;
constexpr Result Fault=123,Cancelled=456;
constexpr Result Result_TransferCancelled=Cancelled;
#include "network_socket_ui_mock.hpp"
#define R_FAILED(rc) ((rc)!=0)
#define R_SUCCEEDED(rc) ((rc)==0)
#define R_TRY(expression) do {const auto _checked_result=(expression);if(R_FAILED(_checked_result))return _checked_result;} while(false)
#define R_UNLESS(expression,result) do {if(!(expression))return (result);} while(false)
#define MAKERESULT(module,description) (Result(10000+(module)+(description)))
namespace nexus {
constexpr Result Invalid=10,Unavailable=11;enum class Target{Sd,Usb,Internal};
struct Space{u64 free{},total{};};struct Status{u64 generation{};bool available{};bool Available()const{return available;}};
namespace safety{enum class Operation{ReadOnly,MayWrite};}
namespace install{struct Diagnostic{std::string text,completion;};}
}
namespace sphaira::ui {struct ProgressBox;}
namespace state {
Result connect_error{},policy_error{},sd_error{},destination_error{},source_error{},query_error{},install_error{};
bool applet{},usb_available{true},active_transfer{},install_skipped{};u64 generation{77},free_space{1ULL<<35};
bool mounted{true},foreground{true};unsigned partial_records{};
unsigned checks{},installs{},mutations{},copies{},unmounts{},opens{},closes{},discovery{},saved{};
nexus::Target target{};u64 selected_generation{};std::string installed_mount,installed_path,completion;
std::weak_ptr<void> session;std::vector<nexus::network::Connection> connections;
std::map<std::string,nexus::files::Entry> files;
std::vector<std::string> installed_paths,queue_actions;std::vector<int> queue_images;
std::function<void(sphaira::ui::ProgressBox*)> after_install;
std::map<std::string,std::pair<size_t,size_t>> outcomes;
}
namespace nexus {
Result CheckUsbMutationAllowed(){++state::checks;return state::policy_error;}
Result QueryPhysicalSd(Space& out){out.free=state::free_space;return state::sd_error;}
Result QueryDestination(Target,Space& out){out.free=state::free_space;return state::destination_error;}
struct Client{Result Query(Status& out){out={state::generation,state::usb_available};return state::query_error;}Result Check(u64 generation){return state::usb_available&&generation==state::generation?0:Fault;}};
namespace updates {void StopStartupCheck(){}}
namespace lifecycle {bool CanPoll(){return state::foreground;}}
namespace transfer {enum class Mode{Off,Active};Mode Active(){return state::active_transfer?Mode::Active:Mode::Off;}}
}
namespace fs {struct FsPath:std::string{using std::string::string;using std::string::operator=;std::string toString()const{return *this;}};}
constexpr int NifmServiceType_User=1;
Result socketInitialize(const SocketInitConfig* config){assert(config->tcp_rx_buf_size==512*1024);++state::opens;return 0;}Result nifmInitialize(int){return 0;}Result nifmGetCurrentIpAddress(u32* value){*value=1;return 0;}
void nifmExit(){}void socketExit(){++state::closes;}
struct SwkbdConfig{};Result swkbdCreate(SwkbdConfig*,int){return 0;}void swkbdConfigMakePresetPassword(SwkbdConfig*){}
void swkbdConfigSetStringLenMax(SwkbdConfig*,int){}void swkbdConfigSetInitialText(SwkbdConfig*,const char*){}
void swkbdConfigSetHeaderText(SwkbdConfig*,const char*){}void swkbdConfigSetGuideText(SwkbdConfig*,const char*){}
void swkbdConfigSetSubText(SwkbdConfig*,const char*){}
Result swkbdShow(SwkbdConfig*,char*,size_t){return Cancelled;}void swkbdClose(SwkbdConfig*){}
int ini_puts(const char*,const char*,const char*,const char*){return 1;}
namespace sphaira::ui {
struct ProgressScope {ProgressScope(ProgressBox*,unsigned,unsigned){}};
enum class ProgressBoxOption{None};
enum class Button{X};struct Action {std::string label;std::function<void()> callback;};
struct Row{std::string label;std::function<void()> callback;virtual ~Row()=default;};
struct SidebarEntryCallback:Row{
    std::function<void()> edit;void SetAction(Button,Action action){edit=std::move(action.callback);}
    bool pop_on_click{};
    SidebarEntryCallback(std::string label,std::function<void()> callback,bool pop=false,const std::string& = {}):pop_on_click(pop){this->label=std::move(label);this->callback=std::move(callback);}
    SidebarEntryCallback(std::string label,std::function<void()> callback,const std::string& info):SidebarEntryCallback(std::move(label),std::move(callback),false,info){}
    SidebarEntryCallback(std::string label,std::function<void()> callback,const char* info):SidebarEntryCallback(std::move(label),std::move(callback),std::string(info)){}
};
struct SidebarEntryArray:Row{using Items=std::vector<std::string>;template<class F>SidebarEntryArray(const char*,Items,F,int,const char*){}};
struct SidebarEntryBool:Row{SidebarEntryBool(const char*,bool,std::function<void(bool&)>,const char*){}};
struct SidebarEntryTextInput:Row{std::string value;SidebarEntryTextInput(const char* label,const std::string& value,const char*,const char*,int,int,const char*):value(value){this->label=label;}const std::string& GetValue()const{return value;}void SetValue(std::string next){value=std::move(next);}};
struct SidebarEntryTextBase:Row{std::string value;SidebarEntryTextBase(const char* label,const std::string& value,std::function<void()> callback,const char*):value(value){this->label=label;this->callback=std::move(callback);}void SetValue(std::string next){value=std::move(next);}};
struct Sidebar{
    enum class Side{RIGHT};std::string title,subtitle;std::vector<std::unique_ptr<Row>> entries;
    Sidebar(std::string title,std::string subtitle,Side,float=450):title(std::move(title)),subtitle(std::move(subtitle)){}
    Sidebar(std::string title,Side side):Sidebar(std::move(title),"",side){}
    virtual ~Sidebar()=default;
    virtual void OnFocusGained() noexcept {}
    void ClearEntries(){entries.clear();}
    template<class T,class... Args>T* Add(Args&&... args){auto entry=std::make_unique<T>(std::forward<Args>(args)...);auto* result=entry.get();entries.push_back(std::move(entry));return result;}
};
struct FormSidebar:Sidebar{explicit FormSidebar(std::string title):Sidebar(std::move(title),Side::RIGHT){}};
struct OptionBox{
    using Callback=std::function<void(std::optional<s64>)>;std::string message,left,right;int selected{};Callback callback;
    OptionBox(std::string text,std::string left,Callback cb):message(std::move(text)),left(std::move(left)),callback(std::move(cb)){}
    OptionBox(std::string text,std::string left,std::string right,int selected,Callback cb):message(std::move(text)),left(std::move(left)),right(std::move(right)),selected(selected),callback(std::move(cb)){}
};
struct ProgressBox{
    void SetItem(const std::string& item){title=item;}
    std::string action,title;std::function<Result(ProgressBox*)> work;std::function<void(Result)> done;nexus::safety::Operation operation;bool cancelled{};
    ProgressBox(int,std::string action,std::string title,std::function<Result(ProgressBox*)> work,std::function<void(Result)> done,
        ProgressBoxOption=ProgressBoxOption::None,nexus::safety::Operation operation=nexus::safety::Operation::MayWrite)
        :action(std::move(action)),title(std::move(title)),work(std::move(work)),done(std::move(done)),operation(operation){}
    Result ShouldExitResult(){return cancelled?Cancelled:0;}bool ShouldExit(){return cancelled;}
    int image{};std::string note;
    ProgressBox& SetActionName(std::string next){action=std::move(next);return *this;}
    ProgressBox& SetTitle(std::string next){title=std::move(next);return *this;}
    ProgressBox& SetImage(int next){image=next;return *this;}
    ProgressBox& SetProgressNote(std::string next){note=std::move(next);return *this;}
};
}
namespace sphaira {
namespace utils{std::string formatSizeStorage(u64 size){return std::to_string(size)+" bytes";}}
namespace ui::menu::network {struct Browser{std::shared_ptr<nexus::network::browser::Model> model;explicit Browser(std::shared_ptr<nexus::network::browser::Model> state):model(std::move(state)){}};}
struct App {
    static inline std::unique_ptr<ui::Sidebar> sidebar;static inline std::unique_ptr<ui::OptionBox> option;static inline std::unique_ptr<ui::ProgressBox> progress;
    static inline std::shared_ptr<nexus::network::browser::Model> browser;static inline bool browser_active{};static inline unsigned browser_pushes{};
    static bool IsApplet(){return state::applet;}static void Notify(const std::string&){}
    template<class T,class... Args>static void Push(Args&&... args){
        if constexpr(std::is_same_v<T,ui::OptionBox>)option=std::make_unique<T>(std::forward<Args>(args)...);
        else if constexpr(std::is_same_v<T,ui::ProgressBox>){assert(!progress);progress=std::make_unique<T>(std::forward<Args>(args)...);}
        else if constexpr(std::is_same_v<T,ui::menu::network::Browser>){auto view=std::make_unique<T>(std::forward<Args>(args)...);browser=view->model;browser_active=true;++browser_pushes;}
        else if constexpr(std::is_base_of_v<ui::Sidebar,T>){browser_active=false;sidebar=std::make_unique<T>(std::forward<Args>(args)...);sidebar->OnFocusGained();}
        else static_assert(std::is_same_v<T,void>);
    }
    static void Push(std::unique_ptr<ui::Sidebar> value){browser_active=false;sidebar=std::move(value);sidebar->OnFocusGained();}
    static void PushErrorBox(Result rc,const std::string& text){assert(rc);Push<ui::OptionBox>(text,"OK",[](auto){});}
    static void Run(bool cancel=false){assert(progress);auto worker=std::move(progress);worker->cancelled=cancel;const auto result=worker->work(worker.get());worker->done(result);}
    static void Press(std::optional<s64> choice){assert(option);auto callback=option->callback;option.reset();callback(choice);}
    static bool Has(const std::string& label){if(browser_active){assert(browser);return browser->empty==label||std::any_of(browser->rows.begin(),browser->rows.end(),[&](const auto& row){return row.name==label;});}assert(sidebar);return std::any_of(sidebar->entries.begin(),sidebar->entries.end(),[&](const auto& row){return row->label==label;});}
    static void Select(const std::string& label){if(browser_active){assert(browser);for(size_t i=0;i<browser->rows.size();++i)if(browser->rows[i].name==label){browser->selected=i;browser->Activate();return;}std::cerr<<"Missing browser row: "<<label<<"\n";assert(false);}assert(sidebar);for(const auto& row:sidebar->entries)if(row->label==label){auto cb=row->callback;assert(cb);cb();return;}std::cerr<<"Missing UI row: "<<label<<'\n';assert(false);}
};
namespace nexusapp {
// NETWORK_OUTCOME_PRODUCTION
Result InstallNetworkPackage(ui::ProgressBox* progress,const std::string& mount,const std::string& path,u64 size,nexus::Target target,u64 generation,nexus::install::Diagnostic& diagnostic,NetworkInstallOutcome* outcome=nullptr){
    if(outcome)*outcome={};
    ++state::installs;assert(progress->operation==nexus::safety::Operation::MayWrite);assert(!state::session.expired());assert(size==1024);
    state::target=target;state::selected_generation=generation;state::installed_mount=mount;state::installed_path=path;
    state::installed_paths.push_back(path);state::queue_actions.push_back(progress->action);state::queue_images.push_back(progress->image);
    if(progress->cancelled)return Cancelled;if(target==nexus::Target::Usb&&generation!=state::generation)return Fault;
    if(!state::files.contains(path)||state::files.at(path).size!=size){diagnostic.text="NAS file changed";return Fault;}
    if(outcome)outcome->attempted=true;
    if(state::install_error){diagnostic.text="NAS read disconnected";if(outcome)outcome->installed_records=state::partial_records;return state::install_error;}
    auto counts=state::outcomes.contains(path)?state::outcomes.at(path):std::pair<size_t,size_t>{state::install_skipped?0:1,state::install_skipped?1:0};
    if(outcome){outcome->installed_records=counts.first;outcome->skipped_records=counts.second;}
    if(counts.first)++state::mutations;diagnostic.completion=state::completion;
    progress->image=99;progress->title="Installed title";progress->note="Previous title note";
    if(state::after_install)state::after_install(progress);return 0;
}
}
namespace location {enum FsEntryFlag{FsEntryFlag_ReadOnly=1,FsEntryFlag_NoStatFile=8};struct StdioEntry{std::string mount;unsigned flags;};using StdioEntries=std::vector<StdioEntry>;}
}
namespace sphaira::devoptab {
void DisplayNetworkInstallLocations(const std::string&);
void AddNetworkInstallShortcuts(ui::Sidebar&);
void UmountNeworkDevice(const fs::FsPath&){++state::unmounts;}
Result GetNetworkDevices(location::StdioEntries& out){out.clear();if(state::mounted)out.push_back({"nexusnet1:/",location::FsEntryFlag_ReadOnly});return 0;}
namespace common {
struct MountConfig{std::string name,url,user,pass;bool read_only{},no_stat_file{},no_stat_dir{};int timeout{};std::map<std::string,std::string> extra;};
Result ConnectSmbShare(const MountConfig& config,fs::FsPath& mount,std::string& detail){assert(config.read_only&&!config.no_stat_file);if(state::connect_error){detail="Could not connect";return state::connect_error;}mount="nexusnet1:/";return 0;}
Result ConnectNfsShare(const MountConfig& config,fs::FsPath& mount,std::string& detail){return ConnectSmbShare(config,mount,detail);}
}
namespace {
using namespace ui;using namespace nexus::files;using Connection=nexus::network::Connection;
constexpr const char* ConfigPath="/config/nexusmanager/network.ini";
// SESSION_PRODUCTION
using SessionPtr=std::shared_ptr<Session>;
nexus::network::SessionPasswords session_passwords;
using BrowserModel=nexus::network::browser::Model;using BrowserState=std::shared_ptr<BrowserModel>;using BrowserRow=nexus::network::browser::Row;using BrowserKind=nexus::network::browser::Kind;
using SelectedNetworkFile=nexus::network::browser::SelectedFile;
std::vector<Connection> Load(){return state::connections;}Result Save(const Connection& connection,const std::string* =nullptr){++state::saved;auto found=std::find_if(state::connections.begin(),state::connections.end(),[&](const auto& row){return row.name==connection.name;});if(found==state::connections.end())state::connections.push_back(connection);else *found=connection;return 0;}
bool SavedEndpoint(const Connection& c){return std::any_of(state::connections.begin(),state::connections.end(),[&](const auto& row){return row.name==c.name&&nexus::network::SameEndpoint(row,c);});}
bool KnownPassword(const Connection& c,std::string& password){return session_passwords.Find(c,password);}
Result SavePassword(const Connection&,const std::string&){return 0;}
Result Forget(const Connection& c){std::erase_if(state::connections,[&](const auto& row){return row.name==c.name;});session_passwords.Forget(c);return 0;}
void EditConnectionAfterFailure(const Connection&,bool);
void BrowseServerShares(Connection,const std::string&,bool){}
void DiscoverNetwork(bool,const std::string&){++state::discovery;}
class CopyIO {
    SessionPtr session;ProgressBox* progress;
public:
    CopyIO(SessionPtr session,ProgressBox* progress):session(std::move(session)),progress(progress){state::session=this->session;}
    Result Stat(bool usb,const std::string& path,Entry& entry,bool& exists){assert(!usb);R_TRY(progress->ShouldExitResult());R_TRY(state::source_error);auto found=state::files.find(path);exists=found!=state::files.end();if(exists)entry=found->second;return 0;}
    Result List(bool usb,const std::string& path,std::vector<std::string>& names){assert(!usb);R_TRY(progress->ShouldExitResult());R_TRY(state::source_error);for(const auto& [name,item]:state::files)if(Parent(name)==path)names.push_back(Leaf(name));return 0;}
};
void Browse(SessionPtr,const std::string&,BrowserState state={});
void Locations(const std::string&,bool);
void Destination(SessionPtr,const std::string&,const std::string&,size_t=0){++state::copies;}
namespace smbmount = nexus::smbmount;
int mount_requests{};
void MountGame(SessionPtr,const Entry&){++mount_requests;}
void ManageMountedGame(){}
// FUNCTIONS_PRODUCTION
}
// DISPLAY_PRODUCTION
}
namespace sphaira::ui::menu::nexusmenu {
// INSTALL_SOURCES_CLASS_PRODUCTION
struct Menu {unsigned source_choices{};bool usb{};void ChooseSource(bool value){usb=value;++source_choices;}void OpenSources(){
// SOURCES_PRODUCTION
}};
}
using sphaira::App;using namespace sphaira::devoptab;
void Reset(){
    App::sidebar.reset();App::option.reset();App::progress.reset();App::browser.reset();App::browser_active=false;App::browser_pushes=0;
    state::connect_error=state::policy_error=state::sd_error=state::destination_error=state::source_error=state::query_error=state::install_error=0;
    state::applet=state::active_transfer=state::install_skipped=false;state::usb_available=true;state::generation=77;state::free_space=1ULL<<35;
    state::mounted=state::foreground=true;state::partial_records=0;state::installed_paths.clear();state::queue_actions.clear();state::queue_images.clear();state::after_install={};state::outcomes.clear();
    state::checks=state::installs=state::mutations=state::copies=state::unmounts=state::opens=state::closes=state::discovery=state::saved=0;
    state::session.reset();state::selected_generation=0;state::installed_mount=state::installed_path={};state::completion="Original NSP was kept on NAS";
    state::connections={{"Office NAS","SMB","192.168.1.10","Games","user",""},{"Linux NAS","NFS","nas.local","/exports","",""}};
    session_passwords.Clear();session_passwords.Remember(state::connections.front(),"test-session-only");
    state::files={{"/game.nsp",{"/game.nsp",1024,false,{}}},{"/notes.txt",{"/notes.txt",1024,false,{}}},{"/compressed.nsz",{"/compressed.nsz",1024,false,{}}},{"/folder",{"/folder",0,true,{}}}};
}
void OpenBrowse(const std::string& protocol="SMB"){
    sphaira::ui::menu::nexusmenu::Menu menu;menu.OpenSources();assert(App::sidebar->title=="Install games");assert(!App::Has("SMB")&&!App::Has("NFS")&&App::sidebar->entries.size()==2);DisplayNetworkLocations();
    assert(App::sidebar->title=="SMB / NFS");assert(App::Has("Add "+protocol+" location"));
    assert(App::Has("["+protocol+"] "+(protocol=="SMB"?"Office NAS":"Linux NAS")));assert(App::Has(protocol=="SMB"?"[NFS] Linux NAS":"[SMB] Office NAS"));
    App::Select("["+protocol+"] "+(protocol=="SMB"?"Office NAS":"Linux NAS")); // saved location connects immediately
    assert(App::progress&&App::progress->operation==nexus::safety::Operation::ReadOnly);assert(!state::installs&&!state::copies);App::Run();
    assert(App::progress&&App::progress->operation==nexus::safety::Operation::ReadOnly);App::Run();
    assert(App::browser->title=="File manager / "+protocol&&App::Has("game.nsp")&&App::Has("folder"));assert(App::Has("notes.txt")&&App::Has("compressed.nsz"));assert(!state::installs&&!state::copies);
}
void Pick(){App::Select("game.nsp");assert(App::sidebar->title=="Picked file"&&App::Has("Install picked file"));App::Select("Install picked file");assert(App::sidebar->title=="Choose install destination");assert(App::sidebar->entries.size()==2&&App::Has("SD Card")&&App::Has("USB Drive"));assert(!state::installs&&!state::copies);}
void Preflight(const std::string& destination){Pick();App::Select(destination);assert(App::progress&&App::progress->operation==nexus::safety::Operation::ReadOnly);App::Run();}
// QUEUE_UI_CASES
int main(){
    for(const auto* protocol:{"SMB","NFS"}){
        auto session=std::make_shared<Session>();session->protocol=protocol;
        PickPackage(session,{"/Game.XCI",4096,false,{}});
        assert(App::Has("Install picked file"));
        assert(App::Has("Mount XCI from SMB")==(session->protocol=="SMB"));
        if(session->protocol=="SMB")App::Select("Mount XCI from SMB");
        PickPackage(session,{"/Game.nsp",4096,false,{}});
        assert(!App::Has("Mount XCI from SMB"));
    }
    assert(mount_requests==1);
    // Home SMB/NFS is a general browser; packages still install directly,
    // while unrelated files remain available for normal file browsing.
    Reset();Connect(state::connections.front(),"test-session-only",false);App::Run();App::Run();
    assert(App::Has("notes.txt")&&App::Has("game.nsp")&&App::Has("folder"));
    App::Select("game.nsp");assert(App::Has("Install picked file"));
    // Install Games stays local-only, including after saving another NAS.
    Reset();sphaira::ui::menu::nexusmenu::Menu owner;owner.OpenSources();
    assert(App::sidebar->entries.size()==2&&App::Has("SD card")&&App::Has("USB drive"));
    Connection shortcut{"Quick NAS","SMB","192.168.1.50","Games","",""};Save(shortcut);
    App::sidebar->OnFocusGained();assert(App::sidebar->entries.size()==2&&!App::Has("[SMB] Quick NAS"));
    App::Select("SD card");assert(owner.source_choices==1&&!owner.usb);App::sidebar->OnFocusGained();App::Select("USB drive");assert(owner.source_choices==2&&owner.usb);
    // The dedicated network manager owns saved servers and refreshes on return.
    DisplayNetworkLocations();assert(App::Has("[SMB] Quick NAS")&&App::Has("[NFS] Linux NAS"));
    const auto source_rows=App::sidebar->entries.size();App::sidebar->OnFocusGained();App::sidebar->OnFocusGained();assert(App::sidebar->entries.size()==source_rows);
    state::connections.front().name="Renamed NAS";App::sidebar->OnFocusGained();assert(App::Has("[SMB] Renamed NAS")&&!App::Has("[SMB] Office NAS"));
    std::erase_if(state::connections,[](const auto& c){return c.name=="Quick NAS";});App::sidebar->OnFocusGained();assert(!App::Has("[SMB] Quick NAS")&&App::sidebar->entries.size()==source_rows-1);
    // Keep the location list alive beneath an edited connection, as the real
    // widget stack does. Focus return must reload persisted values, not append
    // duplicate rows or preserve stale captured connection details.
    Reset();DisplayNetworkInstallLocations("SMB");auto list=std::move(App::sidebar);assert(list);
    Connection added{"Saved NAS","SMB","192.168.1.21","Backups","user",""};Save(added);
    list->OnFocusGained();App::sidebar=std::move(list);assert(App::Has("[SMB] Saved NAS")&&!App::Has("[NFS] Linux NAS"));
    const auto rows=App::sidebar->entries.size();App::sidebar->OnFocusGained();App::sidebar->OnFocusGained();assert(App::sidebar->entries.size()==rows);
    added.host="192.168.1.22";Save(added);App::sidebar->OnFocusGained();assert(App::sidebar->entries.size()==rows);
    auto saved_row=std::find_if(App::sidebar->entries.begin(),App::sidebar->entries.end(),[](const auto& row){return row->label=="[SMB] Saved NAS";});
    assert(saved_row!=App::sidebar->entries.end());auto edit=dynamic_cast<sphaira::ui::SidebarEntryCallback*>(saved_row->get())->edit;assert(edit);edit();App::Select("Edit connection");
    auto server=std::find_if(App::sidebar->entries.begin(),App::sidebar->entries.end(),[](const auto& row){return row->label=="Server";});
    assert(server!=App::sidebar->entries.end()&&dynamic_cast<sphaira::ui::SidebarEntryTextInput*>(server->get())->GetValue()=="192.168.1.22");
    Reset();DisplayNetworkInstallLocations("NFS");const auto nfs_rows=App::sidebar->entries.size();App::sidebar->OnFocusGained();assert(App::sidebar->entries.size()==nfs_rows&&App::Has("[NFS] Linux NAS")&&!App::Has("[SMB] Office NAS")&&!App::Has("Scan for SMB servers"));
    Reset();OpenBrowse();auto browser=App::browser;const auto root_rows=browser->rows.size();
    App::Select("folder");state::source_error=Fault;App::Run();assert(App::browser==browser&&browser->location=="Office NAS:/"&&browser->rows.size()==root_rows&&App::browser_pushes==1);
    state::source_error=0;App::Select("folder");App::Run(true);assert(browser->location=="Office NAS:/"&&App::browser_pushes==1);
    App::Select("folder");App::Run();assert(browser->location=="Office NAS:/folder"&&browser->rows.size()==1&&App::Has("Copy this folder to USB")&&browser->back&&App::browser_pushes==1);
    browser->back();App::Run();assert(browser->location=="Office NAS:/"&&!browser->back&&browser->rows[browser->selected].name=="folder"&&App::browser_pushes==1);
    browser->refresh();App::Run();assert(browser->rows.size()==root_rows&&App::browser_pushes==1);browser.reset();
    for(const auto& file:{"title.NSP","title.nsz","title.XCI","title.xcz"}){
        Reset();state::files.emplace("/"+std::string(file),nexus::files::Entry{"/"+std::string(file),1024,false,{}});OpenBrowse();assert(App::Has(file));App::Select(file);App::Select("Install picked file");App::Select("SD Card");App::Run();App::Press(1);App::Run();assert(state::installed_path=="/"+std::string(file)&&!state::copies);
    }
    for(const auto& protocol:{"SMB","NFS"})for(const auto& destination:{"SD Card","USB Drive"}){
        Reset();OpenBrowse(protocol);Preflight(destination);assert(App::option&&App::option->right=="Install"&&App::option->selected==0);assert(!state::installs&&!state::mutations&&!state::copies);
        assert(App::option->message.find("No package copy is needed")!=std::string::npos);App::sidebar.reset();App::browser.reset();assert(!state::session.expired());App::Press(1);
        assert(App::progress&&App::progress->operation==nexus::safety::Operation::MayWrite);assert(!state::session.expired()&&!state::installs);App::Run();
        assert(state::installs==1&&state::mutations==1&&!state::copies);assert(state::target==(std::string(destination)=="SD Card"?nexus::Target::Sd:nexus::Target::Usb));assert(state::selected_generation==(std::string(destination)=="SD Card"?0:77));
        assert(state::installed_mount=="nexusnet1:/"&&state::installed_path=="/game.nsp");assert(App::option->message=="NAS install finished\n\nDestination: "+std::string(destination)+"\nFile: game.nsp\n\n"+state::completion);assert(state::unmounts==1&&state::closes==1);
    }
    for(const auto& destination:{"SD Card","USB Drive"})for(const auto& skipped_report:{
        "Installed: 0\nSkipped: 1\nThis update was skipped because this system already has a newer version.\nOriginal NSP was kept on NAS",
        "No content was installed. 1 record(s) were skipped by installation checks. Current installed versions were kept.\nOriginal NSP was kept on NAS"}){
        Reset();OpenBrowse();Preflight(destination);state::install_skipped=true;
        state::completion=skipped_report;
        App::Press(1);App::Run();assert(state::installs==1&&!state::mutations&&!state::copies);
        assert(App::option->message=="NAS install finished\n\nDestination: "+std::string(destination)+"\nFile: game.nsp\n\n"+state::completion);
        assert(App::option->message.find("Installed to ")==std::string::npos);
    }
    for(auto choice:{std::optional<s64>{},std::optional<s64>{0}}){Reset();OpenBrowse();Preflight("USB Drive");App::Press(choice);assert(!App::progress&&!state::installs&&!state::mutations&&!state::copies);}
    Reset();OpenBrowse();Pick();App::Select("SD Card");App::Run(true);assert(App::option&&!state::installs&&!state::mutations);
    Reset();OpenBrowse();Preflight("USB Drive");state::generation=78;App::Press(1);App::Run();assert(state::installs==1&&state::selected_generation==77&&!state::mutations&&App::option->message.find("stopped")!=std::string::npos);
    for(unsigned error=0;error<7;++error){Reset();OpenBrowse();if(error==0)state::source_error=Fault;if(error==1)state::policy_error=Fault;if(error==2)state::sd_error=Fault;if(error==3)state::destination_error=Fault;if(error==4)state::query_error=Fault;if(error==5)state::usb_available=false;if(error==6)state::free_space=1;Preflight("USB Drive");assert(App::option&&App::option->message.find("Nothing was installed")!=std::string::npos&&!App::progress&&!state::installs&&!state::mutations);}
    Reset();OpenBrowse();state::files.at("/game.nsp").size=2048;Preflight("SD Card");assert(App::option&&!state::installs&&!state::mutations);
    Reset();OpenBrowse();Preflight("SD Card");App::Press(1);App::Run(true);assert(state::installs==1&&!state::mutations&&App::option->message.find("stopped")!=std::string::npos);
    Reset();OpenBrowse();Preflight("SD Card");state::install_error=Fault;App::Press(1);App::Run();assert(App::option->message.find("NAS read disconnected")!=std::string::npos&&!state::mutations);
    Reset();state::applet=true;DisplayNetworkInstallLocations("SMB");assert(App::option&&!App::sidebar&&!App::progress&&!state::opens);
    Reset();DisplayNetworkInstallLocations("FTP");assert(App::option&&!App::sidebar&&!App::progress);
    Reset();DisplayNetworkInstallLocations("SMB");assert(App::Has("Scan for SMB servers"));App::Select("Scan for SMB servers");assert(state::discovery==1&&!state::installs&&!state::copies);
    Reset();state::connect_error=Fault;Connect(state::connections.front(),"session-only-password",true);App::Run();assert(App::option&&!App::progress&&!state::installs&&!state::copies&&state::opens==1&&state::closes==1);
    Reset();Connect(state::connections.front(),"",true);App::Run(true);assert(App::option&&!App::progress&&!state::installs&&!state::opens);
    Reset();state::active_transfer=true;Connect(state::connections.front(),"",true);App::Run();assert(App::option&&!App::progress&&!state::installs&&!state::opens);
    Reset();Connect(state::connections.front(),"",true);App::Run();state::source_error=Fault;App::Run();assert(App::option&&!App::progress&&!state::installs&&!state::copies&&state::unmounts==1&&state::closes==1);
    Reset();auto session=std::make_shared<Session>();session->mount="nexusnet1:/";session->name="NAS";session->protocol="SMB";session->installing=true;Browse(session,"/folder");App::Run();assert(App::Has("No supported game files in this folder")&&!App::Has("Copy this folder to USB"));
    session.reset();RunQueueUiTests();
    std::cout<<"Production NAS install UI: local-only Install games; dedicated SMB/NFS > full-screen Browse > NSP/NSZ/XCI/XCZ > SD/USB; read-only preflight, explicit confirmation, cancellation/errors, source lifetime and USB generation pin passed\n";
}
