// SPDX-License-Identifier: GPL-3.0-or-later
#include <algorithm>
#include <array>
#include <atomic>
#include <cassert>
#include <cstring>
#include <functional>
#include <iostream>
#include <map>
#include <set>
#include <span>
#include <string>
#include <tuple>
#include <vector>
#include <openssl/sha.h>
#include "nexus/usb_import_scan_core.hpp"
#include "nexus/smb_mount.hpp"
#include "nexus/usb_import_diagnostic.hpp"
#include "nexus/index_repair_core.hpp"
#include "nexus/badge_format.hpp"
using u8=std::uint8_t;using u16=std::uint16_t;using u32=std::uint32_t;using u64=std::uint64_t;using s64=std::int64_t;using Result=u32;
constexpr Result Fault=123,Result_TransferCancelled=456;
#define R_FAILED(v) ((v)!=0)
#define R_SUCCEEDED(v) ((v)==0)
#define R_TRY(v) do{const auto rc_=(v);if(rc_)return rc_;}while(false)
#define R_UNLESS(c,r) do{if(!(c))return (r);}while(false)
#define MAKERESULT(m,d) (Result((m)*512+(d)))
#define JOIN2(a,b) a##b
#define JOIN(a,b) JOIN2(a,b)
struct Scope{std::function<void()> f;~Scope(){f();}};
#define ON_SCOPE_EXIT(...) Scope JOIN(scope_,__LINE__){[&]{__VA_ARGS__;}}
namespace nexus {constexpr Result Invalid=0x1759,Unavailable=23;struct Entry{std::string name;bool directory{};u64 size{};};}
enum NcmStorageId{NcmStorageId_BuiltInUser=4,NcmStorageId_SdCard=5};
constexpr u8 NcmContentMetaType_Application=0x80,NcmContentMetaType_Patch=0x81,NcmContentMetaType_AddOnContent=0x82,NcmContentMetaType_DataPatch=0x84,NcmContentInstallType_Full=0;
constexpr u8 NcmContentType_Meta=0,NcmContentType_Program=1,NcmContentType_Data=2,NcmContentType_Control=3,NcmContentType_HtmlDocument=4,NcmContentType_LegalInformation=5,NcmContentType_DeltaFragment=6;
using NcmContentId=std::array<u8,16>;using FsRightsId=std::array<u8,16>;
struct NcmContentMetaKey{u64 id{};u32 version{};u8 type{},install_type{};u8 padding[2]{};bool operator==(const NcmContentMetaKey&)const=default;};
struct NcmContentInfo{NcmContentId content_id{};u32 size_low{};u8 size_high{},attr{},content_type{},id_offset{};};
struct NcmContentMetaHeader{u16 extended_header_size{},content_count{},content_meta_count{};u8 attributes{},storage_id{};};
struct NcmContentMetaInfo{u8 data[16]{};};
struct NcmContentStorage{int location{};};struct NcmContentMetaDatabase{int location{};};
void ncmContentInfoSizeToU64(const NcmContentInfo* info,u64* size){*size=info->size_low|(u64(info->size_high)<<32);}
void ncmU64ToContentInfoSize(u64 size,NcmContentInfo* info){info->size_low=u32(size);info->size_high=u8(size>>32);}
namespace ncm{struct ContentStorageRecord{NcmContentMetaKey key;u8 storage_id{};bool operator==(const ContentStorageRecord&)const=default;};}
namespace nca{
constexpr u8 ContentType_Program=0,ContentType_Meta=1,ContentType_Control=2,ContentType_Manual=3,ContentType_Data=4,ContentType_PublicData=5;
struct Header{FsRightsId rights_id{};u64 size{4096},program_id{};u8 content_type{};bool valid{true},decryptable{true};bool IsValid()const{return valid;}};
Result DecryptHeader(const Header* source,int,Header& output){if(!source->decryptable)return Fault;output=*source;output.valid=true;return 0;}
}
namespace sphaira::ui{struct ProgressBox{unsigned calls{};bool cancelled{};Result ShouldExitResult(){++calls;return cancelled?Result_TransferCancelled:0;}void SetTitle(const char*){++calls;}void NewTransfer(const char*){++calls;}void UpdateTransfer(size_t,size_t){++calls;}};}
namespace sphaira::yati{struct ExistingUsbContent{NcmContentInfo info;std::array<u8,32> expected_hash{};bool has_expected_hash{};};struct ExistingUsbRecord{NcmContentMetaKey key;u64 application_id{};std::vector<ExistingUsbContent> content;std::vector<u8> installed_meta;};}
// PUBLIC_SCAN_TYPES
namespace sphaira::nexusapp {
namespace core=nexus::usb_import;
constexpr Result MissingUsb=MAKERESULT(140,205),MissingUsbTicket=600,InvalidUsbTicket=601;
constexpr size_t MaxFiles=65536,MaxTitles=4096,MaxReferences=131072,MaxStoredMeta=32*1024*1024;
using Id=std::array<u8,16>;using Key=std::tuple<u64,u32,u8>;using Bytes=std::vector<u8>;
Id ContentId(const NcmContentId& id){return id;}Key MetaKey(const NcmContentMetaKey& key){return {key.id,key.version,key.type};}
std::string HexId(const NcmContentId* id){char text[33]{};for(size_t i=0;i<id->size();++i)snprintf(text+i*2,3,"%02x",(*id)[i]);return text;}
std::string TitleId(u64 id){char text[17]{};snprintf(text,sizeof(text),"%016llX",static_cast<unsigned long long>(id));return text;}
std::string SafeName(std::string value){return value;}
struct File{NcmContentId id{};std::string path;u64 size{};};
struct HeaderInfo{FsRightsId rights{};u64 size{};u8 type{};bool valid{};};
struct World{unsigned service_opens{};Result open_result{},ticket_recheck_result{};
    std::map<std::pair<int,Key>,Bytes> metadata;
    std::map<std::pair<int,Id>,s64> physical;
    std::map<std::pair<int,Id>,nca::Header> native_headers;
    std::map<Id,nca::Header> usb_headers;
    std::map<Id,Bytes> cnmts;
    std::map<std::string,std::vector<nexus::Entry>> lists;
    std::map<std::string,nexus::repair::Image> files;
    std::map<Id,Result> archives;
    std::vector<FsRightsId> tickets;
    std::vector<NcmContentMetaKey> installed;
    std::map<u64,std::vector<ncm::ContentStorageRecord>> apps;
    std::set<u64> home;
    nexus::repair::Indexes routes;
    std::atomic_bool* cancel{};bool cancel_on_list{},modern{};
    Result check_rc{},read_rc{},native_rc{};
    unsigned checks{},reads{},archive_reads{},cache_reads{},name_reads{},open_storage{},close_storage{},open_database{},close_database{};
} world;
void sha256CalculateHash(void* out,const void* bytes,size_t size){SHA256(static_cast<const u8*>(bytes),size,static_cast<u8*>(out));}
bool hosversionAtLeast(int,int,int){return world.modern;}
Result ncmOpenContentMetaDatabase(NcmContentMetaDatabase* db,NcmStorageId location){++world.open_database;db->location=location;return world.native_rc;}
Result ncmOpenContentStorage(NcmContentStorage* storage,NcmStorageId location){++world.open_storage;storage->location=location;return world.native_rc;}
void ncmContentMetaDatabaseClose(NcmContentMetaDatabase* db){if(db->location){++world.close_database;db->location=0;}}
void ncmContentStorageClose(NcmContentStorage* storage){if(storage->location){++world.close_storage;storage->location=0;}}
Result ncmContentMetaDatabaseHas(NcmContentMetaDatabase* db,bool* present,const NcmContentMetaKey* key){*present=world.metadata.contains({db->location,MetaKey(*key)});return world.native_rc;}
Result ncmContentStorageHas(NcmContentStorage* storage,bool* present,const NcmContentId* id){*present=world.physical.contains({storage->location,*id});return world.native_rc;}
Result ncmContentStorageGetSizeFromContentId(NcmContentStorage* storage,s64* size,const NcmContentId* id){*size=world.physical.at({storage->location,*id});return world.native_rc;}
Result ncmContentStorageReadContentIdFile(NcmContentStorage* storage,void* out,size_t size,const NcmContentId* id,s64 offset){assert(size==sizeof(nca::Header)&&offset==0);const auto it=world.native_headers.find({storage->location,*id});if(it==world.native_headers.end())return Fault;memcpy(out,&it->second,size);return world.native_rc;}
namespace es{bool IsRightsIdValid(const FsRightsId& id){return id!=FsRightsId{};}bool IsRightsIdFound(const FsRightsId& id,const std::vector<FsRightsId>& tickets){return std::find(tickets.begin(),tickets.end(),id)!=tickets.end();}}
namespace title{std::string GetCachedTitleName(u64){++world.cache_reads;return "Cached name";}}
struct UsbTicketPair{};
Result LoadUsbTicketPair(u64,const FsRightsId& id,UsbTicketPair&){++world.archive_reads;return world.archives.contains(id)?world.archives.at(id):MissingUsbTicket;}
struct Session{
    ui::ProgressBox* progress;UsbImportScan& scan;const std::atomic_bool* cancel;const char* stage{"opening the read-only USB library scan"};
    NcmContentStorage native{NcmStorageId_SdCard};NcmContentMetaDatabase db{NcmStorageId_SdCard};int keys{};
    nexus::repair::Indexes routes;std::vector<FsRightsId> tickets;std::vector<NcmContentMetaKey> installed;
    std::map<u64,std::vector<ncm::ContentStorageRecord>> applications;std::set<u64> home_applications;
    std::map<Id,HeaderInfo> headers;
    struct Usb{
        Result Check(u64){++world.checks;return world.check_rc;}
        Result List(u64,const std::string& path,std::vector<nexus::Entry>& out){if(world.cancel_on_list&&world.cancel)world.cancel->store(true);const auto it=world.lists.find(path);if(it==world.lists.end())return MissingUsb;out=it->second;return 0;}
    } usb;
    Session(ui::ProgressBox* p,UsbImportScan& value,const std::atomic_bool* c=nullptr):progress(p),scan(value),cancel(c),routes(world.routes),tickets(world.tickets),installed(world.installed),applications(world.apps),home_applications(world.home){for(const auto& [id,h]:world.usb_headers)headers[id]={h.rights_id,h.size,h.content_type,h.valid};}
    // PRODUCTION_CANCEL
    // PRODUCTION_CHECK
    Result Probe(u64 expected){R_TRY(Cancelled());scan.generation=expected?expected:7;return Check();}
    Result CheckTicketsUnchanged(){R_TRY(world.ticket_recheck_result);return tickets==world.tickets?0:Fault;}
    Result Open(u64 expected,bool=false){++world.service_opens;R_TRY(world.open_result);return Probe(expected);}
    Result ReadSd(const std::string& path,nexus::repair::Image& out,size_t limit){++world.reads;R_TRY(Check());R_TRY(world.read_rc);out=world.files.contains(path)?world.files.at(path):nexus::repair::Image{};R_UNLESS(out.data.size()<=limit,nexus::Invalid);return 0;}
    Result RawFrom(NcmContentMetaDatabase& database,const NcmContentMetaKey& key,Bytes& out){R_TRY(world.read_rc);const auto it=world.metadata.find({database.location,MetaKey(key)});if(it==world.metadata.end())return Fault;out=it->second;return Check();}
    Result Raw(const NcmContentMetaKey& key,Bytes& out){return RawFrom(db,key,out);}
    Result AppRecords(u64 application,const std::vector<ncm::ContentStorageRecord>*& out){out=&applications[application];return Check();}
    Result Header(const File& file,nca::Header& out,bool& valid){R_TRY(Check());out=world.usb_headers.at(file.id);valid=out.valid;return 0;}
};
// PRODUCTION_SAME_KEY
// PRODUCTION_HEADER_TYPE
// PRODUCTION_SAME_REFERENCES
// PRODUCTION_NATIVE
// PRODUCTION_BADGE
// PRODUCTION_CLASSIFY
// PRODUCTION_INSTALLED_IDENTITY
// PRODUCTION_INSTALLED_RECORD
// PRODUCTION_RECONCILE
// PRODUCTION_BASE
// PRODUCTION_PLAN
// PRODUCTION_SUMMARY
// PRODUCTION_CANONICAL
// PRODUCTION_PREVIEW_IDENTITY
// PRODUCTION_MAKE_RECORD
Result ReadCnmt(Session&,const File& file,const nca::Header&,Bytes& raw,std::string& reason){raw=world.cnmts.at(file.id);reason.clear();return 0;}
Result ReadTitleNames(Session&){++world.name_reads;return 0;}
// PRODUCTION_SCAN
unsigned cases{},checks{};
#define REQUIRE(c) do{++checks;if(!(c)){std::cerr<<"Case "<<cases<<" line "<<__LINE__<<": "<<#c<<'\n';std::abort();}}while(false)
void Reset(){++cases;world={};}
constexpr u64 AppId=0x0100000000010000ULL;
Id IdOf(u8 n){Id id{};id[0]=n;return id;}
u8 HeaderKind(u8 type){return type==NcmContentType_Meta?nca::ContentType_Meta:type==NcmContentType_Control?nca::ContentType_Control:type==NcmContentType_Program?nca::ContentType_Program:nca::ContentType_Data;}
Bytes Raw(const yati::ExistingUsbRecord& record){
    NcmContentMetaHeader header{};header.extended_header_size=record.key.type==NcmContentMetaType_DataPatch?16:8;header.content_count=record.content.size();
    Bytes bytes(sizeof(header)+header.extended_header_size+record.content.size()*sizeof(NcmContentInfo));memcpy(bytes.data(),&header,sizeof(header));const auto app_at=sizeof(header)+(record.key.type==NcmContentMetaType_DataPatch?8:0);memcpy(bytes.data()+app_at,&record.application_id,sizeof(u64));
    for(size_t i=0;i<record.content.size();++i)memcpy(bytes.data()+sizeof(header)+header.extended_header_size+i*sizeof(NcmContentInfo),&record.content[i].info,sizeof(NcmContentInfo));return bytes;
}
UsbImportTitle Row(u8 type=NcmContentMetaType_Application,u8 serial=1){
    UsbImportTitle row;row.name="Example";row.record.key={AppId+(type==NcmContentMetaType_Application?0:u64(type)),1,type,0,{}};row.record.application_id=AppId;
    for(u8 kind:{NcmContentType_Meta,NcmContentType_Control,type==NcmContentMetaType_AddOnContent||type==NcmContentMetaType_DataPatch?NcmContentType_Data:NcmContentType_Program}){yati::ExistingUsbContent c;c.info.content_id=IdOf(serial++);c.info.content_type=kind;ncmU64ToContentInfoSize(4096,&c.info);row.record.content.push_back(c);nca::Header header;header.content_type=HeaderKind(kind);header.program_id=row.record.key.id;world.usb_headers[c.info.content_id]=header;}
    row.record.installed_meta=Raw(row.record);return row;
}
void Registered(const UsbImportTitle& row,int storage=NcmStorageId_SdCard){world.metadata[{storage,MetaKey(row.record.key)}]=row.record.installed_meta;world.apps[row.record.application_id].push_back({row.record.key,u8(storage)});world.home.insert(row.record.application_id);if(storage==NcmStorageId_SdCard)world.installed.push_back(row.record.key);}
void Routes(const UsbImportTitle& row){std::vector<nexus::recovery::Content> content;for(const auto& c:row.record.content){u64 size{};ncmContentInfoSizeToU64(&c.info,&size);content.push_back({c.info.content_id,size,c.info.content_type,c.info.id_offset});}REQUIRE(nexus::repair::Merge(world.routes,row.record.key.id,row.record.key.type==NcmContentMetaType_Application,content)!=nexus::repair::MergeResult::Invalid);}
void Native(const UsbImportTitle& row,int location){Registered(row,location);for(const auto& c:row.record.content){world.physical[{location,c.info.content_id}]=4096;world.native_headers[{location,c.info.content_id}]=world.usb_headers.at(c.info.content_id);}}
void DisabledBadges(){world.files["/atmosphere/usb_badges/disabled"]={true,{'B','2'}};}
Result ClassifyRow(UsbImportTitle& row){UsbImportScan scan;scan.generation=7;Session session(nullptr,scan);return Classify(session,row);}
UsbLibraryPlan Plan(std::vector<UsbImportTitle> rows){UsbImportScan scan;scan.complete=true;scan.titles=std::move(rows);return PlanUsbLibrary(scan);}
void UsbFiles(){
    std::map<std::string,std::vector<nexus::Entry>> buckets;
    for(const auto& [id,header]:world.usb_headers){u8 hash[32]{};sha256CalculateHash(hash,id.data(),id.size());char bucket[9];snprintf(bucket,sizeof(bucket),"%08X",unsigned(hash[0]));buckets[bucket].push_back({HexId(&id)+".nca",false,header.size});}
    for(const auto& [bucket,entries]:buckets){world.lists["/registered"].push_back({bucket,true,0});world.lists["/registered/"+bucket]=entries;}
}
Bytes Cnmt(const UsbImportTitle& row){
    const size_t count=row.record.content.size()-1;Bytes raw(32+16+count*56+32);memcpy(raw.data(),&row.record.key.id,8);memcpy(raw.data()+8,&row.record.key.version,4);raw[12]=NcmContentMetaType_Application;raw[14]=16;raw[16]=u8(count);
    for(size_t i=0;i<count;++i){const auto& info=row.record.content[i+1].info;const size_t offset=48+i*56;memcpy(raw.data()+offset,info.content_id.data(),16);memcpy(raw.data()+offset+32,info.content_id.data(),16);memcpy(raw.data()+offset+48,&info.size_low,4);raw[offset+54]=info.content_type;}
    return raw;
}
auto StateSnapshot(){return std::tuple(world.metadata,world.physical,world.apps,world.home,world.routes,world.files,world.tickets,world.archives);}
UsbImportTitle InstalledOnly(const UsbImportTitle& source,u64 id,u64 application,u8 type){
    auto row=source;row.record.key.id=id;row.record.key.version=0;row.record.key.type=type;row.record.application_id=application;
    for(size_t i=0;i<row.record.content.size();++i)row.record.content[i].info.content_id=IdOf(200+i);
    row.record.installed_meta=Raw(row.record);return row;
}
void RetailUsb(const UsbImportTitle& row){world.cnmts[row.record.content.front().info.content_id]=Cnmt(row);UsbFiles();}
int Main(){
    {
        Reset(); auto game=Row(); RetailUsb(game);
        std::vector<nexus::Entry> flat;
        for(const auto& [path,entries]:world.lists)
            if(path!="/registered")flat.insert(flat.end(),entries.begin(),entries.end());
        world.lists.clear();world.lists["/registered"]=flat;
        REQUIRE(!flat.empty());
        UsbImportScan usb,image;
        REQUIRE(!ScanUsbImports(nullptr,usb,7,nullptr,false) && usb.nca_files==0);
        const u64 generation=nexus::smbmount::GenerationBit|7;
        REQUIRE(!ScanUsbImports(nullptr,image,generation,nullptr,false));
        REQUIRE(image.complete && image.generation==generation && image.nca_files==flat.size());
        REQUIRE(!image.titles.empty() && image.titles.front().record.application_id==game.record.application_id);
    }
    // Empty or absent /registered is a successful no-op even if the installed
    // database cannot open. No ticket, map, HOME or installation mutation.
    for(bool folder:{false,true}){Reset();world.open_result=Fault;if(folder)world.lists["/registered"]={};UsbImportScan empty;
        REQUIRE(ScanUsbImports(nullptr,empty,7,nullptr,false)==0&&empty.complete&&empty.titles.empty()&&world.service_opens==0);
        const auto summary=SummarizeUsbLibrary(empty);REQUIRE(!summary.affected_games&&!summary.repairable_games&&!summary.blocked_games);}
    {Reset();auto older=Row(NcmContentMetaType_Patch,1);auto newer=older;newer.record.key.version=2;Registered(newer);
    world.usb_headers[older.record.content.back().info.content_id].rights_id=IdOf(77);
    REQUIRE(ClassifyRow(older)==0&&older.registration==UsbImportRegistration::Superseded&&world.archive_reads==0);}
    // A completed registration remains healthy on repeated scans even if the
    // optional HOME USB badge cache does not exist or could not be generated.
    {Reset();auto healthy=Row();Registered(healthy);Routes(healthy);RetailUsb(healthy);
        for(unsigned attempt=0;attempt<2;++attempt){UsbImportScan check;
            REQUIRE(ScanUsbImports(nullptr,check,7,nullptr,false)==0&&check.complete);
            REQUIRE(!SummarizeUsbLibrary(check).affected_games&&!SummarizeUsbLibrary(check).repairable_games);}}
    {Reset();auto healthy=Row();Registered(healthy);Routes(healthy);RetailUsb(healthy);world.ticket_recheck_result=Fault;UsbImportScan check;
        REQUIRE(ScanUsbImports(nullptr,check,7,nullptr,false)==Fault&&!check.complete&&check.titles.empty());}

    Reset();auto row=Row();Registered(row);Routes(row);DisabledBadges();REQUIRE(ClassifyRow(row)==0&&row.status==UsbImportStatus::AlreadyRegistered&&row.registration==UsbImportRegistration::Usb);
    for(unsigned missing=0;missing<3;++missing){Reset();row=Row();Registered(row);Routes(row);DisabledBadges();if(missing==0)world.routes.titles.clear();if(missing==1)world.routes.mappings.clear();if(missing==2)world.routes.content.erase(row.record.content.back().info.content_id);const auto before=world.routes;REQUIRE(ClassifyRow(row)==0&&row.status==UsbImportStatus::Ready);REQUIRE(world.routes==before);}
    Reset();row=Row();Registered(row);Routes(row);world.routes.mappings.at(AppId)[0]=IdOf(99);REQUIRE(ClassifyRow(row)==0&&row.status==UsbImportStatus::Incomplete);
    Reset();row=Row();Registered(row);Routes(row);DisabledBadges();world.home.clear();REQUIRE(ClassifyRow(row)==0&&row.status==UsbImportStatus::Ready);
    for(Result archive:{Result{0},MissingUsbTicket,InvalidUsbTicket,Fault}){Reset();row=Row();Registered(row);Routes(row);DisabledBadges();world.usb_headers[row.record.content.back().info.content_id].rights_id=IdOf(77);world.archives[IdOf(77)]=archive;const auto rc=ClassifyRow(row);REQUIRE(row.missing_tickets);REQUIRE(archive==Fault?rc==Fault:rc==0);if(!archive)REQUIRE(row.status==UsbImportStatus::Ready&&row.archived_tickets.size()==1);else if(archive!=Fault)REQUIRE(row.status==UsbImportStatus::TicketMissing);}
    Reset();row=Row();Registered(row);Routes(row);DisabledBadges();world.usb_headers[row.record.content.back().info.content_id].rights_id=IdOf(77);world.tickets.push_back(IdOf(77));REQUIRE(ClassifyRow(row)==0&&row.status==UsbImportStatus::AlreadyRegistered&&!row.missing_tickets&&world.archive_reads==0);
    // Shared control files cannot turn a complete USB installation into native.
    Reset();row=Row();Registered(row);Routes(row);DisabledBadges();world.physical[{5,row.record.content[1].info.content_id}]=4096;REQUIRE(ClassifyRow(row)==0&&row.registration==UsbImportRegistration::Usb);
    for(int location:{4,5}){Reset();row=Row();Native(row,location);REQUIRE(ClassifyRow(row)==0&&row.registration==UsbImportRegistration::Native);REQUIRE(world.open_database==world.close_database&&world.open_storage==world.close_storage);}
    Reset();row=Row();Native(row,5);world.physical.erase({5,row.record.content[1].info.content_id});REQUIRE(ClassifyRow(row)==0&&row.status==UsbImportStatus::Incomplete);
    Reset();row=Row();Native(row,4);world.native_headers[{4,row.record.content.back().info.content_id}].rights_id=IdOf(77);REQUIRE(ClassifyRow(row)==0&&row.status==UsbImportStatus::TicketMissing&&row.missing_tickets);
    Reset();row=Row();Registered(row);Routes(row);REQUIRE(ClassifyRow(row)==0&&row.status==UsbImportStatus::AlreadyRegistered);
    Reset();row=Row();Registered(row);Routes(row);world.files["/atmosphere/usb_badges/0100000000010000-0.ubg"]={true,Bytes(200)};REQUIRE(ClassifyRow(row)==0&&row.status==UsbImportStatus::AlreadyRegistered);
    Reset();row=Row();Registered(row);Routes(row);DisabledBadges();world.read_rc=Fault;REQUIRE(ClassifyRow(row)==Fault);
    Reset();row=Row();row.status=UsbImportStatus::Ready;auto update=Row(NcmContentMetaType_Patch,10);update.status=UsbImportStatus::AlreadyRegistered;update.registration=UsbImportRegistration::Usb;auto dlc=Row(NcmContentMetaType_AddOnContent,20);dlc.status=UsbImportStatus::AlreadyRegistered;dlc.registration=UsbImportRegistration::Usb;auto plan=Plan({row,update,dlc});REQUIRE(plan.summary.affected_games==1&&plan.summary.repairable_games==1&&plan.summary.selected_items==3);REQUIRE(std::all_of(plan.selected.begin(),plan.selected.end(),[](bool value){return value;}));
    for(auto blocked:{UsbImportStatus::Incomplete,UsbImportStatus::TicketMissing}){Reset();dlc.status=blocked;dlc.reason="Required member unavailable";plan=Plan({row,update,dlc});REQUIRE(plan.summary.blocked_games==1&&!plan.summary.repairable_games&&!plan.summary.selected_items);REQUIRE(!plan.family_reason[0].empty()&&!plan.family_reason[1].empty());}
    Reset();dlc.status=UsbImportStatus::AlreadyRegistered;dlc.registration=UsbImportRegistration::Native;plan=Plan({row,update,dlc});REQUIRE(plan.summary.selected_items==2&&!plan.selected[2]);
    Reset();update.registration=UsbImportRegistration::Superseded;plan=Plan({row,update});REQUIRE(plan.summary.blocked_games==1&&plan.summary.selected_items==0);plan=Plan({update});REQUIRE(plan.summary.affected_games==0);
    Reset();update.registration=UsbImportRegistration::Usb;auto older=row;older.record.key.version=0;older.status=UsbImportStatus::TicketMissing;plan=Plan({older,row,update});REQUIRE(plan.summary.repairable_games==1&&plan.summary.missing_ticket_games==0&&!plan.selected[0]);
    Reset();auto unknown=UsbImportTitle{};unknown.status=UsbImportStatus::Incomplete;plan=Plan({unknown});REQUIRE(plan.summary.affected_games==0);
    // A registered sibling absent from the USB scan blocks the whole family.
    Reset();row=Row();row.status=UsbImportStatus::Ready;update=Row(NcmContentMetaType_Patch,10);Registered(update);UsbImportScan scan;scan.generation=7;scan.titles={row};{Session session(nullptr,scan);REQUIRE(ReconcileFamilyMembers(session)==0);}scan.complete=true;plan=PlanUsbLibrary(scan);REQUIRE(scan.titles.size()==2&&plan.summary.blocked_games==1&&!plan.summary.selected_items);
    // A verified native base absent from USB is preserved as a dependency.
    Reset();row=Row();Native(row,4);update=Row(NcmContentMetaType_Patch,10);update.status=UsbImportStatus::Ready;scan={};scan.generation=7;scan.titles={update};{Session session(nullptr,scan);REQUIRE(ReconcileFamilyMembers(session)==0);}scan.complete=true;plan=PlanUsbLibrary(scan);REQUIRE(scan.titles.size()==2&&plan.summary.selected_items==1&&plan.summary.repairable_games==1&&scan.titles[1].registration==UsbImportRegistration::Native);
    Reset();update=Row(NcmContentMetaType_Patch,10);update.status=UsbImportStatus::Ready;scan={};scan.generation=7;scan.titles={update};{Session session(nullptr,scan);REQUIRE(ReconcileFamilyMembers(session)==0);}scan.complete=true;REQUIRE(scan.titles.size()==2&&PlanUsbLibrary(scan).summary.blocked_games==1);
    Reset();row=Row();row.status=UsbImportStatus::Ready;update=Row(NcmContentMetaType_Patch,10);Registered(update);world.apps.clear();world.home.clear();scan={};scan.generation=7;scan.titles={row};{Session session(nullptr,scan);REQUIRE(ReconcileFamilyMembers(session)==0);}scan.complete=true;REQUIRE(scan.titles.size()==2&&PlanUsbLibrary(scan).summary.blocked_games==1);
    // A native exception still requires a complete base layout and full install.
    for(bool partial:{false,true}){Reset();row=Row();if(partial)row.record.key.install_type=1;else row.record.content={row.record.content[1]};row.record.installed_meta=Raw(row.record);Native(row,4);update=Row(NcmContentMetaType_Patch,10);update.status=UsbImportStatus::Ready;scan={};scan.generation=7;scan.titles={update};{Session session(nullptr,scan);REQUIRE(ReconcileFamilyMembers(session)==0);}scan.complete=true;REQUIRE(scan.titles.size()==2&&PlanUsbLibrary(scan).summary.blocked_games==1&&scan.titles[1].registration!=UsbImportRegistration::Native);}
    Reset();row=Row();row.record.content={row.record.content[1]};row.record.installed_meta=Raw(row.record);Native(row,5);scan={};scan.generation=7;{Session session(nullptr,scan);bool healthy=true;REQUIRE(NativeRecord(session,row.record,NcmStorageId_SdCard,healthy)==0&&!healthy);}
    // Actual public scanner: no progress pointer and names=false must avoid every UI/cache call.
    Reset();row=Row();world.cnmts[row.record.content.front().info.content_id]=Cnmt(row);UsbFiles();std::atomic_bool cancel{false};REQUIRE(ScanUsbImports(nullptr,scan,7,&cancel,false)==0&&scan.complete&&scan.titles.size()==1);REQUIRE(world.cache_reads==0&&world.name_reads==0&&SummarizeUsbLibrary(scan).repairable_games==1);
    // Cleanup reads physical ownership even when current-system permissions,
    // HOME registrations and import reconciliation are not available.
    Reset();row=Row();RetailUsb(row);world.read_rc=Fault;const auto ownership_before=StateSnapshot();
    REQUIRE(ScanUsbImports(nullptr,scan,7,nullptr,false,true)==0&&scan.complete&&scan.titles.size()==1);
    REQUIRE(!scan.titles[0].record.content.empty()&&scan.titles[0].status==UsbImportStatus::Incomplete&&StateSnapshot()==ownership_before);
    Reset();cancel=true;REQUIRE(ScanUsbImports(nullptr,scan,7,&cancel,false)==Result_TransferCancelled&&!scan.complete&&world.checks==0);
    Reset();row=Row();world.cnmts[row.record.content.front().info.content_id]=Cnmt(row);UsbFiles();cancel=false;world.cancel=&cancel;world.cancel_on_list=true;REQUIRE(ScanUsbImports(nullptr,scan,7,&cancel,false)==Result_TransferCancelled&&!scan.complete&&world.cache_reads==0);
    Reset();row=Row();world.cnmts[row.record.content.front().info.content_id]=Cnmt(row);UsbFiles();ui::ProgressBox progress;REQUIRE(ScanUsbImports(&progress,scan,7)==0&&scan.complete&&progress.calls>0&&world.cache_reads>0&&world.name_reads==1);
    Reset();row=Row();world.cnmts[row.record.content.front().info.content_id]=Cnmt(row);UsbFiles();world.check_rc=Fault;REQUIRE(ScanUsbImports(nullptr,scan,7,nullptr,false)==Fault&&!scan.complete&&scan.detail.find("No game files")!=std::string::npos&&scan.detail.find("0x0000007B")!=std::string::npos);
    // 0.2.6 regression: the installed Manager NSP/forwarder is unrelated to
    // retail USB families and must never invalidate the read-only startup scan.
    for(const u64 id:{0x05004e584d470000ULL,0x05005553424c0000ULL}){
        Reset();row=Row();auto unrelated=InstalledOnly(row,id,id,NcmContentMetaType_Application);Registered(unrelated);RetailUsb(row);
        const auto before=StateSnapshot();cancel=false;
        REQUIRE(ScanUsbImports(nullptr,scan,7,&cancel,false)==0&&scan.complete&&scan.titles.size()==1);
        REQUIRE(SummarizeUsbLibrary(scan).repairable_games==1&&world.cache_reads==0&&world.name_reads==0);
        REQUIRE(StateSnapshot()==before);
    }
    // Its excluded metadata is not opened, even if it is unavailable to this scan.
    Reset();row=Row();auto unrelated=InstalledOnly(row,0x05004e584d470000ULL,0x05004e584d470000ULL,NcmContentMetaType_Application);Registered(unrelated);world.metadata.clear();RetailUsb(row);
    {const auto before=StateSnapshot();REQUIRE(ScanUsbImports(nullptr,scan,7,nullptr,false)==0&&scan.complete);REQUIRE(StateSnapshot()==before);}
    // Filtering the unrelated app cannot conceal a real absent retail sibling.
    Reset();row=Row();unrelated=InstalledOnly(row,0x05004e584d470000ULL,0x05004e584d470000ULL,NcmContentMetaType_Application);Registered(unrelated);auto absent=InstalledOnly(row,AppId+0x800,AppId,NcmContentMetaType_Patch);Registered(absent);RetailUsb(row);
    {const auto before=StateSnapshot();REQUIRE(ScanUsbImports(nullptr,scan,7,nullptr,false)==0&&scan.complete);const auto summary=SummarizeUsbLibrary(scan);REQUIRE(summary.blocked_games==1&&summary.selected_items==0&&summary.repairable_games==0);REQUIRE(StateSnapshot()==before);}
    // A malformed in-scope orphan still stops association safely, rather than
    // being ignored along with unrelated Applications.
    Reset();row=Row();auto malformed=InstalledOnly(row,AppId+0x800,AppId,NcmContentMetaType_Patch);Registered(malformed);world.apps.clear();world.home.clear();world.metadata[{5,MetaKey(malformed.record.key)}]=Bytes(sizeof(NcmContentMetaHeader));RetailUsb(row);
    {const auto before=StateSnapshot();REQUIRE(ScanUsbImports(nullptr,scan,7,nullptr,false)==0x1759&&!scan.complete);REQUIRE(scan.detail.find("could not be associated safely")!=std::string::npos);REQUIRE(StateSnapshot()==before);}
    // Unsupported child IDs attached to a checked family are rejected whether
    // discovered through HOME or bounded NCM-only orphan association.
    for(bool home:{false,true}){
        Reset();row=Row();auto child=InstalledOnly(row,0x05004e584d470800ULL,AppId,NcmContentMetaType_Patch);Registered(child);if(!home){world.apps.clear();world.home.clear();}RetailUsb(row);
        const auto before=StateSnapshot();REQUIRE(ScanUsbImports(nullptr,scan,7,nullptr,false)==0x1759&&!scan.complete);REQUIRE(scan.detail.find("unsupported title ID for this game family")!=std::string::npos);REQUIRE(StateSnapshot()==before);
    }
    Reset();row=Row();auto attached=InstalledOnly(row,0x05004e584d470000ULL,AppId,NcmContentMetaType_Application);Registered(attached);RetailUsb(row);
    {const auto before=StateSnapshot();REQUIRE(ScanUsbImports(nullptr,scan,7,nullptr,false)==0x1759&&!scan.complete);REQUIRE(StateSnapshot()==before);}
    std::cout<<"USB repair actual classifier/native/route/ticket/badge/family reconciliation/planner/background scan: "<<cases<<" cases, "<<checks<<" assertions passed\n";return 0;
}
}
int main(){return sphaira::nexusapp::Main();}
