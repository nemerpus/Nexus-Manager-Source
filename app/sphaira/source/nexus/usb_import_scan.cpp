#include "nexus/localize.hpp"
#include "nexus/smb_mount.hpp"
// SPDX-License-Identifier: GPL-3.0-or-later
#include "nexus/usb_import_scan.hpp"
#include "nexus/usb_import_scan_core.hpp"
#include "nexus/usb_import_diagnostic.hpp"
#include "nexus/usb_ticket_store.hpp"
#include "nexus/index_repair_core.hpp"
#include "nexus/bootstrap.h"
#include "nexus/badge_format.hpp"
#include "nexus/manager.hpp"
#include "yati/nx/nca.hpp"
#include "yati/nx/crypto.hpp"
#include "yati/nx/es.hpp"
#include "yati/nx/ns.hpp"
#include "title_info.hpp"
#include "defines.hpp"
#include <algorithm>
#include <array>
#include <cstdio>
#include <cstring>
#include <map>
#include <set>
#include <tuple>

namespace sphaira::nexusapp {
namespace {
namespace core=nexus::usb_import;
constexpr Result MissingUsb=MAKERESULT(140,205);
constexpr size_t MaxFiles=65536,MaxTitles=4096,MaxReferences=131072,MaxStoredMeta=32*1024*1024;
using Id=std::array<u8,16>;
using Key=std::tuple<u64,u32,u8>;
Id ContentId(const NcmContentId& id){Id result{};std::memcpy(result.data(),&id,result.size());return result;}
Key MetaKey(const NcmContentMetaKey& key){return {key.id,key.version,key.type};}
std::string TitleId(u64 id){char text[17]{};std::snprintf(text,sizeof(text),"%016llX",static_cast<unsigned long long>(id));return text;}
std::string SafeName(std::string name){for(auto& c:name)if(static_cast<unsigned char>(c)<32||c==127)c=' ';return name;}
struct File {NcmContentId id{};std::string path;u64 size{};};
struct HeaderInfo {FsRightsId rights{};u64 size{};u8 type{};bool valid{};};
bool SameKey(const NcmContentMetaKey& a,const NcmContentMetaKey& b){return MetaKey(a)==MetaKey(b)&&a.install_type==b.install_type;}
bool HeaderType(u8 ncm_type,u8 nca_type){
    switch(ncm_type){
        case NcmContentType_Meta:return nca_type==nca::ContentType_Meta;
        case NcmContentType_Program:return nca_type==nca::ContentType_Program;
        case NcmContentType_Control:return nca_type==nca::ContentType_Control;
        case NcmContentType_HtmlDocument:return nca_type==nca::ContentType_Manual;
        case NcmContentType_Data:return nca_type==nca::ContentType_Data||nca_type==nca::ContentType_PublicData;
        case NcmContentType_LegalInformation:return nca_type==nca::ContentType_Manual||nca_type==nca::ContentType_PublicData;
        default:return false;
    }
}
struct Session {
    ui::ProgressBox* progress;
    UsbImportScan& scan;
    const std::atomic_bool* cancel;
    const char* stage{"opening the read-only USB library scan"_nx};
    nexus::Client usb;
    keys::Keys keys{};
    NcmContentMetaDatabase db{};
    NcmContentStorage native{};
    FsFileSystem sd{};
    nexus::repair::Indexes routes;
    bool ncm_open{},es_open{},ns_open{},spl_open{},sd_open{};
    std::vector<FsRightsId> tickets;
    std::vector<NcmContentMetaKey> installed;
    std::map<u64,std::vector<ncm::ContentStorageRecord>> applications;
    std::set<u64> home_applications;
    std::map<Id,HeaderInfo> headers;
    Session(ui::ProgressBox* p,UsbImportScan& s,const std::atomic_bool* c):progress(p),scan(s),cancel(c){}
    ~Session(){ncmContentStorageClose(&native);ncmContentMetaDatabaseClose(&db);if(sd_open)fsFsClose(&sd);if(ncm_open)ncmExit();if(es_open)es::Exit();if(ns_open)ns::Exit();if(spl_open)splCryptoExit();keys={};}
    Result Cancelled(){if(cancel&&cancel->load())return Result_TransferCancelled;return progress?progress->ShouldExitResult():0;}
    Result Check(){R_TRY(Cancelled());return usb.Check(scan.generation);}
    Result ReadSd(const std::string& name,nexus::repair::Image& out,size_t limit){
        stage="reading a bounded physical-SD routing index or HOME icon cache"_nx;
        R_TRY(Check());out={};char path[FS_MAX_PATH]{};snprintf(path,sizeof(path),"%s",name.c_str());FsFile file{};
        const auto opened=fsFsOpenFile(&sd,path,FsOpenMode_Read,&file);if(opened==MAKERESULT(2,1))return 0;R_TRY(opened);
        s64 size{};auto rc=fsFileGetSize(&file,&size);u64 got{};
        if(R_SUCCEEDED(rc)&&(size<0||static_cast<u64>(size)>limit))rc=nexus::Invalid;
        if(R_SUCCEEDED(rc)){out.data.resize(size);rc=fsFileRead(&file,0,out.data.data(),out.data.size(),FsReadOption_None,&got);}
        fsFileClose(&file);R_TRY(rc);R_UNLESS(got==out.data.size(),nexus::Invalid);out.exists=true;return Check();
    }
    Result Probe(u64 expected){
        R_TRY(Cancelled());
        stage="checking the connected USB drive"_nx;
        nexus::Status status{};R_TRY(usb.Query(status));R_UNLESS(status.Available()&&(!expected||status.generation==expected),nexus::Unavailable);
        scan.generation=status.generation;
        return Check();
    }
    Result ReadTicketSnapshot(std::vector<FsRightsId>& out){
        out.clear();stage="reading current-system game permissions"_nx;
        for(bool personal:{false,true}){
            R_TRY(Check());s32 count{},written{},after{};
            R_TRY(personal?es::CountPersonalizedTicket(&count):es::CountCommonTicket(&count));
            R_UNLESS(count>=0&&count<=65536,nexus::Invalid);std::vector<FsRightsId> page(count);
            if(count)R_TRY(personal?es::ListPersonalizedTicket(&written,page.data(),count):es::ListCommonTicket(&written,page.data(),count));
            R_TRY(personal?es::CountPersonalizedTicket(&after):es::CountCommonTicket(&after));
            R_UNLESS(written==count&&after==count,nexus::Invalid);
            std::sort(page.begin(),page.end(),[](const auto& a,const auto& b){return std::memcmp(&a,&b,sizeof(a))<0;});
            for(size_t i=0;i<page.size();++i){
                R_UNLESS(es::IsRightsIdValid(page[i])&&(!i||std::memcmp(&page[i-1],&page[i],sizeof(page[i]))),nexus::Invalid);
            }
            out.insert(out.end(),page.begin(),page.end());
        }
        std::sort(out.begin(),out.end(),[](const auto& a,const auto& b){return std::memcmp(&a,&b,sizeof(a))<0;});
        return Check();
    }
    Result CheckTicketsUnchanged(){
        std::vector<FsRightsId> current;R_TRY(ReadTicketSnapshot(current));
        R_UNLESS(current.size()==tickets.size()&&std::equal(current.begin(),current.end(),tickets.begin(),[](const auto& a,const auto& b){return !std::memcmp(&a,&b,sizeof(a));}),nexus::Invalid);
        return 0;
    }
    Result Open(u64 expected,bool ownership_only=false){
        R_TRY(Probe(expected));
        if(ownership_only){
            stage="opening the content-header key service"_nx;R_TRY(splCryptoInitialize());spl_open=true;
            R_TRY(keys::parse_keys(keys,false));return Check();
        }
        if(!nexusHasSdBootstrap(envGetLoaderInfo(),envGetLoaderInfoSize())){
            stage="checking the physical SD view"_nx;
            NexusVsdStatus vs{};R_TRY(usb.VirtualSdStatus(vs));R_UNLESS(!(vs.flags&(NEXUS_VSD_ACTIVE|NEXUS_VSD_ARMED)),nexus::Unavailable);
        }
        stage="opening the physical SD filesystem"_nx;R_TRY(fsOpenSdCardFileSystem(&sd));sd_open=true;
        nexus::repair::Snapshot indexes;
        for(size_t i=0;i<indexes.size();++i)R_TRY(ReadSd(nexus::repair::Live(i),indexes[i],nexus::repair::MaxFile));
        if(!nexus::repair::Decode(indexes,routes)){scan.detail="The saved USB routing indexes are damaged or unsupported. Nothing was changed. Restore the saved routing backup before repairing games."_nx;return nexus::Invalid;}
        stage="opening the content manager and physical SD content database"_nx;
        R_TRY(ncmInitialize());ncm_open=true;R_TRY(ncmOpenContentMetaDatabase(&db,NcmStorageId_SdCard));
        R_TRY(OpenStorage(Target::Sd,native));
        stage="opening the game-permission and HOME registration services"_nx;
        R_TRY(es::Initialize());es_open=true;R_TRY(ns::Initialize());ns_open=true;
        bool home_complete=false;
        for(s32 offset=0;offset<65536;offset+=128){
            R_TRY(Check());NsApplicationRecord page[128]{};s32 count{};R_TRY(nsListApplicationRecord(page,128,offset,&count));
            R_UNLESS(count>=0&&count<=128,nexus::Invalid);
            for(s32 i=0;i<count;++i)home_applications.insert(page[i].application_id);
            if(count<128){home_complete=true;break;}
        }
        R_UNLESS(home_complete,nexus::Invalid);
        stage="opening the content-header key service"_nx;R_TRY(splCryptoInitialize());spl_open=true;
        auto result=keys::parse_keys(keys,false);
        if(R_FAILED(result))scan.detail="The system could not open its content-header key. No game files or registrations were changed."_nx;
        R_TRY(result);
        R_TRY(ReadTicketSnapshot(tickets));
        stage="listing the existing SD content metadata"_nx;installed.resize(16384);s32 total{},written{};
        R_TRY(ncmContentMetaDatabaseList(&db,&total,&written,installed.data(),installed.size(),NcmContentMetaType_Unknown,0,0,UINT64_MAX,NcmContentInstallType_Full));
        R_UNLESS(total>=0&&written==total&&written<=static_cast<s32>(installed.size()),nexus::Invalid);installed.resize(written);
        return Check();
    }
    Result Read(const std::string& path,u64 offset,void* output,size_t size){
        auto* bytes=static_cast<u8*>(output);size_t done{};
        while(done<size){
            R_TRY(Check());const auto count=std::min(size-done,size_t{65536});u64 got{};
            R_TRY(usb.Read(scan.generation,path,offset+done,bytes+done,count,got));
            R_UNLESS(got==count,nexus::Invalid);done+=count;
        }
        return Check();
    }
    Result Header(const File& file,nca::Header& header,bool& valid){
        valid=false;header={};R_TRY(Check());nexus::Info stat{};
        const auto sr=usb.Stat(scan.generation,file.path,stat);if(sr==MissingUsb)return 0;R_TRY(sr);
        if(stat.directory||stat.size!=file.size||stat.size<sizeof(header))return 0;
        R_TRY(Read(file.path,0,&header,sizeof(header)));
        if(!header.IsValid()&&R_FAILED(nca::DecryptHeader(&header,keys,header)))return 0;
        valid=header.size==stat.size&&header.content_type<=nca::ContentType_PublicData;
        return 0;
    }
    Result RawFrom(NcmContentMetaDatabase& database,const NcmContentMetaKey& key,std::vector<u8>& raw){
        stage="reading bounded existing content metadata"_nx;
        u64 size{},got{};R_TRY(ncmContentMetaDatabaseGetSize(&database,&size,&key));
        R_UNLESS(size>=sizeof(NcmContentMetaHeader)&&size<=core::MaxMetaBytes,nexus::Invalid);
        raw.resize(size);R_TRY(ncmContentMetaDatabaseGet(&database,&key,&got,raw.data(),raw.size()));R_UNLESS(got==size,nexus::Invalid);return Check();
    }
    Result Raw(const NcmContentMetaKey& key,std::vector<u8>& raw){return RawFrom(db,key,raw);}
    Result AppRecords(u64 id,const std::vector<ncm::ContentStorageRecord>*& result){
        auto it=applications.find(id);if(it==applications.end()){
            std::vector<ncm::ContentStorageRecord> records;R_TRY(Check());R_TRY(ns::GetApplicationRecords(id,records));
            it=applications.emplace(id,std::move(records)).first;
        }
        result=&it->second;return 0;
    }
};

Result ReadCnmt(Session& s,const File& file,const nca::Header& header,std::vector<u8>& raw,std::string& reason){
    reason="Metadata uses an unsupported or damaged filesystem layout."_nx;
    if(es::IsRightsIdValid(header.rights_id)){reason="The content metadata itself requires an unavailable title-key reader."_nx;return 0;}
    for(size_t index=0;index<NCA_SECTION_TOTAL;++index){
        const auto& fs=header.fs_header[index];const auto& section=header.fs_table[index];
        if(!section.IsValid())continue;
        if(!fs.IsValid()||fs.fs_type!=nca::FileSystemType_PFS0||fs.hash_type!=nca::HashType_HierarchicalSha256||
            section.GetOffset()<sizeof(header)||section.GetOffsetEnd()<=section.GetOffset()||section.GetOffsetEnd()>file.size)continue;
        u8 fs_hash[32]{};sha256CalculateHash(fs_hash,&fs,sizeof(fs));
        if(std::memcmp(fs_hash,&header.fs_header_hash[index],sizeof(fs_hash)))continue;
        const auto& layer=fs.hash_data.hierarchical_sha256_data.pfs0_layer;
        if(fs.hash_data.hierarchical_sha256_data.layer_count!=2||layer.size<16||!core::Range(layer.offset,layer.size,section.GetSize()))continue;
        const bool encrypted=fs.encryption_type==nca::EncryptionType_AesCtr||fs.encryption_type==nca::EncryptionType_AesCtrSkipLayerHash;
        if(!encrypted&&fs.encryption_type!=nca::EncryptionType_None)continue;
        auto decrypted=header;
        if(encrypted){
            if(header.kaek_index>=3||header.GetKeyGeneration()>0x20)continue;
            const auto rc=nca::DecryptKeak(s.keys,decrypted);
            if(R_FAILED(rc)){reason="The system could not decrypt this metadata's content-key generation."_nx;continue;}
        }
        const auto read=[&](u64 offset,size_t size,std::vector<u8>& out)->Result{
            R_UNLESS(size<=core::MaxMetaBytes&&core::Range(offset,size,layer.size),nexus::Invalid);
            const u64 absolute=section.GetOffset()+layer.offset+offset,aligned=encrypted?absolute&~u64{15}:absolute,pad=absolute-aligned;
            R_UNLESS(core::Range(aligned,size+pad,file.size),nexus::Invalid);out.resize(size+pad);
            R_TRY(s.Read(file.path,aligned,out.data(),out.size()));
            if(encrypted){u8 ctr[16]{};crypto::SetCtr(ctr,fs.section_ctr,aligned);Aes128CtrContext ctx;aes128CtrContextCreate(&ctx,decrypted.key_area[2].area,ctr);aes128CtrCrypt(&ctx,out.data(),out.data(),out.size());}
            if(pad)out.erase(out.begin(),out.begin()+pad);
            return 0;
        };
        std::vector<u8> table;R_TRY(read(0,16,table));if(std::memcmp(table.data(),"PFS0",4))continue;
        const auto count=core::Read<u32>(table,4),strings=core::Read<u32>(table,8);
        const u64 table_size=16+u64(count)*24+strings;
        if(!count||count>1024||table_size>65536||table_size>layer.size)continue;
        R_TRY(read(0,table_size,table));u64 offset{},size{};
        if(!core::FindCnmt(table,layer.size,offset,size))continue;
        R_TRY(read(offset,size,raw));reason.clear();return 0;
    }
    return 0;
}

bool MakeRecord(const core::Meta& meta,const File& file,yati::ExistingUsbRecord& result){
    result={};result.key.id=meta.id;result.key.version=meta.version;result.key.type=meta.type;result.key.install_type=NcmContentInstallType_Full;result.application_id=meta.application_id;
    yati::ExistingUsbContent self{};self.info.content_id=file.id;self.info.content_type=NcmContentType_Meta;ncmU64ToContentInfoSize(file.size,&self.info);result.content.push_back(self);
    for(const auto& item:meta.content){
        // Delta fragments are optional patch-install payloads. The existing
        // installer deliberately excludes them from the installed content DB.
        if(item.type==NcmContentType_DeltaFragment)continue;
        yati::ExistingUsbContent content{};std::memcpy(&content.info.content_id,item.id.data(),item.id.size());ncmU64ToContentInfoSize(item.size,&content.info);
        content.info.attr=item.attributes;content.info.content_type=item.type;content.info.id_offset=item.id_offset;content.expected_hash=item.hash;content.has_expected_hash=true;
        if(ContentId(content.info.content_id)==ContentId(file.id))return false;
        result.content.push_back(content);
    }
    if(result.content.size()<2)return false;
    NcmContentMetaHeader h{};std::memcpy(&h,meta.header.data(),sizeof(h));h.content_count=result.content.size();h.storage_id=0;
    const auto metadata_size=sizeof(h)+meta.extended.size()+result.content.size()*sizeof(NcmContentInfo)+meta.tail.size();
    if(metadata_size>1024*1024)return false; // Same per-record bound as the import journal.
    result.installed_meta.resize(metadata_size);
    auto* at=result.installed_meta.data();std::memcpy(at,&h,sizeof(h));at+=sizeof(h);
    std::memcpy(at,meta.extended.data(),meta.extended.size());at+=meta.extended.size();
    for(const auto& content:result.content){std::memcpy(at,&content.info,sizeof(content.info));at+=sizeof(content.info);}
    if(!meta.tail.empty())std::memcpy(at,meta.tail.data(),meta.tail.size());
    return true;
}

void PreviewIdentity(UsbImportTitle& row,const nca::Header& header,std::span<const u8> raw,bool names){
    // Retain a bounded identity for an incomplete newer CNMT, so selecting the
    // latest version cannot silently fall back to an older complete copy.
    if(raw.size()<32||!core::SupportedType(raw[12]))return;
    const auto id=core::Read<u64>(raw,0);if(!core::UserId(id)||id!=header.program_id)return;
    row.record.key.id=id;row.record.key.version=core::Read<u32>(raw,8);row.record.key.type=raw[12];row.record.key.install_type=NcmContentInstallType_Full;
    const auto ext=core::Read<u16>(raw,14);
    if(raw[12]==NcmContentMetaType_Application)row.record.application_id=id;
    else if(core::Range(32,ext,raw.size())&&ext>=(raw[12]==NcmContentMetaType_DataPatch?16u:8u))
        row.record.application_id=core::Read<u64>(raw,raw[12]==NcmContentMetaType_DataPatch?40:32);
    if(!core::UserId(row.record.application_id))row.record.application_id=0;
    row.name=names&&row.record.application_id?SafeName(title::GetCachedTitleName(row.record.application_id)):std::string{};
    if(row.name.empty())row.name=TitleId(row.record.application_id?row.record.application_id:id);
}

bool SameReferences(std::span<const u8> raw,const yati::ExistingUsbRecord& record){
    NcmContentMetaHeader h{};if(raw.size()<sizeof(h))return false;std::memcpy(&h,raw.data(),sizeof(h));
    const size_t at=sizeof(h)+h.extended_header_size;
    if(h.content_count!=record.content.size()||!core::Range(at,u64(h.content_count)*sizeof(NcmContentInfo)+u64(h.content_meta_count)*sizeof(NcmContentMetaInfo),raw.size()))return false;
    std::set<Id> seen;
    for(size_t i=0;i<h.content_count;++i){
        NcmContentInfo info{};std::memcpy(&info,raw.data()+at+i*sizeof(info),sizeof(info));
        if(!seen.insert(ContentId(info.content_id)).second)return false;
        if(std::memcmp(&record.content[i].info,&info,sizeof(info)))return false;
    }
    return true;
}

Result NativeRecord(Session& s,const yati::ExistingUsbRecord& record,NcmStorageId location,bool& healthy,bool* missing_ticket=nullptr){
    healthy=false;
    if(record.key.install_type!=NcmContentInstallType_Full)return 0;
    std::vector<nexus::recovery::Content> references;size_t metas{},data{};
    for(const auto& content:record.content){nexus::recovery::Content item{};memcpy(item.id.data(),&content.info.content_id,16);ncmContentInfoSizeToU64(&content.info,&item.size);item.type=content.info.content_type;item.offset=content.info.id_offset;references.push_back(item);metas+=item.type==NcmContentType_Meta;data+=item.type==NcmContentType_Data;}
    nexus::recovery::Maps layout;
    if(metas!=1||!nexus::recovery::Add(layout,record.key.id,record.key.type==NcmContentMetaType_Application,references)||
        ((record.key.type==NcmContentMetaType_AddOnContent||record.key.type==NcmContentMetaType_DataPatch)&&!data))return 0;
    NcmContentMetaDatabase internal_db{};NcmContentStorage internal_storage{};
    ON_SCOPE_EXIT(ncmContentStorageClose(&internal_storage);ncmContentMetaDatabaseClose(&internal_db));
    auto* database=&s.db;auto* storage=&s.native;
    if(location==NcmStorageId_BuiltInUser){
        R_TRY(ncmOpenContentMetaDatabase(&internal_db,location));R_TRY(ncmOpenContentStorage(&internal_storage,location));
        database=&internal_db;storage=&internal_storage;
    }else R_UNLESS(location==NcmStorageId_SdCard,nexus::Invalid);
    bool exists{};R_TRY(ncmContentMetaDatabaseHas(database,&exists,&record.key));if(!exists)return 0;
    std::vector<u8> raw;R_TRY(s.RawFrom(*database,record.key,raw));if(!SameReferences(raw,record))return 0;
    for(const auto& content:record.content){
        R_TRY(s.Check());R_TRY(ncmContentStorageHas(storage,&exists,&content.info.content_id));if(!exists)return 0;
        s64 size{};u64 expected{};ncmContentInfoSizeToU64(&content.info,&expected);
        R_TRY(ncmContentStorageGetSizeFromContentId(storage,&size,&content.info.content_id));
        if(size<0||static_cast<u64>(size)!=expected)return 0;
        nca::Header header{};R_TRY(ncmContentStorageReadContentIdFile(storage,&header,sizeof(header),&content.info.content_id,0));
        if(!header.IsValid()&&R_FAILED(nca::DecryptHeader(&header,s.keys,header)))return 0;
        if(header.size!=expected||!HeaderType(content.info.content_type,header.content_type))return 0;
        if(es::IsRightsIdValid(header.rights_id)&&!es::IsRightsIdFound(header.rights_id,s.tickets)){if(missing_ticket)*missing_ticket=true;return 0;}
    }
    healthy=true;return s.Check();
}
[[maybe_unused]] Result BadgeHealthy(Session& s,u64 application,bool& healthy){
    healthy=true;nexus::repair::Image disabled;
    R_TRY(s.ReadSd("/atmosphere/usb_badges/disabled",disabled,16));if(disabled.exists)return 0;
    for(unsigned variant=0;variant<(hosversionAtLeast(21,0,0)?2u:1u);++variant){
        char path[128];snprintf(path,sizeof(path),"/atmosphere/usb_badges/%016llx-%u.ubg",static_cast<unsigned long long>(application),variant);
        nexus::repair::Image image;R_TRY(s.ReadSd(path,image,1024*1024));
        if(!image.exists||image.data.size()<sizeof(nexus_badge::Header)){healthy=false;continue;}
        nexus_badge::Header header{};memcpy(&header,image.data.data(),sizeof(header));const auto dimension=variant?174u:256u;
        if(!nexus_badge::Valid(header,application,image.data.size())||header.dimension!=dimension||header.flags!=3){healthy=false;continue;}
        const auto* jpeg=image.data.data()+sizeof(header);u8 hash[32]{};sha256CalculateHash(hash,jpeg,header.jpeg_size);
        if(memcmp(hash,header.jpeg_hash,sizeof(hash))||!nexus_badge::Jpeg(jpeg,header.jpeg_size,dimension))healthy=false;
    }
    return s.Check();
}
Result Classify(Session& s,UsbImportTitle& row){
    auto& record=row.record;bool incomplete{},native_content{};std::set<Id> rights_seen;
    // Old metadata may remain after an update. It is not a broken current
    // game and must not trigger ticket recovery or a downgrade attempt.
    for(const auto& key:s.installed)if(key.id==record.key.id&&key.type==record.key.type&&key.version>record.key.version){
        row.status=UsbImportStatus::AlreadyRegistered;row.registration=UsbImportRegistration::Superseded;
        row.reason="A newer version is already registered. This older USB copy is kept and does not need repair."_nx;return s.Check();
    }
    for(const auto& content:record.content){
        R_TRY(s.Check());u64 expected{};ncmContentInfoSizeToU64(&content.info,&expected);
        const auto it=s.headers.find(ContentId(content.info.content_id));
        if(it==s.headers.end()||!it->second.valid||it->second.size!=expected||!HeaderType(content.info.content_type,it->second.type)){
            if(!incomplete)row.reason="Missing, wrong-size or unreadable content: "_nx+HexId(&content.info.content_id)+".nca";
            incomplete=true;continue;
        }
        if(content.info.content_type==NcmContentType_Program||content.info.content_type==NcmContentType_Data){
            bool on_sd{};R_TRY(ncmContentStorageHas(&s.native,&on_sd,&content.info.content_id));native_content|=on_sd;
        }
        const auto& rights=it->second.rights;
        if(es::IsRightsIdValid(rights)){
            Id id{};std::memcpy(id.data(),&rights,id.size());
            if(rights_seen.insert(id).second)row.required_tickets.push_back(rights);
        }
    }
    if(incomplete){row.status=UsbImportStatus::Incomplete;return 0;}
    for(const auto& rights:row.required_tickets){
        if(es::IsRightsIdFound(rights,s.tickets))continue;
        row.missing_tickets=true;
        R_TRY(s.Check());UsbTicketPair pair;const auto rc=LoadUsbTicketPair(s.scan.generation,rights,pair);
        if(rc==MissingUsbTicket||rc==InvalidUsbTicket){
            row.status=UsbImportStatus::TicketMissing;
            row.reason=rc==InvalidUsbTicket?"The required ticket was not found in the current system. The USB backup cannot be used for this console. Reinstall from your original backup; do not delete a working game."_nx:"The required ticket was not found in the current system. No usable backup is available on USB. Reinstall from your original backup if this game cannot launch; do not delete a working game."_nx;
            return 0;
        }
        R_TRY(rc);row.archived_tickets.push_back(rights);
    }
    const std::vector<ncm::ContentStorageRecord>* applications{};R_TRY(s.AppRecords(record.application_id,applications));
    const ncm::ContentStorageRecord* native_record{};
    for(const auto& registered:*applications){
        if(registered.key.id!=record.key.id||registered.key.type!=record.key.type)continue;
        if(!SameKey(registered.key,record.key)||(registered.storage_id!=NcmStorageId_SdCard&&registered.storage_id!=NcmStorageId_BuiltInUser)){
            row.status=UsbImportStatus::Incomplete;
            row.reason="A different version or unsupported storage location is already registered for this item. Use the installer to update it; this repair will not downgrade or move it."_nx;
            return 0;
        }
        if(registered.storage_id==NcmStorageId_BuiltInUser||native_content){
            if(native_record){row.status=UsbImportStatus::Incomplete;row.reason="More than one native storage record claims this item. Resolve the existing installation before repairing its USB family."_nx;return 0;}
            native_record=&registered;
        }
    }
    if(native_record||native_content){
        bool healthy{};if(native_record)R_TRY(NativeRecord(s,record,static_cast<NcmStorageId>(native_record->storage_id),healthy,&row.missing_tickets));
        if(healthy&&!row.missing_tickets&&s.home_applications.contains(record.application_id)){
            row.status=UsbImportStatus::AlreadyRegistered;row.registration=UsbImportRegistration::Native;
            row.reason="This exact item is registered on native SD/internal storage with its required files and permissions. It will be preserved; no USB routing or native content will be changed."_nx;
        }else{
            row.status=row.missing_tickets?UsbImportStatus::TicketMissing:UsbImportStatus::Incomplete;
            row.reason="This item has a native SD/internal installation that is incomplete, conflicting, or missing current-system permissions. Use the installer or Move to USB; USB family repair will not repoint native content."_nx;
        }
        return 0;
    }
    const NcmContentMetaKey* existing{};
    for(const auto& key:s.installed){
        if(key.id!=record.key.id||key.type!=record.key.type)continue;
        if(key.version>record.key.version){row.status=UsbImportStatus::AlreadyRegistered;row.registration=UsbImportRegistration::Superseded;row.reason="A newer version is already registered in this system. This older USB version will not be published or used to repair the family."_nx;return 0;}
        if(SameKey(key,record.key))existing=&key;
    }
    auto routes=s.routes;std::vector<nexus::recovery::Content> references;
    for(const auto& content:record.content){nexus::recovery::Content item{};memcpy(item.id.data(),&content.info.content_id,16);ncmContentInfoSizeToU64(&content.info,&item.size);item.type=content.info.content_type;item.offset=content.info.id_offset;references.push_back(item);}
    const auto routing=nexus::repair::Merge(routes,record.key.id,record.key.type==NcmContentMetaType_Application,references);
    if(routing!=nexus::repair::MergeResult::Intact&&routing!=nexus::repair::MergeResult::Changed){
        row.status=UsbImportStatus::Incomplete;row.reason="The existing USB routing entries conflict with this game's content or exceed the safe index limit. Restore the correct backup or resolve the existing installation before repairing this family."_nx;return 0;
    }
    if(existing){
        std::vector<u8> raw;R_TRY(s.Raw(*existing,raw));
        if(raw.size()>1024*1024){row.status=UsbImportStatus::Incomplete;row.reason="The current system's metadata exceeds the recovery journal's safe size limit. Use the installer for this title."_nx;return 0;}
        if(!SameReferences(raw,record)){row.status=UsbImportStatus::Incomplete;row.reason="This title and version are already registered with different content. Reinstall from your original backup to resolve the conflict."_nx;return 0;}
        record.installed_meta=std::move(raw);
        const bool home=s.home_applications.contains(record.application_id)&&std::any_of(applications->begin(),applications->end(),[&](const auto& r){return r.storage_id==NcmStorageId_SdCard&&SameKey(r.key,record.key);});
        if(home&&row.archived_tickets.empty()&&routing==nexus::repair::MergeResult::Intact){
            row.registration=UsbImportRegistration::Usb;
            // HOME badge images are cosmetic. A missing cache must not offer
            // another full game repair after registration already succeeded.
            // The separate Refresh HOME USB icons action owns that retry.
            row.status=UsbImportStatus::AlreadyRegistered;
            row.reason="Game files, HOME records, USB links and permissions are present. No game repair is needed. Missing USB labels on HOME can be refreshed separately."_nx;
            return s.Check();
        }
    }
    row.status=UsbImportStatus::Ready;
    row.reason=row.archived_tickets.empty()?"Missing registration or USB routing can be restored from the existing USB files. The whole game family's hashes will be checked before repair."_nx:"Current-system permissions are missing. Valid saved tickets for this console can be restored after the whole USB game family is verified."_nx;
    return s.Check();
}

bool InstalledIdentity(const NcmContentMetaKey& key,std::span<const u8> raw,u64& application){
    application=0;NcmContentMetaHeader header{};if(raw.size()<sizeof(header)||!core::SupportedType(key.type))return false;
    memcpy(&header,raw.data(),sizeof(header));if(!core::Range(sizeof(header),header.extended_header_size,raw.size()))return false;
    if(key.type==NcmContentMetaType_Application)application=key.id;
    else{
        const size_t offset=key.type==NcmContentMetaType_DataPatch?8:0;
        if(header.extended_header_size<offset+sizeof(u64))return false;
        memcpy(&application,raw.data()+sizeof(header)+offset,sizeof(application));
    }
    return core::UserId(application);
}
bool InstalledRecord(const NcmContentMetaKey& key,u64 application,const std::vector<u8>& raw,yati::ExistingUsbRecord& record){
    u64 found{};if(key.install_type!=NcmContentInstallType_Full||!InstalledIdentity(key,raw,found)||found!=application)return false;
    NcmContentMetaHeader header{};memcpy(&header,raw.data(),sizeof(header));const size_t offset=sizeof(header)+header.extended_header_size;
    if(!header.content_count||header.content_count>4096||!core::Range(offset,u64(header.content_count)*sizeof(NcmContentInfo)+u64(header.content_meta_count)*sizeof(NcmContentMetaInfo),raw.size()))return false;
    record={};record.key=key;record.application_id=application;record.installed_meta=raw;std::set<Id> seen;
    for(size_t i=0;i<header.content_count;++i){
        yati::ExistingUsbContent content{};memcpy(&content.info,raw.data()+offset+i*sizeof(content.info),sizeof(content.info));
        u64 size{};ncmContentInfoSizeToU64(&content.info,&size);const auto id=ContentId(content.info.content_id);
        if(!nexus::recovery::Nonzero(id)||!seen.insert(id).second||size<0xc00||content.info.content_type>NcmContentType_DeltaFragment)return false;
        record.content.push_back(content);
    }
    return true;
}
Result ReconcileFamilyMembers(Session& s){
    std::set<u64> families;std::set<Key> seen;
    for(const auto& row:s.scan.titles){
        if(core::UserId(row.record.application_id))families.insert(row.record.application_id);
        if(row.record.key.id)seen.insert(MetaKey(row.record.key));
    }
    const auto append=[&](const NcmContentMetaKey& key,NcmStorageId storage,u64 application,const std::vector<u8>* saved)->Result{
        // A child explicitly associated with a retail game must obey the
        // same ID policy as scanned CNMTs. Do not silently omit it from the
        // family plan merely because PlanUsbLibrary cannot select its ID.
        if(!core::UserId(key.id)){
            s.scan.detail="An existing record uses an unsupported title ID for this game family. No registrations were changed. Resolve that record before repairing the family."_nx;
            return nexus::Invalid;
        }
        if(!seen.insert(MetaKey(key)).second)return 0;
        R_UNLESS(s.scan.titles.size()<MaxTitles,nexus::Invalid);R_TRY(s.Check());
        UsbImportTitle row;row.name=TitleId(application);row.record.key=key;row.record.application_id=application;
        row.reason="This system has a game-family registration that was not found as a complete record on this USB drive. Restore its missing files from your original backup before repairing the family."_nx;
        std::vector<u8> raw;
        if(saved)raw=*saved;
        else if(storage==NcmStorageId_SdCard||storage==NcmStorageId_BuiltInUser){
            NcmContentMetaDatabase internal{};ON_SCOPE_EXIT(ncmContentMetaDatabaseClose(&internal));auto* database=&s.db;
            if(storage==NcmStorageId_BuiltInUser){R_TRY(ncmOpenContentMetaDatabase(&internal,storage));database=&internal;}
            bool present{};R_TRY(ncmContentMetaDatabaseHas(database,&present,&key));if(present)R_TRY(s.RawFrom(*database,key,raw));
        }
        if(!raw.empty()&&InstalledRecord(key,application,raw,row.record)){
            const std::vector<ncm::ContentStorageRecord>* records{};R_TRY(s.AppRecords(application,records));
            const bool home=s.home_applications.contains(application)&&std::any_of(records->begin(),records->end(),[&](const auto& r){return r.storage_id==storage&&SameKey(r.key,key);});
            bool native{};if(home&&(storage==NcmStorageId_SdCard||storage==NcmStorageId_BuiltInUser))R_TRY(NativeRecord(s,row.record,storage,native,&row.missing_tickets));
            if(native){row.status=UsbImportStatus::AlreadyRegistered;row.registration=UsbImportRegistration::Native;row.reason="This family member is already complete on native SD/internal storage with current-system permissions. Its content, records and routing will be preserved."_nx;}
            else if(row.missing_tickets){row.status=UsbImportStatus::TicketMissing;row.reason="The native family member is missing current-system permissions. Restore it using the original installer/backup before repairing the USB family."_nx;}
        }
        s.scan.titles.push_back(std::move(row));return 0;
    };
    // HOME records also include native members which need not have USB copies.
    for(const auto application:families){
        const std::vector<ncm::ContentStorageRecord>* records{};R_TRY(s.AppRecords(application,records));
        for(const auto& record:*records)if(core::SupportedType(record.key.type))R_TRY(append(record.key,static_cast<NcmStorageId>(record.storage_id),application,nullptr));
    }
    // An NCM-only orphan must not disappear merely because its HOME record is
    // missing too. Association comes from bounded metadata, never ID arithmetic.
    size_t bytes{};
    for(const auto& key:s.installed){
        if(seen.contains(MetaKey(key))||!core::SupportedType(key.type))continue;
        // An Application is its own family. Manager and other HOME forwarders
        // use non-retail IDs (for example 0x05...) and cannot be children of a
        // scanned retail game. Exclude them before reading their metadata;
        // malformed retail metadata must still fail closed below.
        if(key.type==NcmContentMetaType_Application&&!core::UserId(key.id))continue;
        R_TRY(s.Check());std::vector<u8> raw;R_TRY(s.Raw(key,raw));bytes+=raw.size();
        if(bytes>MaxStoredMeta){s.scan.detail="The existing family metadata exceeds the safe reconciliation limit. No registrations were changed."_nx;return nexus::Invalid;}
        u64 application{};
        if(!InstalledIdentity(key,raw,application)){s.scan.detail="Existing content metadata could not be associated safely with its game family. No registrations were changed; check the existing installation before retrying."_nx;return nexus::Invalid;}
        if(families.contains(application))R_TRY(append(key,NcmStorageId_SdCard,application,&raw));
    }
    // An update/DLC without a positively identified base cannot constitute a
    // complete family even if a stale NCM/NS entry happened to exist.
    for(const auto application:families){
        const bool base=std::any_of(s.scan.titles.begin(),s.scan.titles.end(),[&](const auto& row){return row.record.application_id==application&&row.record.key.id==application&&row.record.key.type==NcmContentMetaType_Application;});
        if(!base){R_UNLESS(s.scan.titles.size()<MaxTitles,nexus::Invalid);UsbImportTitle row;row.name=TitleId(application);row.record.key.id=application;row.record.key.type=NcmContentMetaType_Application;row.record.application_id=application;row.reason="The base game is missing from the scanned USB family and has no verified native installation. Restore the base game from your original backup first."_nx;s.scan.titles.push_back(std::move(row));}
    }
    size_t references{},metadata{};for(const auto& row:s.scan.titles){references+=row.record.content.size();metadata+=row.record.installed_meta.size();}
    if(references>MaxReferences||metadata>MaxStoredMeta){s.scan.detail="The complete game-family plan exceeds the safe recovery limit. No registrations were changed."_nx;return nexus::Invalid;}return s.Check();
}

Result CheckBaseGames(Session& s){
    std::map<u64,const UsbImportTitle*> latest_base;
    for(const auto& row:s.scan.titles){
        if(row.record.key.type!=NcmContentMetaType_Application)continue;
        auto [it,added]=latest_base.emplace(row.record.application_id,&row);
        if(!added&&row.record.key.version>it->second->record.key.version)it->second=&row;
    }
    std::map<u64,bool> base_exists;
    for(auto& row:s.scan.titles){
        if(row.status!=UsbImportStatus::Ready||row.record.key.type==NcmContentMetaType_Application)continue;
        const auto application=row.record.application_id;
        auto existing=base_exists.find(application);
        if(existing==base_exists.end()){
            bool present{};const std::vector<ncm::ContentStorageRecord>* records{};R_TRY(s.AppRecords(application,records));
            for(const auto& record:*records){
                if(record.key.type!=NcmContentMetaType_Application||record.key.id!=application||record.key.install_type!=NcmContentInstallType_Full)continue;
                if(record.storage_id==NcmStorageId_SdCard){R_TRY(ncmContentMetaDatabaseHas(&s.db,&present,&record.key));}
                else if(record.storage_id==NcmStorageId_BuiltInUser){
                    NcmContentMetaDatabase internal{};R_TRY(ncmOpenContentMetaDatabase(&internal,NcmStorageId_BuiltInUser));
                    const auto rc=ncmContentMetaDatabaseHas(&internal,&present,&record.key);ncmContentMetaDatabaseClose(&internal);R_TRY(rc);
                }
                if(present)break;
            }
            existing=base_exists.emplace(application,present).first;
        }
        if(existing->second)continue;
        const auto base=latest_base.find(application);
        if(base!=latest_base.end()&&base->second->status==UsbImportStatus::Ready)continue;
        row.status=UsbImportStatus::Incomplete;
        row.reason="The base game is not registered in this system, and its latest copy on this drive is not ready to import. Install or repair the base game first."_nx;
    }
    return s.Check();
}

Result ControlName(Session& s,const yati::ExistingUsbContent& content,std::string& name){
    u64 size{};ncmContentInfoSizeToU64(&content.info,&size);
    File file{content.info.content_id,CanonicalUsbContentPath(content.info.content_id),size};
    nca::Header header{};bool valid{};R_TRY(s.Header(file,header,valid));
    if(!valid||header.content_type!=nca::ContentType_Control||es::IsRightsIdValid(header.rights_id))return 0;
    for(size_t index=0;index<NCA_SECTION_TOTAL;++index){
        const auto& fs=header.fs_header[index];const auto& section=header.fs_table[index];
        if(!section.IsValid()||!fs.IsValid()||fs.fs_type!=nca::FileSystemType_RomFS||fs.hash_type!=nca::HashType_HierarchicalIntegrity||
            section.GetOffset()<sizeof(header)||section.GetOffsetEnd()<=section.GetOffset()||section.GetOffsetEnd()>size)continue;
        u8 fs_hash[32]{};sha256CalculateHash(fs_hash,&fs,sizeof(fs));if(std::memcmp(fs_hash,&header.fs_header_hash[index],sizeof(fs_hash)))continue;
        const auto& tree=fs.hash_data.integrity_meta_info.info_level_hash;if(tree.max_layers!=7)continue;
        const auto& layer=tree.levels[5];if(layer.hash_data_size<80||!core::Range(layer.logical_offset,layer.hash_data_size,section.GetSize()))continue;
        const bool encrypted=fs.encryption_type==nca::EncryptionType_AesCtr||fs.encryption_type==nca::EncryptionType_AesCtrSkipLayerHash;
        if(!encrypted&&fs.encryption_type!=nca::EncryptionType_None)continue;
        auto decrypted=header;
        if(encrypted&&(header.kaek_index>=3||header.GetKeyGeneration()>0x20||R_FAILED(nca::DecryptKeak(s.keys,decrypted))))continue;
        const auto read=[&](u64 offset,size_t count,std::vector<u8>& out)->Result{
            R_UNLESS(count<=256*1024&&core::Range(offset,count,layer.hash_data_size),nexus::Invalid);
            const u64 absolute=section.GetOffset()+layer.logical_offset+offset,aligned=encrypted?absolute&~u64{15}:absolute,pad=absolute-aligned;
            R_UNLESS(core::Range(aligned,count+pad,size),nexus::Invalid);out.resize(count+pad);R_TRY(s.Read(file.path,aligned,out.data(),out.size()));
            if(encrypted){u8 ctr[16]{};crypto::SetCtr(ctr,fs.section_ctr,aligned);Aes128CtrContext ctx;aes128CtrContextCreate(&ctx,decrypted.key_area[2].area,ctr);aes128CtrCrypt(&ctx,out.data(),out.data(),out.size());}
            if(pad)out.erase(out.begin(),out.begin()+pad);
            return 0;
        };
        std::vector<u8> romfs;R_TRY(read(0,80,romfs));if(core::Read<u64>(romfs,0)!=80)continue;
        const auto metadata_offset=core::Read<u64>(romfs,56),metadata_size=core::Read<u64>(romfs,64),data_offset=core::Read<u64>(romfs,72);
        if(!metadata_size||metadata_size>256*1024||!core::Range(metadata_offset,metadata_size,layer.hash_data_size)||data_offset>layer.hash_data_size)continue;
        R_TRY(read(metadata_offset,metadata_size,romfs));u64 offset{},length{};
        if(!core::FindRomfsRootFile(romfs,layer.hash_data_size-data_offset,"control.nacp",offset,length)||length<sizeof(NacpStruct))continue;
        std::vector<u8> bytes;R_TRY(read(data_offset+offset,sizeof(NacpStruct),bytes));NacpStruct nacp{};std::memcpy(&nacp,bytes.data(),sizeof(nacp));
        // Compressed/newer title formats remain a title-ID fallback; this
        // optional reader must never interpret compressed bytes as a name.
        if(nacp.titles_data_format!=0)continue;
        bool terminated=true;for(const auto& language:nacp.lang_data.lang)if(!std::memchr(language.name,0,sizeof(language.name)))terminated=false;
        if(!terminated)continue;
        NacpLanguageEntry* entry{};if(R_FAILED(nacpGetLanguageEntry(&nacp,&entry))||!entry)entry=&nacp.lang_data.lang[1];
        const auto* end=static_cast<const char*>(std::memchr(entry->name,0,sizeof(entry->name)));if(!end)continue;
        auto candidate=SafeName(std::string(entry->name,end-entry->name));
        if(!candidate.empty()&&core::Utf8(candidate)){name=std::move(candidate);return 0;}
    }
    return s.Check();
}

Result ReadTitleNames(Session& s){
    std::map<u64,std::string> names;
    for(auto& row:s.scan.titles){
        const auto application=row.record.application_id;if(!application)continue;
        const auto known=names.find(application);if(known!=names.end()){row.name=known->second;continue;}
        if(row.name!=TitleId(application)&&!row.name.empty()){names.emplace(application,row.name);continue;}
        for(const auto& content:row.record.content){
            if(content.info.content_type!=NcmContentType_Control)continue;
            const auto header=s.headers.find(ContentId(content.info.content_id));if(header==s.headers.end()||!header->second.valid)continue;
            std::string name;R_TRY(ControlName(s,content,name));if(name.empty())continue;
            row.name=name;names.emplace(application,std::move(name));break;
        }
    }
    for(auto& row:s.scan.titles){const auto known=names.find(row.record.application_id);if(known!=names.end())row.name=known->second;}
    return s.Check();
}
}

std::string CanonicalUsbContentPath(const NcmContentId& id){
    u8 hash[32]{};sha256CalculateHash(hash,&id,sizeof(id));char directory[32]{};
    std::snprintf(directory,sizeof(directory),"/registered/%08X/",static_cast<unsigned>(hash[0]));return std::string(directory)+HexId(&id)+".nca";
}
const char* UsbImportStatusText(UsbImportStatus status){switch(status){case UsbImportStatus::Ready:return "Ready to import"_nx;case UsbImportStatus::AlreadyRegistered:return "Already registered"_nx;case UsbImportStatus::Incomplete:return "Incomplete on drive"_nx;case UsbImportStatus::TicketMissing:return "Ticket not found in system"_nx;}return "Incomplete on drive"_nx;}

UsbLibraryPlan PlanUsbLibrary(const UsbImportScan& scan){
    UsbLibraryPlan plan;plan.selected.resize(scan.titles.size());plan.family_reason.resize(scan.titles.size());
    if(!scan.complete)return plan;
    std::map<std::pair<u64,u8>,u32> newest;
    for(const auto& row:scan.titles)if(row.record.key.id){auto& version=newest[{row.record.key.id,row.record.key.type}];version=std::max(version,row.record.key.version);}
    std::map<u64,std::vector<size_t>> families;
    for(size_t i=0;i<scan.titles.size();++i){const auto& row=scan.titles[i];const auto& key=row.record.key;
        if(core::UserId(key.id)&&core::UserId(row.record.application_id)&&core::SupportedType(key.type)&&key.version==newest[{key.id,key.type}])families[row.record.application_id].push_back(i);
    }
    for(const auto& [application,indices]:families){
        (void)application;bool affected{},missing{};std::string reason;
        for(const auto i:indices){const auto& row=scan.titles[i];
            affected|=row.status==UsbImportStatus::Ready||row.status==UsbImportStatus::Incomplete||row.status==UsbImportStatus::TicketMissing;
            missing|=row.missing_tickets||row.status==UsbImportStatus::TicketMissing;
            if(reason.empty()&&(row.status==UsbImportStatus::Incomplete||row.status==UsbImportStatus::TicketMissing||row.registration==UsbImportRegistration::Superseded||
                (row.status==UsbImportStatus::AlreadyRegistered&&row.registration==UsbImportRegistration::Unknown)||
                (row.status==UsbImportStatus::Ready&&row.registration==UsbImportRegistration::Native)))
                reason="This game family cannot be repaired yet: "_nx+row.name+". "+row.reason;
        }
        if(!affected)continue;
        ++plan.summary.affected_games;if(missing)++plan.summary.missing_ticket_games;
        if(!reason.empty()){
            ++plan.summary.blocked_games;for(const auto i:indices)plan.family_reason[i]=reason;continue;
        }
        ++plan.summary.repairable_games;
        for(const auto i:indices){const auto& row=scan.titles[i];
            if(row.registration==UsbImportRegistration::Native)continue;
            plan.selected[i]=true;++plan.summary.selected_items;
        }
    }
    return plan;
}
UsbLibrarySummary SummarizeUsbLibrary(const UsbImportScan& scan){return PlanUsbLibrary(scan).summary;}

Result ScanUsbImports(ui::ProgressBox* progress,UsbImportScan& scan,u64 expected_generation,const std::atomic_bool* cancel,bool names,bool ownership_only){
    scan={};Session s(progress,scan,cancel);
    const auto operation=[&]()->Result{
    if(progress){progress->SetTitle("Scan USB game library"_nx);progress->NewTransfer("Finding installed USB files"_nx);}R_TRY(s.Probe(expected_generation));
    s.stage="listing registered USB content files"_nx;
    std::vector<nexus::Entry> directories;const auto list_result=s.usb.List(scan.generation,"/registered",directories);
    if(list_result==MissingUsb){R_TRY(s.Check());scan.complete=true;scan.detail="No registered content folder was found on this USB drive. Nothing was changed."_nx;return 0;}R_TRY(list_result);
    R_UNLESS(directories.size()<=MaxFiles,nexus::Invalid);
    std::vector<File> files;std::set<Id> seen_files;
    // The persistent SMB image exposes flat names and also resolves their
    // canonical NCM paths. Physical USB must still pass its bucket checks.
    const bool flat_image = (scan.generation & nexus::smbmount::GenerationBit) != 0;
    auto collect = [&](const nexus::Entry& entry, int bucket)->Result {
        if(entry.directory)return 0;
        Id id{};if(!core::ContentName(entry.name,id))return 0;
        R_UNLESS(files.size()+scan.unresolved_ownership.size()<MaxFiles,nexus::Invalid);
        File file{};std::memcpy(&file.id,id.data(),id.size());
        file.path=CanonicalUsbContentPath(file.id);file.size=entry.size;
        u8 hash[32]{};sha256CalculateHash(hash,&file.id,sizeof(file.id));
        if((bucket>=0 && hash[0]!=bucket)||!seen_files.insert(id).second){
            ++scan.unreadable_ncas;scan.unresolved_ownership.push_back(file.id);return 0;
        }
        files.push_back(std::move(file));return 0;
    };
    for(const auto& directory:directories){
        if(flat_image){R_TRY(collect(directory,-1));continue;}
        R_TRY(s.Check());const std::string name=directory.name;
        if(!directory.directory||name.size()!=8||!std::all_of(name.begin(),name.end(),[](char c){return core::Hex(c)>=0;}))continue;
        u32 bucket{};for(char c:name)bucket=(bucket<<4)|core::Hex(c);if(bucket>255)continue;
        std::vector<nexus::Entry> entries;R_TRY(s.usb.List(scan.generation,"/registered/"+name,entries));
        for(const auto& entry:entries){R_TRY(collect(entry,static_cast<int>(bucket)));}
    }
    scan.nca_files=files.size();
    if(files.empty()){
        R_TRY(s.Check());scan.complete=true;
        scan.detail=scan.unreadable_ncas?"Content files were found in unexpected locations. Nothing was changed; review the drive before attempting repair."_nx:"No installed USB game content was found. No repair is needed. Package files such as NSP, NSZ and XCI belong in Install games."_nx;
        return 0;
    }
    R_TRY(s.Open(scan.generation,ownership_only));
    if(progress)progress->NewTransfer("Reading USB content headers"_nx);
    s.stage="reading and identifying USB content headers"_nx;
    std::vector<File> metas;
    for(size_t i=0;i<files.size();++i){
        const auto& file=files[i];nca::Header header{};bool valid{};R_TRY(s.Header(file,header,valid));
        s.headers[ContentId(file.id)]={header.rights_id,file.size,header.content_type,valid};
        if(!valid){++scan.unreadable_ncas;scan.unresolved_ownership.push_back(file.id);}
        else if(header.content_type==nca::ContentType_Meta)metas.push_back(file);
        if(progress)progress->UpdateTransfer(i+1,files.size());
    }
    R_UNLESS(metas.size()<=MaxTitles,nexus::Invalid);size_t references{},stored_meta{};
    if(progress)progress->NewTransfer("Checking games, updates and DLC"_nx);
    for(size_t i=0;i<metas.size();++i){
        const auto& file=metas[i];UsbImportTitle row{};row.meta_path=file.path;row.name="Metadata "_nx+HexId(&file.id);
        nca::Header header{};bool valid{};R_TRY(s.Header(file,header,valid));
        if(!valid){scan.unresolved_ownership.push_back(file.id);row.reason="The metadata file changed or is unreadable. Scan the drive again."_nx;scan.titles.push_back(std::move(row));continue;}
        s.stage="reading and validating USB game metadata"_nx;
        std::vector<u8> raw;R_TRY(ReadCnmt(s,file,header,raw,row.reason));
        if(!row.reason.empty()){scan.unresolved_ownership.push_back(file.id);scan.titles.push_back(std::move(row));continue;}
        if(raw.size()>=13&&!core::SupportedType(raw[12])){++scan.ignored_meta;scan.unresolved_ownership.push_back(file.id);continue;}
        PreviewIdentity(row,header,raw,names);
        core::Meta parsed;
        if(!core::ParseCnmt(raw,parsed,row.reason,ownership_only)||parsed.id!=header.program_id||!MakeRecord(parsed,file,row.record)){
            scan.unresolved_ownership.push_back(file.id);
            if(row.reason.empty())row.reason="This metadata is unsupported, too large for recovery, or contains an inconsistent NCA reference."_nx;
            scan.titles.push_back(std::move(row));continue;
        }
        row.name=names?SafeName(title::GetCachedTitleName(row.record.application_id)):std::string{};if(row.name.empty())row.name=TitleId(row.record.application_id);
        if(!ownership_only){s.stage="checking content, permissions and registrations"_nx;R_TRY(Classify(s,row));}
        references+=row.record.content.size();stored_meta+=row.record.installed_meta.size();
        if(references>MaxReferences||stored_meta>MaxStoredMeta){scan.detail="This drive's metadata exceeds the safe scan limit. No registrations were changed."_nx;return nexus::Invalid;}
        scan.titles.push_back(std::move(row));if(progress)progress->UpdateTransfer(i+1,metas.size());
    }
    if(ownership_only){R_TRY(s.Check());scan.complete=true;scan.detail="Physical USB content ownership was read without import or ticket checks."_nx;return 0;}
    std::map<Key,size_t> seen_meta;
    for(size_t i=0;i<scan.titles.size();++i){
        auto& row=scan.titles[i];if(!row.record.key.id)continue;
        auto [previous,added]=seen_meta.emplace(MetaKey(row.record.key),i);
        if(!added){
            auto& other=scan.titles[previous->second];other.status=row.status=UsbImportStatus::Incomplete;
            other.reason=row.reason="More than one metadata NCA claims this title and version. Reinstall from your original backup to resolve the conflict."_nx;
        }
    }
    s.stage="reconciling all registered game-family members"_nx;R_TRY(ReconcileFamilyMembers(s));R_TRY(CheckBaseGames(s));if(names){if(progress)progress->NewTransfer("Reading game names"_nx);R_TRY(ReadTitleNames(s));}R_TRY(s.CheckTicketsUnchanged());R_TRY(s.Check());scan.complete=true;
    scan.detail="The scan read USB content directly. No game files, tickets, HOME records or SD routing indexes were changed. Import checks content hashes before registration. Optional delta fragments are not installed game content."_nx;
    return 0;
    };
    const auto result=operation();
    if(R_FAILED(result)&&scan.detail.empty())scan.detail=nexus::usbimport::FailureDetail(s.stage,result,"No game files, permissions or registrations were changed."_nx);
    if(R_FAILED(result)){scan.complete=false;if(!ownership_only)scan.titles.clear();}
    return result;
}


std::string UsbImportPreview(const UsbImportScan& scan){
    if(!scan.complete)return "USB check could not finish. Game health and ticket status are not confirmed. Nothing was changed.\n\n"_nx+scan.detail;
    size_t ready{},registered{},incomplete{},tickets{};
    for(const auto& row:scan.titles)switch(row.status){case UsbImportStatus::Ready:++ready;break;case UsbImportStatus::AlreadyRegistered:++registered;break;case UsbImportStatus::Incomplete:++incomplete;break;case UsbImportStatus::TicketMissing:++tickets;break;}
    const auto heading = scan.generation & nexus::smbmount::GenerationBit ? "SMB library preview\n\n"_nx : "USB library preview\n\n"_nx;
    std::string result=heading+std::to_string(ready)+" ready to import; "_nx+std::to_string(registered)+" already registered; "_nx+std::to_string(incomplete)+" incomplete or conflicting; "_nx+std::to_string(tickets)+" missing tickets.\n\n"_nx;
    if(scan.unreadable_ncas)result+=std::to_string(scan.unreadable_ncas)+" content files could not be identified or read. They were not treated as complete games.\n\n"_nx;
    if(scan.titles.empty())result+=scan.nca_files?"This drive contains NCA files, but no supported game metadata could be identified. It has not been treated as an empty drive.\n\n"_nx:"No registered game content was found.\n\n"_nx;
    return result+scan.detail+"\n\nSaves stay in the current system and are not imported."_nx;
}
}
