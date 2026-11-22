"""Exercise the actual on-demand startup function with host service doubles."""
from pathlib import Path
import subprocess
import tempfile

app = Path(__file__).resolve().parents[1]
source = (app / 'sphaira/source/nexus/network_locations.cpp').read_text()
body = source[source.index('Result OpenResidentStore('):source.index('void ReviewMountedGame(')]
fixture = r'''
#include <cassert>
#include <cstdint>
#include <sys/stat.h>
#include <vector>
using Result=unsigned; using u64=uint64_t;
constexpr unsigned NcmStorageId_None=0;
struct NcmProgramLocation { u64 id; unsigned storage; char pad[7]; };
namespace nexus {constexpr Result Unavailable=75; void Log(const char*,Result,u64=0){}}
namespace smbmount {
struct Status{};
struct Store {
    std::vector<Result> replies;
    Result Query(Status&){Result r=replies.front();if(replies.size()>1)replies.erase(replies.begin());return r;}
};
}
#define R_TRY(call) do{auto r=(call);if(r)return r;}while(false)
#define R_FAILED(r) ((r)!=0)
struct ProgressBox { Result cancelled{}; Result ShouldExitResult(){return cancelled;} };
int attempts=0, exits=0; Result outcome=0;
void svcSleepThread(long){}
Result pmshellInitialize(){return 0;}
void pmshellExit(){++exits;}
Result pmshellLaunchProgram(unsigned flags,const NcmProgramLocation* loc,u64* pid){
    assert(!flags && !loc->storage && loc->id==UINT64_C(0x42000000004D5453));
    ++attempts;*pid=123;return outcome;
}
'''
cases = r'''
int main(){
    smbmount::Status s; ProgressBox p; using nexus::Unavailable;
    smbmount::Store active{{0}}; assert(!OpenResidentStore(active,s,&p)&&!attempts);
    smbmount::Store absent{{Unavailable}};assert(OpenResidentStore(absent,s,&p)==Unavailable&&!attempts);
    extern void install();install();
    smbmount::Store started{{Unavailable,Unavailable,0}};assert(!OpenResidentStore(started,s,&p)&&attempts==1&&exits==1);
    assert(OpenResidentStore(absent,s,&p)==Unavailable&&attempts==2&&exits==2);
    outcome=0x10801;assert(OpenResidentStore(absent,s,&p)==outcome&&attempts==3&&exits==3);
    smbmount::Store race{{Unavailable,0}};assert(!OpenResidentStore(race,s,&p)&&attempts==4&&exits==4);
    p.cancelled=9;assert(OpenResidentStore(absent,s,&p)==9&&attempts==4);
}
#include <filesystem>
#include <fstream>
void install(){
    auto path=std::filesystem::path("sdmc:/atmosphere/contents/42000000004D5453/exefs.nsp");
    std::filesystem::create_directories(path.parent_path());std::ofstream file(path);file<<"fixture";
}
'''
with tempfile.TemporaryDirectory(prefix='nexus-provider-launch-') as tmp:
    work = Path(tmp)
    (work / 'test.cpp').write_text(fixture + body + cases)
    subprocess.run(['c++','-std=c++20','-O2','-fsanitize=undefined','test.cpp','-o','test'],cwd=work,check=True)
    subprocess.run([work / 'test'],cwd=work,check=True)
