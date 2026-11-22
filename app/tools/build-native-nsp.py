"""Build a standalone Manager NSP and verify decrypted contents locally.

Tool output is suppressed because crypto tools may print derived keys.
The receipt contains local build provenance and must not be published.
"""
from pathlib import Path
import argparse,hashlib,importlib.util,json,re,shutil,struct,subprocess,sys,tempfile
from contextlib import contextmanager

APP=Path(__file__).resolve().parents[1]
TITLE='05004e584d470000'
def sha(p):return hashlib.sha256(p.read_bytes()).hexdigest()

@contextmanager
def packing_keyset(path):
    # Older packing tools abort on unrelated entries in newer key files.
    # This NSP uses key generation 1. Keep the full input for the secret scan.
    lengths = {'header_key':64, 'key_area_key_application_00':32}
    entries = {}
    for line in path.read_text(encoding='utf-8-sig').splitlines():
        name, sep, value = line.partition('=')
        name, value = name.strip(), value.strip()
        if sep and name in lengths and re.fullmatch(r'[0-9a-fA-F]+',value) and len(value)==lengths[name]:
            entries[name] = value
    if entries.keys() != lengths.keys():
        yield path  # Allow the tool to derive missing keys from the supplied inputs.
        return
    with tempfile.TemporaryDirectory(prefix='nexus-pack-input-') as directory:
        with tempfile.NamedTemporaryFile(mode='w',dir=directory,delete=False) as subset:
            subset.writelines(f'{k} = {v}\n' for k,v in entries.items())
        yield Path(subset.name)
def run(tool,args,cwd):
    result=subprocess.run([str(tool),*map(str,args)],cwd=cwd,stdout=subprocess.DEVNULL,
                          stderr=subprocess.DEVNULL,timeout=120,
                          creationflags=getattr(subprocess,'CREATE_NO_WINDOW',0))
    if result.returncode:raise RuntimeError(tool.name+' failed with exit '+str(result.returncode)+'; crypto output suppressed')

def main():
    parser=argparse.ArgumentParser()
    path_args=('build','keys','packer','tool-dir','output','receipt')
    for name in path_args:
        parser.add_argument('--'+name,required=True,type=Path)
    parser.add_argument('--version',required=True,help='Exact expected NACP version; reject a stale build')
    a=parser.parse_args()
    for name in path_args:
        attr=name.replace('-','_')
        setattr(a,attr,getattr(a,attr).resolve())
    assert not a.output.exists() and not a.receipt.exists(),'Do not overwrite artifacts'
    elf=a.build/'sphaira/sphaira.elf';nro=a.build/'switch/nexusmanager/NexusManager.nro'
    suffix = '.exe' if sys.platform == 'win32' else ''
    tools={n:a.tool_dir/(n+suffix) for n in ('elf2nso','npdmtool','hactool')}
    for p in (elf,nro,a.keys,a.packer,*tools.values()):assert p.is_file(),p.name
    data=nro.read_bytes();elf_data=elf.read_bytes()
    assert data[16:20]==b'NRO0' and elf_data[:4]==b'\x7fELF'
    assert struct.unpack_from('<H',elf_data,18)[0]==183
    for marker in (b'My games',b'Install games',b'MANAGER-0.1.11-ports2',b'/switch/left4dead',b'port-transfer',
                   b'runtime-native-application',b'Copied ',b'Verifying copied files',b'Already present'):
        assert marker in data and marker in elf_data
    aset=struct.unpack_from('<I',data,24)[0];assert data[aset:aset+4]==b'ASET'
    def asset(at):
        off,size=struct.unpack_from('<QQ',data,aset+at)
        assert off>=56 and size and aset+off+size<=len(data)
        return data[aset+off:aset+off+size]
    nacp=bytearray(asset(24));assert len(nacp)==0x4000
    assert nacp[:0x200].split(b'\0',1)[0]==b'Nexus Manager'
    version=nacp[0x3060:0x3070].split(b'\0',1)[0].decode();assert version==a.version,'Unexpected application version'
    stage=Path(tempfile.mkdtemp(prefix='native-manager-',dir=a.build))
    for name in ('exefs','romfs','control','logo','unpacked','verified'):(stage/name).mkdir()
    run(tools['elf2nso'],[elf,stage/'exefs/main'],stage)
    nso=(stage/'exefs/main').read_bytes();assert nso[:4]==b'NSO0'
    assert sha(stage/'exefs/main')!=sha(a.build/'hbl/exefs/main'),'Loader substituted for application'
    cfg=json.loads((APP/'hbl/hbl.json').read_text())
    cfg.update(name='Nexus Manager',title_id='0x'+TITLE,title_id_range_min='0x'+TITLE,
               title_id_range_max='0x'+TITLE,address_space_type=3)
    for cap in cfg['kernel_capabilities']:
        if cap['type']=='kernel_flags':
            cap['value'].update(highest_thread_priority=63,lowest_thread_priority=28,highest_cpu_id=3,lowest_cpu_id=0)
    assert next(c for c in cfg['kernel_capabilities'] if c['type']=='application_type')['value']==1
    (stage/'native.json').write_text(json.dumps(cfg,indent=2))
    run(tools['npdmtool'],[stage/'native.json',stage/'exefs/main.npdm'],stage)
    # Prepare the native title's control metadata before packing so different
    # packer versions produce the same title IDs and application flags.
    tid=int(TITLE,16)
    for off in (0x3038,0x3078,*range(0x30b0,0x30f0,8)):struct.pack_into('<Q',nacp,off,tid)
    struct.pack_into('<Q',nacp,0x3070,tid+0x1000)
    nacp[0x30f1]=nacp[0x3212]=nacp[0x34d1]=0;struct.pack_into('<I',nacp,0x34d4,1)
    (stage/'control/control.nacp').write_bytes(nacp)
    (stage/'control/icon_AmericanEnglish.dat').write_bytes(asset(8))
    (stage/'program.romfs').write_bytes(asset(40))
    run(tools['hactool'],['-t','romfs','--romfsdir='+str(stage/'romfs'),stage/'program.romfs'],stage)
    files={p.relative_to(stage/'romfs').as_posix():sha(p) for p in (stage/'romfs').rglob('*') if p.is_file()}
    assert files and any(n.startswith('shaders/') for n in files)
    assert not any(Path(n).suffix.lower()=='.nro' or Path(n).name in ('nextNroPath','nextArgv') for n in files)
    with packing_keyset(a.keys) as keyset:
        # The generated NPDM already sets TITLE. An override also rewrites the
        # NACP, which must remain byte-identical to the prepared native copy.
        run(a.packer,['--keyset',keyset,'--nopatchnacplogo','--keepncadir'],stage)
    package=stage/'hacbrewpack_nsp'/(TITLE+'.nsp');assert package.is_file()
    spec=importlib.util.spec_from_file_location('pfs_helpers',APP/'tools/build-home-nsp.py')
    helpers=importlib.util.module_from_spec(spec);spec.loader.exec_module(helpers)
    nsp=package.read_bytes();helpers.extract_pfs(nsp,stage/'unpacked')
    ncas=list((stage/'unpacked').glob('*.nca'));assert len(ncas)==3
    exefs=stage/'verified/exefs';romfs=stage/'verified/romfs'
    for p in ncas:
        assert p.name[:32]==sha(p)[:32]
        with packing_keyset(a.keys) as keyset:
            run(tools['hactool'],['-x','--disablekeywarns','--suppresskeys','-k',keyset,
                '--exefsdir='+str(exefs),'--romfsdir='+str(romfs),p],stage)
    assert sha(exefs/'main')==sha(stage/'exefs/main')
    assert sha(exefs/'main.npdm')==sha(stage/'exefs/main.npdm')
    sys.path.insert(0,str(APP/'tests'))
    from forwarder_npdm_tests import verify_npdm
    verify_npdm((exefs/'main.npdm').read_bytes(),int(TITLE,16))
    for name,digest in files.items():assert sha(romfs/name)==digest,name
    assert (romfs/'control.nacp').read_bytes()==nacp
    assert (romfs/'icon_AmericanEnglish.dat').read_bytes()==asset(8)
    run(tools['hactool'],['-t','nso0','--uncompressed='+str(stage/'main-uncompressed.nso'),exefs/'main'],stage)
    plain=(stage/'main-uncompressed.nso').read_bytes()
    assert b'My games' in plain and b'runtime-native-application' in plain
    # Compare supplied values only in memory; do not report values or key names.
    secrets=set()
    for line in a.keys.read_text(encoding='utf-8-sig').splitlines():
        name,sep,value=line.partition('=');name,value=name.strip(),value.strip()
        if sep and '_source' not in name and re.fullmatch(r'[0-9a-fA-F]{32,128}',value) and re.match(r'^(key_area_key_(application|ocean|system)_|titlekek_|master_key_|bis_key_|mariko_bek$|device_key$|header_key$|sd_card_(nca|save)_key$)',name):
            raw=bytes.fromhex(value)
            if any(raw):secrets.add(raw)
    assert len(secrets)>10
    for payload in (nsp,plain,elf_data,asset(40)):
        assert not any(v in payload or v.hex().encode() in payload.lower() for v in secrets),'Secret scan failed'
    a.output.parent.mkdir(parents=True,exist_ok=True)
    with a.output.open('xb') as f:f.write(nsp)
    receipt={'passed':True,'console_tested':False,'version':version,'title_id':TITLE,
        'kind':'Standalone native NSO application with embedded RomFS; no external NRO required',
        'nsp_sha256':sha(a.output),'nro_sha256':sha(nro),'elf_sha256':sha(elf),
        'nso_sha256':sha(exefs/'main'),'romfs_files':files,'npdm':'39-bit application, cores 0-3, ACI0/ACID verified',
        'secret_values_checked':len(secrets),'secret_scan_findings':0,'stage':str(stage)}
    a.receipt.parent.mkdir(parents=True,exist_ok=True);a.receipt.write_text(json.dumps(receipt,indent=2))
    print('PASS standalone NSP: native executable, embedded assets, NPDM, NACP, icon, NCA hashes and secret scan')
    print(a.output)

if __name__=='__main__':main()
