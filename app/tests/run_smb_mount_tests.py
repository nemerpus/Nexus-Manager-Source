from pathlib import Path
import subprocess
import tempfile

app = Path(__file__).resolve().parents[1]
with tempfile.TemporaryDirectory(prefix='nexus-smb-mount-') as work:
    binary = Path(work) / 'smb-mount'
    subprocess.run(['c++', '-std=c++20', '-O2', '-fsanitize=undefined', '-Wall',
                    '-I', str(app / 'sphaira/include'), str(app / 'tests/smb_mount_tests.cpp'),
                    '-o', str(binary)], check=True)
    subprocess.run([binary], check=True)
