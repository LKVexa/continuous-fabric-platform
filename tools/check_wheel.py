"""Verify shipped assets and an import from the built wheel, outside the source tree."""
import subprocess
import sys
import tempfile
import zipfile
from pathlib import Path

wheel = next(Path(sys.argv[1]).glob('cfp-*.whl')).resolve()
with zipfile.ZipFile(wheel) as archive:
    names = archive.namelist()
    for suffix in ('cfp/web/index.html', '/licenses/LICENSE', '/licenses/NOTICE'):
        assert any(n.endswith(suffix) for n in names), f'missing {suffix}'
    with tempfile.TemporaryDirectory() as tmp:
        archive.extractall(tmp)
        code = ('import sys; sys.path.insert(0, sys.argv[1]); '
                'import cfp; from cfp.server import WEB; '
                'assert cfp.__version__ == "1.0.1"; '
                'assert (WEB / "index.html").is_file(); '
                'print("wheel import, version, UI, LICENSE and NOTICE: PASS")')
        subprocess.run([sys.executable, '-I', '-c', code, tmp], cwd=tmp, check=True)
