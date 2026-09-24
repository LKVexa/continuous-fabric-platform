"""Vendor copies of every stockpile into <platform>/vendor/, with a SHA-256 manifest.

Sources are never modified. Caches (.mypy_cache, .ruff_cache, __pycache__, node_modules, .git)
are skipped. Re-running is idempotent: unchanged files (same size+hash) are not rewritten.
"""
from __future__ import annotations
import hashlib, json, os, shutil, time
from pathlib import Path
from .atlas import discover

SKIP_DIRS = {".mypy_cache", ".ruff_cache", "__pycache__", "node_modules", ".git", ".pytest_cache"}


def _tree(files):
    return hashlib.sha256("\n".join(f"{k} {v}" for k, v in sorted(files.items())).encode()).hexdigest()


def _safe_files(root):
    """Do not traverse symbolic links or Windows junctions."""
    for current, dirs, names in os.walk(root, followlinks=False):
        dirs[:] = [d for d in dirs if d not in SKIP_DIRS]
        for name in dirs + names:
            p = Path(current) / name
            if p.is_symlink() or getattr(p, "is_junction", lambda: False)():
                raise ValueError(f"linked paths are not supported: {p.name}")
        for name in names:
            if name != ".cfp_vendor.json":
                yield Path(current) / name


def _sha(p: Path) -> str:
    h = hashlib.sha256()
    with p.open("rb") as f:
        for chunk in iter(lambda: f.read(1 << 20), b""):
            h.update(chunk)
    return h.hexdigest()


def vendor(root: Path, dest: Path, include_duplicates: bool = False, only: list[str] | None = None,
           log=print) -> dict:
    dest.mkdir(parents=True, exist_ok=True)
    manifest = {"schema": "cfp.vendor/1", "root": str(root), "started": time.time(), "atoms": {}}
    for atom in discover(root):
        if only and atom.name not in only:
            continue
        if atom.duplicate_of and not include_duplicates:
            manifest["atoms"][atom.name] = {"skipped": "duplicate_of " + atom.duplicate_of}
            continue
        src, out = Path(atom.path), dest / atom.name
        if dest.resolve().is_relative_to(src.resolve()):
            raise ValueError("vendor destination cannot be inside a source atom")
        if src.is_symlink() or out.is_symlink() or getattr(src, "is_junction", lambda: False)() or getattr(out, "is_junction", lambda: False)():
            raise ValueError("linked atoms are not supported")
        out.mkdir(parents=True, exist_ok=True)
        files, nbytes, copied = {}, 0, 0
        # Verify existing destination paths before copying anything through them.
        list(_safe_files(out))
        for f in _safe_files(src):
            rel = f.relative_to(src)
            if any(part in SKIP_DIRS for part in rel.parts) or not f.is_file():
                continue
            digest = _sha(f)
            target = out / rel
            if not (target.exists() and target.stat().st_size == f.stat().st_size and _sha(target) == digest):
                target.parent.mkdir(parents=True, exist_ok=True)
                shutil.copy2(f, target)
                copied += 1
            files[rel.as_posix()] = digest
            nbytes += f.stat().st_size
        tree = _tree(files)
        manifest["atoms"][atom.name] = {"layer": atom.layer, "files": len(files), "bytes": nbytes,
                                        "copied": copied, "tree_sha256": tree}
        (out / ".cfp_vendor.json").write_text(json.dumps({"source": atom.path, "tree_sha256": tree,
                                                          "files": files}, indent=1), encoding="utf-8")
        log(f"vendored {atom.name}: {len(files)} files, {copied} copied")
    manifest["finished"] = time.time()
    (dest / "VENDOR_MANIFEST.json").write_text(json.dumps(manifest, indent=2), encoding="utf-8")
    return manifest


def verify_atom(root: Path) -> dict:
    bad, checked = [], 0
    try:
        if root.is_symlink() or getattr(root, "is_junction", lambda: False)():
            raise ValueError("linked atom")
        m = root / ".cfp_vendor.json"
        if m.is_symlink():
            raise ValueError("linked manifest")
        data = json.loads(m.read_text(encoding="utf-8"))
        if not isinstance(data.get("files"), dict) or not data["files"] or _tree(data["files"]) != data.get("tree_sha256"):
            raise ValueError("invalid manifest")
        actual = {p.relative_to(root).as_posix() for p in _safe_files(root)}
        bad.extend(sorted(actual - data["files"].keys()))
        for rel, digest in data["files"].items():
            p = root / rel
            checked += 1
            if (not isinstance(rel, str) or Path(rel).is_absolute() or ".." in Path(rel).parts
                    or "\\" in rel or ":" in rel or not p.resolve().is_relative_to(root.resolve())
                    or rel not in actual or not p.is_file() or _sha(p) != digest):
                bad.append(rel)
    except (OSError, ValueError, TypeError, AttributeError):
        bad.append("invalid or missing manifest / unsafe tree")
    return {"checked": checked, "mismatched": bad, "ok": not bad}


def verify(dest: Path) -> dict:
    """Re-hash every atom; empty, malformed, extra and missing trees fail closed."""
    bad, checked = [], 0
    manifests = list(dest.glob("*/.cfp_vendor.json"))
    if not manifests:
        bad.append("no vendored manifests found")
    for m in manifests:
        result = verify_atom(m.parent)
        checked += result["checked"]
        bad.extend(f"{m.parent.name}/{rel}" for rel in result["mismatched"])
    if dest.is_dir():
        bad.extend(p.name + "/missing manifest" for p in dest.iterdir()
                   if p.is_dir() and not (p / ".cfp_vendor.json").is_file())
    return {"checked": checked, "mismatched": bad, "ok": not bad}
