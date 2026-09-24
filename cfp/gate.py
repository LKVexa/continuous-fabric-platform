"""Promotion gate: an atom becomes OPERATIONAL only on native executable evidence.

The gate runs the atom's own test suite in a subprocess with a timeout and records an evidence
document (inputs, environment, exit code, digest of output). Existence of source never promotes.
"""
from __future__ import annotations
import hashlib, json, os, platform, re, subprocess, sys, time
from pathlib import Path

STATUSES = ("STAGED", "GATED_FAIL", "GATED_PASS", "OPERATIONAL", "BLOCKED_EXTERNAL_AUTHORITY")


def detect_suite(pkg: Path) -> list[str] | None:
    if (pkg / "package.json").exists() and (pkg / "tests").exists():
        return ["node", "--test", "tests/"]
    if (pkg / "tests").is_dir() and any((pkg / "tests").rglob("test_*.py")):
        # Many atoms are importable as <pkgname>; run from the parent so relative imports resolve.
        return [sys.executable, "-m", "unittest", "discover", "-s", "tests"]
    for v in ("VERIFY.cmd", "VERIFY") if os.name == "nt" else ("VERIFY",):
        if (pkg / v).exists():
            return ["cmd", "/c", v] if v.endswith(".cmd") else ["sh", v]
    return None


def run_gate(atom: dict, evidence_dir: Path, timeout: int = 900) -> dict:
    pkg = Path(atom["package_dir"])
    if Path(atom["name"]).name != atom["name"] or any(c in atom["name"] for c in ("/", "\\", ":")) or atom["name"] in (".", ".."):
        raise ValueError("invalid atom name")
    cmd = detect_suite(pkg)
    rec = {"schema": "cfp.gate-evidence/1", "atom": atom["name"], "package_dir": str(pkg), "cmd": cmd,
           "started": time.time(), "env": {"python": sys.version.split()[0], "os": platform.platform(),
                                           "machine": platform.machine()}}
    if cmd is None:
        rec.update(status="STAGED", reason="no executable suite found")
    else:
        env = dict(os.environ, PYTHONPATH=os.pathsep.join([str(pkg.parent), str(pkg)]))
        try:
            p = subprocess.run(cmd, cwd=pkg, env=env, capture_output=True, text=True, timeout=timeout)
            out = (p.stdout or "") + (p.stderr or "")
            zero_tests = ("unittest" in cmd and re.search(r"Ran 0 tests?\b", out)) or (cmd[0] == "node" and re.search(r"# tests 0\b", out))
            rec.update(exit=p.returncode, status="GATED_PASS" if p.returncode == 0 and not zero_tests else "GATED_FAIL",
                       output_sha256=hashlib.sha256(out.encode()).hexdigest(), tail=out[-4000:])
            if zero_tests:
                rec["reason"] = "test runner executed zero tests"
        except subprocess.TimeoutExpired:
            rec.update(status="GATED_FAIL", reason=f"timeout {timeout}s")
        except FileNotFoundError as e:
            rec.update(status="STAGED", reason=f"runner missing: {e}")
    rec["finished"] = time.time()
    evidence_dir.mkdir(parents=True, exist_ok=True)
    path = evidence_dir / f"{atom['name']}.json"
    path.write_text(json.dumps(rec, indent=2), encoding="utf-8")
    rec["evidence_path"] = str(path)
    return rec


def promote(ledger: dict, rec: dict, fabric_link_ok: bool) -> str:
    """GATED_PASS + a live fabric link (atom reachable from the platform) => OPERATIONAL."""
    status = rec["status"]
    if status == "GATED_PASS" and fabric_link_ok:
        status = "OPERATIONAL"
    ledger[rec["atom"]] = {"status": status, "evidence": rec.get("evidence_path"), "at": rec["finished"]}
    return status
