"""Atlas: discovers the Post Kubernetes World stockpiles and maps each onto a platform layer."""
from __future__ import annotations
import json, re
from dataclasses import dataclass, asdict, field
from pathlib import Path

LAYERS = ["clients", "session", "unified", "control", "execution", "continuous", "model"]

# Role map from the synthesis blueprint. Keys are gap/inv/pln/sch numbers.
GAP_ROLES = {
    1: ("edge", "edge node supervisor: join/admit/cordon/drain of attested edge nodes"),
    2: ("scheduling", "hardware capability discovery"),
    3: ("scheduling", "topology-aware scheduler"),
    4: ("continuity", "disconnected operation controller"),
    5: ("continuity", "state replication / consistency model"),
    6: ("admission", "device identity and attestation"),
    7: ("admission", "artifact provenance signing"),
    8: ("lifecycle", "OTA lifecycle and rollback"),
    9: ("observability", "unified observability"),
    10: ("scheduling", "power/thermal-aware scheduling"),
    11: ("scheduling", "accelerator scheduling"),
    12: ("continuity", "WAN resilience and NAT traversal"),
    13: ("admission", "policy engine"),
    14: ("continuity", "data gravity manager"),
    15: ("lifecycle", "runtime compatibility certification"),
}
PLN_ROLES = {1: "intent", 2: "application", 3: "distributed runtime", 4: "execution",
             5: "elasticity", 6: "data", 7: "security"}
INV_BANDS = [  # (lo, hi, subsystem)
    (2, 8, "substrate+orchestration legacy bridge"), (9, 13, "portable compute + contracts"),
    (14, 22, "async ABI + component worlds"), (23, 32, "virtualization: microvm/unikernel/wasm"),
    (34, 40, "transports + isolation tiers"), (41, 45, "capability security + SFI"),
    (52, 58, "messaging, secrets, durable execution, mesh"), (60, 68, "wasm application fabric"),
    (69, 72, "agentic workloads"),
]
DF_TIERS = {"DF_Small": ("N_SMALL", "MSSL/ASM-1"), "DF_Medium": ("N_MEDIUM", "LCTLC/1.1"),
            "DF_Large": ("N_LARGE", "LCTLC/1.2"), "DF_Xtra_Large": ("N_XLARGE", "LCTLC/1.0")}
EVIDENCE_FILES = ["evidence/exit_gate.json", "release/exit-gate.json", "evidence/evidence.json",
                  "RELEASE_MANIFEST.json", "release/manifest.json", "e/full-suite.tap", "MANIFEST.json"]


@dataclass
class Atom:
    name: str
    path: str
    layer: str
    kind: str
    role: str
    subsystem: str = ""
    number: int | None = None
    version: str = ""
    tier: str = ""
    dialect: str = ""
    package_dir: str = ""
    evidence: list = field(default_factory=list)
    status: str = "STAGED"  # STAGED -> GATED_PASS/GATED_FAIL -> OPERATIONAL (never by existence)
    duplicate_of: str = ""

    def to_dict(self):
        return asdict(self)


def _version(name: str) -> str:
    m = re.search(r"v?(\d+\.\d+\.\d+[\w.\-]*)", name)
    return m.group(1) if m else ""


def classify(name: str) -> tuple[str, str, str, str, int | None]:
    """Return (layer, kind, role, subsystem, number) for a stockpile directory name."""
    n = name.lower()
    m = re.match(r"(gap|inv|pln|sch)(\d+)", n)
    if m:
        kind, num = m.group(1), int(m.group(2))
        if kind == "gap":
            sub, role = GAP_ROLES.get(num, ("continuous", "gap"))
            return "continuous", "gap", role, sub, num
        if kind == "pln":
            return "continuous", "plane", f"{PLN_ROLES.get(num, 'plane')} plane", "planes", num
        if kind == "sch":
            return "continuous", "scheduler", "workload classification and runtime placement", "scheduling", num
        sub = next((s for lo, hi, s in INV_BANDS if lo <= num <= hi), "invention")
        role = re.sub(r"_v\d.*$|-\d.*$", "", name[len(m.group(0)) + 1:]).replace("_", " ")
        return "continuous", "inv", role, sub, num
    if n.startswith("hermit-ramws"):
        return "session", "surface", "virtual terminal + RAM virtual WebSocket (hermit.vws.v2)", "io", None
    if n.startswith("df_unified"):
        return "unified", "door", "single door: registry, pins, batteries, console over sealed members", "door", None
    if n == "df_fabric":
        return "control", "fabric", "federation control plane; replica/pipeline/BSP; PK overlays", "fabric", None
    for tier in DF_TIERS:
        if name == tier:
            return "execution", "node", f"sealed execution node {DF_TIERS[tier][0]}", "nodes", None
    if n.startswith("bottle_rocket"):
        return "model", "vm-package", "operational VM package embedded by DF size tiers", "vm", None
    if n == "_model":
        return "model", "refinement", "estate refinement, reasoning center, runtime tooling", "reasoning", None
    if n.startswith("qvm"):
        return "execution", "vm", "Quorum/Quantum VM (classical emulation)", "vm", None
    if n.startswith(("ios735", "linearandroid")):
        return "clients", "mobile", "mobile client LCTL surface", "mobile", None
    if n.startswith("uc32"):
        return "control", "containership", "unikernel containership ACF web candidate", "fabric", None
    if n == "rodeo":
        return "model", "build", "RODEO build tool", "build", None
    return "model", "other", "unclassified stockpile", "other", None


def _package_dir(p: Path) -> Path:
    """Many atoms wrap their package in one inner directory."""
    try:
        entries = list(p.iterdir())
    except OSError:
        return p
    kids = [c for c in entries if c.is_dir() and not c.name.startswith(".")]
    files = [c for c in entries if c.is_file() and not c.name.startswith(".")]
    if len(kids) == 1 and not files:
        return kids[0]
    return p


def discover(root: Path) -> list[Atom]:
    atoms: list[Atom] = []
    seen: dict[str, str] = {}
    for d in sorted(p for p in root.iterdir() if p.is_dir()):
        if d.name in ("vendor", "CFP_Continuous_Fabric_Platform_v1.0.0") or d.name.startswith("."):
            continue
        layer, kind, role, sub, num = classify(d.name)
        pkg = _package_dir(d)
        try:
            ev = [e for e in EVIDENCE_FILES if (pkg / e).exists()]
        except OSError:
            ev = []
        tier, dialect = DF_TIERS.get(d.name, ("", ""))
        a = Atom(d.name, str(d), layer, kind, role, sub, num, _version(d.name), tier, dialect,
                 str(pkg), ev)
        key = f"{kind}{num}" if num is not None else ""
        if key and key in seen and re.search(r"_1$|\(1\)$", d.name):
            a.duplicate_of = seen[key]
        elif key:
            seen.setdefault(key, d.name)
        atoms.append(a)
    return atoms


def summary(atoms: list[Atom]) -> dict:
    out: dict = {"total": len(atoms), "by_layer": {}, "by_kind": {}, "duplicates": 0}
    for a in atoms:
        out["by_layer"][a.layer] = out["by_layer"].get(a.layer, 0) + 1
        out["by_kind"][a.kind] = out["by_kind"].get(a.kind, 0) + 1
        out["duplicates"] += bool(a.duplicate_of)
    return out


def load_ledger(path: Path) -> dict:
    try:
        return json.loads(path.read_text(encoding="utf-8"))
    except (OSError, ValueError):
        return {}
