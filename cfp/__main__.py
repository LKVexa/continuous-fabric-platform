"""cfp CLI: atlas | vendor | vendor-verify | up | node | gate"""
from __future__ import annotations
import argparse, asyncio, json, os, sys
from pathlib import Path
from . import atlas, vendor, gate, __version__
from .fabric import Fabric
from .server import Gateway

PLATFORM = Path(os.environ.get("CFP_HOME", Path.cwd())).resolve()
DEFAULT_ROOT = PLATFORM.parent  # the "Post Kubernetes World" folder this platform sits in


def main(argv=None):
    ap = argparse.ArgumentParser(prog="cfp", description=f"Continuous Fabric Platform {__version__}")
    ap.add_argument("--root", type=Path, default=DEFAULT_ROOT, help="stockpile root")
    sub = ap.add_subparsers(dest="cmd", required=True)
    sub.add_parser("atlas")
    v = sub.add_parser("vendor"); v.add_argument("--include-duplicates", action="store_true")
    v.add_argument("--only", nargs="*")
    sub.add_parser("vendor-verify")
    g = sub.add_parser("gate"); g.add_argument("atom", nargs="?"); g.add_argument("--all", action="store_true")
    u = sub.add_parser("up"); u.add_argument("--host", default="127.0.0.1"); u.add_argument("--port", type=int, default=8740)
    u.add_argument("--network", choices=["deny", "lan", "wan"], default="deny")
    n = sub.add_parser("node"); n.add_argument("--gateway", default="127.0.0.1:8740"); n.add_argument("--ticket", required=True)
    n.add_argument("--profile", default="{}", help='JSON e.g. {"tier":"N_LARGE","zone":"cloud-us"}')
    a = ap.parse_args(argv)

    if a.cmd == "atlas":
        atoms = atlas.discover(a.root)
        for x in atoms:
            print(f"{x.layer:<11}{x.kind:<12}{x.name}" + (f"  [dup of {x.duplicate_of}]" if x.duplicate_of else ""))
        print(json.dumps(atlas.summary(atoms), indent=1))
        (PLATFORM / "ledger").mkdir(exist_ok=True)
        (PLATFORM / "ledger" / "ATLAS.json").write_text(json.dumps([x.to_dict() for x in atoms], indent=1), encoding="utf-8")
    elif a.cmd == "vendor":
        m = vendor.vendor(a.root, PLATFORM / "vendor", a.include_duplicates, a.only)
        print(f"vendored {sum(1 for v in m['atoms'].values() if 'files' in v)} atoms -> {PLATFORM / 'vendor'}")
    elif a.cmd == "vendor-verify":
        r = vendor.verify(PLATFORM / "vendor"); print(json.dumps(r, indent=1)); return 0 if r["ok"] else 1
    elif a.cmd == "gate":
        src = PLATFORM / "vendor"
        atoms = [x for x in atlas.discover(src) if a.all or x.name == a.atom]
        if not atoms:
            ap.error("no matching vendored atoms; use vendor before gate")
        ledger_p = PLATFORM / "ledger" / "PLATFORM_LEDGER.json"
        ledger = atlas.load_ledger(ledger_p)
        for x in atoms:
            rec = gate.run_gate(x.to_dict(), PLATFORM / "ledger" / "evidence")
            st = gate.promote(ledger, rec, vendor.verify_atom(Path(x.path))["ok"])
            print(f"{st:<12}{x.name}")
        ledger_p.parent.mkdir(exist_ok=True); ledger_p.write_text(json.dumps(ledger, indent=2))
        return 0 if all(ledger[x.name]["status"] == "OPERATIONAL" for x in atoms) else 1
    elif a.cmd == "up":
        if a.network == "deny" and a.host not in ("127.0.0.1", "localhost", "::1"):
            ap.error("network=deny binds loopback only; pass --network lan to expose to phones on your LAN")
        asyncio.run(_up(a))
    elif a.cmd == "node":
        h, p = a.gateway.rsplit(":", 1)
        asyncio.run(__import__("cfp.node", fromlist=["run_node"]).run_node(
            h, int(p), a.ticket, json.loads(a.profile), PLATFORM / "vendor"))


async def _up(a):
    PLATFORM.mkdir(parents=True, exist_ok=True)
    # The replay cache is in memory. A fresh process key invalidates all old tickets.
    gw = Gateway(PLATFORM, Fabric(os.urandom(32), a.network), a.host, a.port)
    srv = await gw.serve()
    t = gw.fabric.attestor.issue("console", "local")
    shown = "127.0.0.1" if a.host in ("0.0.0.0", "::") else a.host
    print(f"CFP {__version__} gateway on {a.host}:{a.port} network={a.network}")
    print(f"open the console: http://{shown}:{a.port}/#t={t}&id=console")
    async with srv:
        await srv.serve_forever()


if __name__ == "__main__":
    sys.exit(main())
