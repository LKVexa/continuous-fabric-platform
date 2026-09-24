"""Node agent: joins the fabric over the virtual WebSocket and executes placed tasks.

Run one on a desktop (local), a cloud VM (cloud) or emulate a phone (mobile). Real phones join
through the browser client at / which is itself a node agent written in JavaScript.
"""
from __future__ import annotations
import asyncio, hashlib, json, math, subprocess, sys, time
from pathlib import Path
from .ws import connect, Closed

TASKS = {"echo", "sha256", "sum", "sleep", "probe"}


def execute(task: dict, vendor_dir: Path | None = None):
    name, args = task.get("task"), [str(a) for a in task.get("args", [])]
    if name == "echo":
        return " ".join(args)
    if name == "sha256":
        return hashlib.sha256(" ".join(args).encode()).hexdigest()
    if name == "sum":
        return sum(float(a) for a in args)
    if name == "sleep":
        duration = float(args[0]) if args else 0.1
        if not math.isfinite(duration) or duration < 0:
            return {"error": "sleep duration must be finite and nonnegative"}
        time.sleep(min(duration, 5))
        return "slept"
    if name == "probe":
        if not vendor_dir or not args:
            return {"error": "probe needs a vendored atom on this node"}
        root = vendor_dir.resolve()
        if Path(args[0]).name != args[0] or args[0] in (".", "..") or any(c in args[0] for c in ("/", "\\", ":")):
            return {"error": "invalid atom name"}
        atom = root / args[0]
        if atom.is_symlink() or not atom.resolve().is_relative_to(root) or not atom.is_dir():
            return {"error": "atom must be a directory within vendor"}
        from .atlas import _package_dir
        from .vendor import verify_atom
        if not verify_atom(atom)["ok"]:
            return {"error": "atom integrity verification failed"}
        pkg = _package_dir(atom)
        if pkg.is_symlink() or not pkg.resolve().is_relative_to(root) or not pkg.name.isidentifier():
            return {"error": "invalid package path"}
        if pkg is None or not (pkg / "__init__.py").exists():
            return {"atom": args[0], "importable": False, "reason": "no python package"}
        p = subprocess.run([sys.executable, "-c", "import importlib,sys; importlib.import_module(sys.argv[1])", pkg.name], cwd=pkg.parent,
                           capture_output=True, text=True, timeout=60)
        return {"atom": args[0], "package": pkg.name, "importable": p.returncode == 0,
                "stderr": p.stderr[-400:]}
    return {"error": f"unknown task {name}", "known": sorted(TASKS)}


async def run_node(host, port, ticket, profile, vendor_dir=None, script=None, on_line=print):
    ws = await connect(host, port)
    await ws.send(json.dumps({"op": "join", "ticket": ticket, "profile": profile}))

    async def pump():
        while True:
            msg = json.loads(await ws.recv())
            op = msg.get("op")
            if op == "exec":
                try:
                    res = await asyncio.to_thread(execute, msg["task"], vendor_dir)
                except Exception as e:  # task errors are results, not crashes
                    res = {"error": repr(e)}
                await ws.send(json.dumps({"op": "result", "job": msg["job"], "result": res}))
            elif op in ("out", "error", "welcome"):
                on_line(msg.get("text") or json.dumps(msg))

    async def beat():
        while True:
            await asyncio.sleep(10)
            await ws.send(json.dumps({"op": "hb", "telemetry": {k: profile[k] for k in ("battery", "thermal")
                                                                 if k in profile}}))
    tasks = [asyncio.create_task(pump()), asyncio.create_task(beat())]
    try:
        if script:
            for line in script:
                await ws.send(json.dumps({"op": "term", "line": line}))
                await asyncio.sleep(0.2)
        await asyncio.gather(*tasks)
    except Closed:
        pass
    finally:
        for t in tasks:
            t.cancel()
        await ws.close()
