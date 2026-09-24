"""Fabric gateway: HTTP + virtual WebSocket (/vws) on one port, plus the virtual terminal."""
from __future__ import annotations
import asyncio, base64, binascii, json, shlex, time
from pathlib import Path
from urllib.parse import urlsplit
from . import __version__, atlas, gate, vendor as vend
from .fabric import Fabric, FabricError, CLASSES
from .ws import WebSocket, Closed, accept_key

HERE = Path(__file__).resolve().parent
WEB = HERE / "web"
MAX_LINE = 4096

HELP = """CFP virtual terminal - one platform over mobile, cloud and local
  whoami | nodes | sessions | status | events [n] | layers | atoms [layer|kind]
  ticket <node-id> <mobile|cloud|local>      issue attested join ticket (local class only)
  run <task> [args..] [--heavy] [--on-data D] [--near ZONE] [--tier N_LARGE] [--dialect D]
      tasks: echo | sha256 | sum | sleep | probe <atom>
  jobs | job <id>
  set <key> <value> | get <key> | sync      replicated state (partition-tolerant)
  offline | online                          simulate partition of this node (GAP-04)
  gate <atom>                               run promotion gate on a vendored atom (local only)
  ledger                                    promotion statuses
  vendor-verify                             re-hash vendored copies"""


class Gateway:
    def __init__(self, platform_root: Path, fabric: Fabric | None = None, host="127.0.0.1", port=8740):
        self.root = platform_root
        self.vendor_dir = platform_root / "vendor"
        self.ledger_path = platform_root / "ledger" / "PLATFORM_LEDGER.json"
        self.evidence_dir = platform_root / "ledger" / "evidence"
        self.fabric = fabric or Fabric()
        self.host, self.port = host, port
        self.conns: dict[str, WebSocket] = {}       # node id -> socket
        self.sess_of: dict[str, str] = {}           # node id -> session id
        self.offline: set[str] = set()
        self.ledger = atlas.load_ledger(self.ledger_path)
        self._atoms = None

    # ---- atlas over vendored copies (falls back to sibling stockpiles if not yet vendored)
    def atoms(self):
        if self._atoms is None:
            src = self.vendor_dir if any(self.vendor_dir.glob("*/.cfp_vendor.json")) else self.root.parent
            self._atoms = atlas.discover(src) if src.exists() else []
            for a in self._atoms:
                a.status = self.ledger.get(a.name, {}).get("status", "STAGED")
        return self._atoms

    def save_ledger(self):
        self.ledger_path.parent.mkdir(parents=True, exist_ok=True)
        self.ledger_path.write_text(json.dumps(self.ledger, indent=2), encoding="utf-8")

    # ---- HTTP
    async def handle(self, r: asyncio.StreamReader, w: asyncio.StreamWriter):
        try:
            head = await asyncio.wait_for(r.readuntil(b"\r\n\r\n"), 10)
        except Exception:
            w.close()
            return
        lines = head.decode("latin-1").split("\r\n")
        method, target, _ = (lines[0].split(" ") + ["", ""])[:3]
        hdr = {k.strip().lower(): v.strip() for k, _, v in (l.partition(":") for l in lines[1:] if l)}
        path = urlsplit(target).path
        if method != "GET":
            w.write(b"HTTP/1.1 405 Method Not Allowed\r\nAllow: GET\r\nContent-Length: 0\r\nConnection: close\r\n\r\n")
            await w.drain()
            w.close()
            return
        if path == "/vws" and hdr.get("upgrade", "").lower() == "websocket":
            try:
                valid_key = len(base64.b64decode(hdr.get("sec-websocket-key", ""), validate=True)) == 16
            except (ValueError, binascii.Error):
                valid_key = False
            origin = urlsplit(hdr.get("origin", ""))
            if (not valid_key or hdr.get("sec-websocket-version") != "13"
                    or "upgrade" not in {s.strip().lower() for s in hdr.get("connection", "").split(",")}
                    or (hdr.get("origin") and (origin.scheme not in ("http", "https") or origin.netloc != hdr.get("host")))):
                w.write(b"HTTP/1.1 400 Bad Request\r\nContent-Length: 0\r\nConnection: close\r\n\r\n")
                await w.drain()
                w.close()
                return
            w.write(("HTTP/1.1 101 Switching Protocols\r\nUpgrade: websocket\r\nConnection: Upgrade\r\n"
                     f"Sec-WebSocket-Accept: {accept_key(hdr.get('sec-websocket-key', ''))}\r\n\r\n").encode())
            await w.drain()
            await self.session(WebSocket(r, w, mask=False))
            return
        if path in ("/", "/index.html"):
            body, ctype = (WEB / "index.html").read_bytes(), "text/html; charset=utf-8"
        elif path in ("/api/fabric", "/api/atlas"):
            # Operational metadata is available through the authenticated terminal.
            w.write(b"HTTP/1.1 403 Forbidden\r\nContent-Length: 0\r\nConnection: close\r\n\r\n")
            await w.drain()
            w.close()
            return
        elif path == "/healthz":
            body, ctype = b'{"ok":true}', "application/json"
        else:
            body, ctype = b"not found", "text/plain"
        code = "200 OK" if body != b"not found" else "404 Not Found"
        w.write((f"HTTP/1.1 {code}\r\nContent-Type: {ctype}\r\nContent-Length: {len(body)}\r\n"
                 "Cache-Control: no-store\r\nX-Content-Type-Options: nosniff\r\n"
                 "Referrer-Policy: no-referrer\r\nX-Frame-Options: DENY\r\n"
                 "Content-Security-Policy: default-src 'self'; connect-src 'self'; frame-ancestors 'none'; base-uri 'none'; "
                 "style-src 'self' 'unsafe-inline'; script-src 'self' 'unsafe-inline'\r\n"
                 "Connection: close\r\n\r\n").encode() + body)
        await w.drain()
        w.close()

    # ---- virtual WebSocket session (hermit.vws.v2 semantics)
    async def session(self, ws: WebSocket):
        node = sess = None
        try:
            first = json.loads(await asyncio.wait_for(ws.recv(), 15))
            if not isinstance(first, dict) or first.get("op") != "join":
                raise FabricError("JOIN_REQUIRED", "first frame must be join")
            node, sess = self.fabric.join(first.get("ticket", ""), first.get("profile", {}))
            old = self.conns.get(node.id)
            if old:
                await old.close(4000)
            self.conns[node.id], self.sess_of[node.id] = ws, sess.id
            self.offline.discard(node.id)
            await ws.send(json.dumps({"op": "welcome", "node": node.public(), "session": sess.id,
                                      "credits": sess.credits, "version": __version__}))
            await self.broadcast({"op": "fabric", "snapshot": self.fabric.snapshot()})
            while True:
                raw = await asyncio.wait_for(ws.recv(), 120)
                sess.charge(len(raw.encode("utf-8")))
                msg = json.loads(raw)
                if not isinstance(msg, dict):
                    raise FabricError("BAD_MESSAGE", "message must be an object")
                await self.dispatch(node.id, sess, msg, ws)
        except FabricError as e:
            try:
                await ws.send(json.dumps({"op": "error", "code": e.code, "msg": str(e)}))
            except Exception:
                pass
        except (Closed, asyncio.IncompleteReadError, asyncio.TimeoutError, ConnectionError, ValueError, RecursionError):
            pass
        finally:
            await ws.close()
            if node and self.conns.get(node.id) is ws:
                del self.conns[node.id]
                self.sess_of.pop(node.id, None)
                self.offline.discard(node.id)
                self.fabric.leave(node.id)
                await self.broadcast({"op": "fabric", "snapshot": self.fabric.snapshot()})

    async def broadcast(self, msg):
        data = json.dumps(msg)
        for nid, ws in list(self.conns.items()):
            try:
                await ws.send(data)
            except Exception:
                pass

    async def dispatch(self, nid, sess, msg, ws):
        op = msg.get("op")
        if op == "hb":
            self.fabric.heartbeat(nid, msg.get("telemetry", {}))
        elif op == "term":
            line = str(msg.get("line", ""))[:MAX_LINE]
            try:
                out = await self.terminal(nid, sess, line)
            except FabricError as e:
                out = f"error {e.code}: {e}"
            except (ValueError, IndexError):
                out = "error USAGE: invalid command arguments (try help)"
            await ws.send(json.dumps({"op": "out", "text": out}))
        elif op == "sync":
            node = self.fabric.nodes[nid]
            self.fabric.policy.check(node.caps, "get")
            # Writes use `set`, which assigns identity, clock and time on the gateway.
            # Never merge client-supplied clocks or timestamps into shared state.
            if msg.get("ops"):
                raise FabricError("FORBIDDEN", "raw replica writes are disabled; use set")
            back = self.fabric.sync(nid, node.state.drain())
            await ws.send(json.dumps({"op": "synced", "ops": back}))
        elif op == "result":
            if not isinstance(msg.get("job"), str):
                raise FabricError("BAD_MESSAGE", "job must be a string")
            sess.alloc(len(json.dumps(msg.get("result")).encode("utf-8")))
            rec = self.fabric.complete(msg["job"], msg.get("result"), nid)
            origin = self.conns.get(rec["from"])
            if origin:
                await origin.send(json.dumps({"op": "out", "text": f"[{rec['id']} on {rec['node']}] "
                                              f"{json.dumps(rec['result'])}"}))
        else:
            raise FabricError("BAD_MESSAGE", "unknown operation")

    # ---- virtual terminal
    async def terminal(self, nid: str, sess, line: str) -> str:
        argv = shlex.split(line) if line.strip() else []
        if not argv:
            return ""
        f, node, cmd = self.fabric, self.fabric.nodes[nid], argv[0]
        if "terminal" not in node.caps:
            raise FabricError("FORBIDDEN", "terminal capability not granted")
        local_only = node.cls == "local"
        if cmd == "help":
            return HELP
        if cmd == "whoami":
            return json.dumps({**node.public(), "session": sess.id, "credits": sess.credits,
                               "ram_used": sess.ram_used, "ram_budget": sess.ram_budget}, indent=1)
        if cmd == "nodes":
            return "\n".join(f"{n.id:<16}{n.cls:<8}{n.tier:<10}{n.zone:<10}load={n.load} bat={n.battery:.2f} "
                             f"therm={n.thermal:.2f} {'online' if n.online else 'OFFLINE'}"
                             for n in f.nodes.values()) or "(none)"
        if cmd == "sessions":
            return "\n".join(f"{s.id[:8]} node={s.node} credits={s.credits}" for s in f.sessions.values())
        if cmd == "status":
            s = atlas.summary(self.atoms())
            st = {}
            for a in self.atoms():
                st[a.status] = st.get(a.status, 0) + 1
            return json.dumps({"fabric": f.snapshot(), "atlas": s, "promotion": st}, indent=1)
        if cmd == "events":
            n = int(argv[1]) if len(argv) > 1 else 15
            return "\n".join(json.dumps(e) for e in f.events[-n:])
        if cmd == "layers":
            s = atlas.summary(self.atoms())["by_layer"]
            return "\n".join(f"{l:<11}{s.get(l, 0)}" for l in atlas.LAYERS)
        if cmd == "atoms":
            flt = argv[1] if len(argv) > 1 else None
            rows = [a for a in self.atoms() if not flt or flt in (a.layer, a.kind, a.subsystem)]
            return "\n".join(f"{a.status:<12}{a.layer:<11}{a.name}  - {a.role}" +
                             (f" (dup of {a.duplicate_of})" if a.duplicate_of else "") for a in rows)
        if cmd == "ticket":
            if not local_only:
                raise FabricError("FORBIDDEN", "only local-class nodes may issue tickets")
            if len(argv) < 3 or argv[2] not in CLASSES:
                return "usage: ticket <node-id> <mobile|cloud|local>"
            t = f.attestor.issue(argv[1], argv[2])
            return f"ticket for {argv[1]} ({argv[2]}), single use, 10 min:\n{t}\n" \
                   f"join URL: http://{self.host}:{self.port}/#t={t}&id={argv[1]}"
        if cmd == "run":
            job = self._parse_job(argv[1:])
            sess.alloc(len(line))
            rec = f.submit(sess.id, job)
            target = self.conns.get(rec["node"])
            if target is None:
                return f"placed {rec['id']} on {rec['node']} but node is unreachable"
            await target.send(json.dumps({"op": "exec", "job": rec["id"], "task": job}))
            return f"placed {rec['id']} -> {rec['node']}"
        if cmd == "jobs":
            return "\n".join(f"{j['id']} {j['state']:<7}{j['node']:<16}{j['job']['task']}"
                             for j in f.jobs.values()) or "(none)"
        if cmd == "job":
            job = f.jobs.get(argv[1], {})
            if job and nid not in (job["from"], job["node"]) and not local_only:
                raise FabricError("FORBIDDEN", "job belongs to another node")
            return json.dumps(job, indent=1, default=str)
        if cmd == "set":
            f.policy.check(node.caps, "set")
            sess.alloc(len(line.encode("utf-8")))
            if argv[1] not in f.hub.data and len(f.hub.data) >= 1000:
                raise FabricError("STATE_LIMIT", "state key capacity reached")
            op = node.state.set(argv[1], " ".join(argv[2:]))
            if nid not in self.offline:
                f.sync(nid, node.state.drain())
                return f"set {argv[1]} (synced)"
            return f"set {argv[1]} (queued offline; {len(node.state.outbox)} pending)"
        if cmd == "get":
            f.policy.check(node.caps, "get")
            return repr(node.state.get(argv[1]))
        if cmd == "sync":
            f.policy.check(node.caps, "get")
            if nid in self.offline:
                return "offline: cannot sync"
            back = f.sync(nid, node.state.drain())
            return f"converged; pulled {len(back)} op(s)"
        if cmd == "offline":
            self.offline.add(nid)
            f.log("partition", node=nid, simulated=True)
            return "node is now partitioned; writes queue locally"
        if cmd == "online":
            f.policy.check(node.caps, "get")
            self.offline.discard(nid)
            back = f.sync(nid, node.state.drain())
            return f"reconnected; converged, pulled {len(back)} op(s)"
        if cmd == "ledger":
            return json.dumps(self.ledger, indent=1) if self.ledger else "(no promotions yet)"
        if cmd == "vendor-verify":
            if not local_only:
                raise FabricError("FORBIDDEN", "local only")
            v = await asyncio.to_thread(vend.verify, self.vendor_dir)
            return json.dumps({"checked": v["checked"], "ok": v["ok"], "mismatched": v["mismatched"][:20]})
        if cmd == "gate":
            if not local_only:
                raise FabricError("FORBIDDEN", "local only")
            a = next((x for x in self.atoms() if x.name == (argv[1] if len(argv) > 1 else "")), None)
            if not a:
                return "unknown atom"
            rec = await asyncio.to_thread(gate.run_gate, a.to_dict(), self.evidence_dir)
            linked = vend.verify_atom(Path(a.path))["ok"]
            a.status = gate.promote(self.ledger, rec, linked)
            self.save_ledger()
            return f"{a.name}: {a.status} (exit={rec.get('exit')}, evidence={rec.get('evidence_path')})" + \
                   ("" if linked else "\nnot vendored: GATED_PASS cannot become OPERATIONAL until vendored")
        return f"unknown command: {cmd} (try help)"

    @staticmethod
    def _parse_job(args):
        job, rest, i = {}, [], 0
        flags = {"--on-data": "data", "--near": "near", "--tier": "min_tier", "--dialect": "dialect",
                 "--accel": "accel"}
        while i < len(args):
            a = args[i]
            if a == "--heavy":
                job["heavy"] = True
            elif a in flags and i + 1 < len(args):
                job[flags[a]] = args[i + 1]
                i += 1
            else:
                rest.append(a)
            i += 1
        if not rest:
            raise FabricError("USAGE", "run <task> [args..]")
        job["task"], job["args"] = rest[0], rest[1:]
        return job

    async def serve(self):
        if self.fabric.policy.network == "deny" and self.host not in ("127.0.0.1", "localhost", "::1"):
            raise FabricError("NETWORK_DENIED", "network=deny requires loopback binding")
        srv = await asyncio.start_server(self.handle, self.host, self.port)
        return srv
