"""Fabric core: one virtual platform over mobile, cloud and local peers.

Mapping to the stockpiles (each is a seam where the vendored atom plugs in):
  admission  : GAP-06 attestation (HMAC join tickets bound to device key), GAP-13 policy, INV-41/42 capabilities
  scheduling : GAP-02 discovery, GAP-03 topology, GAP-10 power/thermal, GAP-11 accelerators
  continuity : GAP-04 disconnected operation, GAP-05 replication (vector-clock LWW), GAP-12 WAN, GAP-14 gravity
  execution  : DF tiers N_SMALL..N_XLARGE; rows are lowered where the attested node lives (gate F7:
               images are never shipped across nodes)
  session    : hermit.vws.v2 semantics - session is the socket, byte credits + RAM ledger per session
"""
from __future__ import annotations
import hashlib, hmac, json, math, re, secrets, time, uuid
from dataclasses import dataclass, field

CLASSES = ("mobile", "cloud", "local")
TIER_RANK = {"N_SMALL": 1, "N_MEDIUM": 2, "N_LARGE": 3, "N_XLARGE": 4}
DEFAULT_CAPS = {"mobile": {"terminal", "state.read", "state.write", "run.light"},
                "cloud": {"terminal", "state.read", "state.write", "run.light", "run.heavy", "bulk"},
                "local": {"terminal", "state.read", "state.write", "run.light", "run.heavy", "bulk", "device"}}


class FabricError(Exception):
    def __init__(self, code: str, msg: str):
        super().__init__(msg)
        self.code = code


# ---------- admission (GAP-06 / GAP-13 / INV-41) ----------
class Attestor:
    """Issues and verifies join tickets. A ticket binds node id, class and capability grant to a
    fabric secret; a peer is admitted only by presenting a valid, unexpired, unreplayed ticket."""

    def __init__(self, secret: bytes | None = None, ttl: float = 600):
        self.secret, self.ttl, self.used = secret or secrets.token_bytes(32), ttl, {}

    def issue(self, node_id: str, cls: str, caps: set[str] | None = None) -> str:
        if cls not in CLASSES:
            raise FabricError("BAD_CLASS", cls)
        if not isinstance(node_id, str) or not re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9_.-]{0,63}", node_id):
            raise FabricError("BAD_NODE", "node id must be 1-64 letters, digits, dots, dashes or underscores")
        grant = DEFAULT_CAPS[cls] if caps is None else caps
        if not set(grant) <= DEFAULT_CAPS[cls]:
            raise FabricError("BAD_CAPS", "grant exceeds node class capabilities")
        body = {"node": node_id, "cls": cls, "caps": sorted(grant),
                "exp": time.time() + self.ttl, "nonce": secrets.token_hex(8)}
        raw = json.dumps(body, sort_keys=True).encode()
        sig = hmac.new(self.secret, raw, hashlib.sha256).hexdigest()
        return raw.hex() + "." + sig

    def verify(self, ticket: str) -> dict:
        try:
            if not isinstance(ticket, str) or len(ticket) > 8192:
                raise ValueError("invalid ticket")
            raw_hex, sig = ticket.split(".")
            raw = bytes.fromhex(raw_hex)
            if not re.fullmatch(r"[0-9a-f]{64}", sig):
                raise ValueError("invalid signature")
        except ValueError:
            raise FabricError("TICKET_MALFORMED", "malformed ticket")
        if not hmac.compare_digest(hmac.new(self.secret, raw, hashlib.sha256).hexdigest(), sig):
            raise FabricError("TICKET_FORGED", "signature mismatch")
        try:
            body = json.loads(raw)
            if (not isinstance(body, dict) or body.get("cls") not in CLASSES
                    or not isinstance(body.get("node"), str)
                    or not re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9_.-]{0,63}", body["node"])
                    or not isinstance(body.get("caps"), list)
                    or not all(isinstance(c, str) for c in body["caps"])
                    or not set(body["caps"]) <= DEFAULT_CAPS[body["cls"]]
                    or type(body.get("exp")) not in (int, float) or not math.isfinite(body["exp"])
                    or not isinstance(body.get("nonce"), str) or len(body["nonce"]) != 16):
                raise ValueError("invalid claims")
        except (ValueError, TypeError, UnicodeError):
            raise FabricError("TICKET_MALFORMED", "invalid ticket claims") from None
        now = time.time()
        self.used = {nonce: exp for nonce, exp in self.used.items() if exp > now}
        if body["exp"] <= now:
            raise FabricError("TICKET_EXPIRED", "ticket expired")
        if body["nonce"] in self.used:
            raise FabricError("TICKET_REPLAY", "ticket already used")
        if len(self.used) >= 10000:
            raise FabricError("ADMISSION_LIMIT", "ticket replay cache is full; retry after tickets expire")
        self.used[body["nonce"]] = body["exp"]
        return body


class Policy:
    """GAP-13 seam: deny-by-default network, capability check per verb."""

    def __init__(self, network: str = "deny"):
        self.network = network
        self.rules = {"run": "run.light", "run.heavy": "run.heavy", "set": "state.write",
                      "get": "state.read", "bulk": "bulk"}

    def check(self, caps: set[str], verb: str):
        need = self.rules.get(verb)
        if need is None or need not in caps:
            raise FabricError("FORBIDDEN", f"capability {need} not granted")


# ---------- continuity (GAP-04 / GAP-05) ----------
class ReplicatedState:
    """Per-node key/value replica with vector clocks; concurrent writes resolve LWW by (ts, node)."""

    def __init__(self, node: str):
        self.node, self.clock, self.data, self.outbox = node, {}, {}, []

    def set(self, key: str, value, ts: float | None = None):
        self.clock[self.node] = self.clock.get(self.node, 0) + 1
        op = {"key": key, "value": value, "ts": time.time() if ts is None else ts, "node": self.node, "vc": dict(self.clock)}
        self._apply(op)
        self.outbox.append(op)
        return op

    def _apply(self, op) -> bool:
        cur = self.data.get(op["key"])
        if cur is None or (op["ts"], op["node"]) > (cur["ts"], cur["node"]):
            self.data[op["key"]] = op
            return True
        return False

    def merge(self, ops) -> int:
        n = 0
        for op in ops:
            for k, v in op["vc"].items():
                self.clock[k] = max(self.clock.get(k, 0), v)
            n += self._apply(op)
        return n

    def get(self, key):
        op = self.data.get(key)
        return None if op is None else op["value"]

    def drain(self):
        out, self.outbox = self.outbox, []
        return out


# ---------- nodes, sessions, scheduling ----------
@dataclass
class Node:
    id: str
    cls: str
    caps: set
    tier: str = "N_SMALL"
    dialect: str = ""
    zone: str = "local"
    battery: float = 1.0
    thermal: float = 0.3
    accel: list = field(default_factory=list)
    gravity: list = field(default_factory=list)  # datasets resident here (GAP-14)
    online: bool = True
    load: int = 0
    last_seen: float = field(default_factory=time.time)
    state: ReplicatedState | None = None

    def public(self):
        return {"id": self.id, "cls": self.cls, "tier": self.tier, "dialect": self.dialect, "zone": self.zone,
                "battery": self.battery, "thermal": self.thermal, "accel": self.accel, "gravity": self.gravity,
                "online": self.online, "load": self.load, "caps": sorted(self.caps)}


@dataclass
class Session:
    id: str
    node: str
    credits: int = 4 << 20       # byte credits (hermit.vws.v2)
    ram_budget: int = 16 << 20   # RAM allocation ledger (LOCAL_VOLATILE)
    ram_used: int = 0
    opened: float = field(default_factory=time.time)

    def charge(self, n: int):
        if n > self.credits:
            raise FabricError("CREDITS_EXHAUSTED", "session byte credits exhausted")
        self.credits -= n

    def alloc(self, n: int):
        if self.ram_used + n > self.ram_budget:
            raise FabricError("RAM_BUDGET", "session RAM ledger exceeded")
        self.ram_used += n


def score(node: Node, job: dict) -> float | None:
    """GAP-02/03/10/11/14 placement score; None => ineligible."""
    if not node.online:
        return None
    need = "run.heavy" if job.get("heavy") else "run.light"
    if need not in node.caps:
        return None
    if TIER_RANK.get(node.tier, 1) < TIER_RANK.get(job.get("min_tier", "N_SMALL"), 1):
        return None
    if job.get("dialect") and job["dialect"] != node.dialect:
        return None  # sealed rows lower only onto matching dialect (images not portable)
    if job.get("accel") and job["accel"] not in node.accel:
        return None
    s = 10.0 * TIER_RANK.get(node.tier, 1)
    s -= 4.0 * node.load
    s -= 20.0 * max(0.0, node.thermal - 0.7)                        # thermal headroom
    if node.cls == "mobile":
        s -= 15.0 * (1.0 - node.battery)                            # spare the phone battery
    if job.get("data") and job["data"] in node.gravity:
        s += 25.0                                                   # move compute to data
    if job.get("near") and node.zone == job["near"]:
        s += 5.0                                                    # topology affinity
    return s


class Fabric:
    def __init__(self, secret: bytes | None = None, network: str = "deny"):
        self.attestor = Attestor(secret)
        self.policy = Policy(network)
        self.nodes: dict[str, Node] = {}
        self.sessions: dict[str, Session] = {}
        self.hub = ReplicatedState("hub")
        self.events: list[dict] = []
        self.jobs: dict[str, dict] = {}

    def log(self, kind, **kw):
        ev = {"t": time.time(), "kind": kind, **kw}
        self.events.append(ev)
        del self.events[:-5000]
        return ev

    # admission
    def join(self, ticket: str, profile: dict) -> tuple[Node, Session]:
        if not isinstance(profile, dict):
            raise FabricError("BAD_PROFILE", "profile must be an object")
        if not isinstance(profile.get("tier", "N_SMALL"), str) or profile.get("tier", "N_SMALL") not in TIER_RANK:
            raise FabricError("BAD_PROFILE", "unknown tier")
        for key in ("battery", "thermal"):
            value = profile.get(key, 1.0 if key == "battery" else 0.3)
            if type(value) not in (int, float) or not math.isfinite(value) or not 0 <= value <= 1:
                raise FabricError("BAD_PROFILE", f"{key} must be a finite number between 0 and 1")
        for key in ("zone", "dialect"):
            if key in profile and (not isinstance(profile[key], str) or len(profile[key]) > 128):
                raise FabricError("BAD_PROFILE", f"invalid {key}")
        for key in ("accel", "gravity"):
            value = profile.get(key, [])
            if not isinstance(value, list) or len(value) > 128 or not all(isinstance(v, str) and len(v) <= 128 for v in value):
                raise FabricError("BAD_PROFILE", f"invalid {key}")
        if len(self.nodes) >= 256:
            raise FabricError("ADMISSION_LIMIT", "node capacity reached")
        body = self.attestor.verify(ticket)
        nid = body["node"]
        if nid in self.nodes and self.nodes[nid].online:
            raise FabricError("NODE_ACTIVE", "node already has an active session")
        node = Node(id=nid, cls=body["cls"], caps=set(body["caps"]),
                    tier=profile.get("tier", "N_SMALL"), dialect=profile.get("dialect", ""),
                    zone=profile.get("zone", body["cls"]), battery=float(profile.get("battery", 1.0)),
                    thermal=float(profile.get("thermal", 0.3)), accel=list(profile.get("accel", [])),
                    gravity=list(profile.get("gravity", [])), state=ReplicatedState(nid))
        prev = self.nodes.get(nid)
        if prev and prev.state:
            node.state = prev.state
        self.nodes[nid] = node
        sess = Session(id=uuid.uuid4().hex, node=nid)
        self.sessions[sess.id] = sess
        self.log("join", node=nid, cls=node.cls, tier=node.tier)
        return node, sess

    def leave(self, nid: str):
        if nid in self.nodes:
            self.nodes[nid].online = False
            self.log("partition", node=nid)
        for sid in [sid for sid, sess in self.sessions.items() if sess.node == nid]:
            del self.sessions[sid]
        for rec in self.jobs.values():
            if rec["node"] == nid and rec["state"] == "placed":
                rec.update(state="failed", result={"error": "node disconnected"}, done=time.time())
        if nid in self.nodes:
            self.nodes[nid].load = 0

    def heartbeat(self, nid: str, telemetry: dict):
        if not isinstance(telemetry, dict):
            raise FabricError("BAD_TELEMETRY", "telemetry must be an object")
        for key in ("battery", "thermal"):
            value = telemetry.get(key, 0)
            if type(value) not in (int, float) or not math.isfinite(value) or not 0 <= value <= 1:
                raise FabricError("BAD_TELEMETRY", f"invalid {key}")
        n = self.nodes[nid]
        n.last_seen = time.time()
        for k in ("battery", "thermal"):
            if k in telemetry:
                setattr(n, k, type(getattr(n, k))(telemetry[k]))

    # scheduling
    def place(self, job: dict) -> Node:
        if job.get("min_tier", "N_SMALL") not in TIER_RANK:
            raise FabricError("BAD_TIER", "unknown minimum tier")
        ranked = [(s, n) for n in self.nodes.values() if (s := score(n, job)) is not None]
        if not ranked:
            raise FabricError("NO_PLACEMENT", "no attested node satisfies the job")
        ranked.sort(key=lambda x: (-x[0], x[1].id))
        return ranked[0][1]

    def submit(self, session_id: str, job: dict) -> dict:
        sess = self.sessions[session_id]
        caps = self.nodes[sess.node].caps
        self.policy.check(caps, "run.heavy" if job.get("heavy") else "run")
        if job.get("task") == "probe" and "device" not in caps:
            raise FabricError("FORBIDDEN", "probe imports trusted local code and requires device capability")
        if len(self.jobs) >= 1000:
            finished = next((jid for jid, rec in self.jobs.items() if rec["state"] != "placed"), None)
            if finished is None:
                raise FabricError("JOB_LIMIT", "too many pending jobs")
            del self.jobs[finished]
        target = self.place(job)
        jid = uuid.uuid4().hex[:12]
        rec = {"id": jid, "job": job, "node": target.id, "from": sess.node, "state": "placed", "t": time.time()}
        self.jobs[jid] = rec
        target.load += 1
        self.log("place", job=jid, node=target.id, origin=sess.node)
        return rec

    def complete(self, jid: str, result, nid: str):
        rec = self.jobs.get(jid)
        if not rec or rec["node"] != nid:
            raise FabricError("FORBIDDEN", "only the assigned node may complete a job")
        if rec["state"] != "placed":
            raise FabricError("JOB_COMPLETE", "job is no longer pending")
        rec.update(state="done", result=result, done=time.time())
        n = self.nodes.get(rec["node"])
        if n:
            n.load = max(0, n.load - 1)
        self.log("done", job=jid, node=rec["node"])
        return rec

    # continuity
    def sync(self, nid: str, ops: list) -> list:
        """Merge a node's outbox into the hub replica and return hub ops the node has not seen."""
        applied = self.hub.merge(ops)
        node = self.nodes[nid]
        seen = node.state.clock if node.state else {}
        # A vector clock alone cannot prove possession of every key from that writer.
        # Send each current key value missing from this replica, including LWW conflicts.
        back = [op for key, op in self.hub.data.items()
                if node.state is None or node.state.data.get(key) != op]
        if node.state:
            node.state.merge(back)
        self.log("sync", node=nid, applied=applied, returned=len(back))
        return back

    def snapshot(self) -> dict:
        return {"nodes": [n.public() for n in self.nodes.values()],
                "sessions": len(self.sessions), "jobs": len(self.jobs),
                "state_keys": len(self.hub.data), "network": self.policy.network}
