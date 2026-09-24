import asyncio, json, tempfile, time, unittest
from pathlib import Path
from cfp import atlas, vendor, gate
from cfp.fabric import Fabric, FabricError, ReplicatedState
from cfp.server import Gateway
from cfp.ws import connect

NAMES = ["_model", "DF_Fabric", "DF_Small", "DF_Large", "DF_Unified", "hermit-ramws_2.0.0-ramws.1",
         "gap04_disconnected_operation_controller_v4.3.0", "gap06_device_identity_and_attestation_v5.0.0",
         "inv36_control_transport_v5.1.0_mc_applied", "inv24_microvm_runtime_v4.3.0", "inv24_microvm_runtime_v4.3.0_1",
         "pln06_data_plane_v4.3.0", "LinearAndroid_LCTL_v0.1.0", "BOTTLE_ROCKET_3.0.0_MODEL_OPERATIONAL_110K"]


def make_root(d: Path):
    for n in NAMES:
        (d / n).mkdir()
        (d / n / "README.md").write_text(n)
    pkg = d / "inv36_control_transport_v5.1.0_mc_applied" / "inv36_control_transport"
    (d / "inv36_control_transport_v5.1.0_mc_applied" / "README.md").unlink()
    (pkg / "tests").mkdir(parents=True)
    (pkg / "__init__.py").write_text("")
    (pkg / "tests" / "__init__.py").write_text("")
    (pkg / "tests" / "test_ok.py").write_text("import unittest\nclass T(unittest.TestCase):\n def test(self): pass\n")
    (pkg / ".mypy_cache").mkdir()
    (pkg / ".mypy_cache" / "junk").write_text("x")


class AtlasVendorGate(unittest.TestCase):
    def test_classify_vendor_gate(self):
        with tempfile.TemporaryDirectory() as t:
            root = Path(t) / "PKW"; root.mkdir(); make_root(root)
            atoms = {a.name: a for a in atlas.discover(root)}
            self.assertEqual(atoms["hermit-ramws_2.0.0-ramws.1"].layer, "session")
            self.assertEqual(atoms["DF_Large"].tier, "N_LARGE")
            self.assertEqual(atoms["gap06_device_identity_and_attestation_v5.0.0"].subsystem, "admission")
            self.assertEqual(atoms["inv24_microvm_runtime_v4.3.0_1"].duplicate_of, "inv24_microvm_runtime_v4.3.0")
            self.assertEqual(atoms["LinearAndroid_LCTL_v0.1.0"].layer, "clients")
            self.assertTrue(all(a.status == "STAGED" for a in atoms.values()))  # existence never promotes
            dest = Path(t) / "plat" / "vendor"
            m = vendor.vendor(root, dest, log=lambda *_: None)
            self.assertIn("skipped", m["atoms"]["inv24_microvm_runtime_v4.3.0_1"])
            self.assertFalse((dest / "inv36_control_transport_v5.1.0_mc_applied/inv36_control_transport/.mypy_cache").exists())
            self.assertTrue(vendor.verify(dest)["ok"])
            (dest / "DF_Small" / "README.md").write_text("tampered")
            self.assertFalse(vendor.verify(dest)["ok"])
            a = next(x for x in atlas.discover(dest) if x.name.startswith("inv36"))
            rec = gate.run_gate(a.to_dict(), Path(t) / "ev")
            self.assertEqual(rec["status"], "GATED_PASS", rec.get("tail"))
            led = {}
            self.assertEqual(gate.promote(led, rec, True), "OPERATIONAL")
            b = next(x for x in atlas.discover(dest) if x.name == "DF_Small")
            self.assertEqual(gate.run_gate(b.to_dict(), Path(t) / "ev")["status"], "STAGED")


class FabricCore(unittest.TestCase):
    def test_admission(self):
        f = Fabric()
        t = f.attestor.issue("p1", "mobile")
        f.join(t, {})
        with self.assertRaises(FabricError) as c: f.join(t, {})
        self.assertEqual(c.exception.code, "TICKET_REPLAY")
        raw, sig = f.attestor.issue("p2", "mobile").split(".")
        forged = bytes.fromhex(raw).replace(b'"mobile"', b'"local"').hex() + "." + sig
        with self.assertRaises(FabricError) as c: f.join(forged, {})
        self.assertEqual(c.exception.code, "TICKET_FORGED")
        f.attestor.ttl = -1
        with self.assertRaises(FabricError) as c: f.join(f.attestor.issue("p3", "cloud"), {})
        self.assertEqual(c.exception.code, "TICKET_EXPIRED")

    def test_placement(self):
        f = Fabric()
        _, ps = f.join(f.attestor.issue("phone", "mobile"), {"battery": 0.2})
        f.join(f.attestor.issue("cloud", "cloud"), {"tier": "N_LARGE", "dialect": "LCTLC/1.2"})
        f.join(f.attestor.issue("desk", "local"), {"tier": "N_SMALL", "gravity": ["ds1"], "dialect": "MSSL/ASM-1"})
        self.assertEqual(f.place({"task": "echo"}).id, "cloud")
        self.assertEqual(f.place({"task": "echo", "data": "ds1"}).id, "desk")          # data gravity
        self.assertEqual(f.place({"task": "x", "dialect": "MSSL/ASM-1"}).id, "desk")   # sealed dialect
        with self.assertRaises(FabricError): f.place({"task": "x", "min_tier": "N_XLARGE"})
        with self.assertRaises(FabricError) as c: f.submit(ps.id, {"task": "x", "heavy": True})
        self.assertEqual(c.exception.code, "FORBIDDEN")                                  # mobile lacks run.heavy
        f.leave("cloud")
        self.assertNotEqual(f.place({"task": "echo"}).id, "cloud")

    def test_convergence(self):
        a, b, hub = ReplicatedState("a"), ReplicatedState("b"), ReplicatedState("hub")
        a.set("k", 1, ts=1); b.set("k", 2, ts=2); a.set("x", "only-a", ts=3)
        hub.merge(a.drain()); hub.merge(b.drain())
        a.merge(hub.data.values()); b.merge(hub.data.values())
        self.assertEqual(a.get("k"), 2); self.assertEqual(b.get("k"), 2); self.assertEqual(b.get("x"), "only-a")


class EndToEnd(unittest.TestCase):
    def test_mobile_cloud_local_over_vws(self):
        asyncio.run(self._run())

    async def _run(self):
        with tempfile.TemporaryDirectory() as t:
            plat = Path(t) / "plat"; (plat / "vendor").mkdir(parents=True)
            gw = Gateway(plat, Fabric(), "127.0.0.1", 0)
            srv = await gw.serve()
            port = srv.sockets[0].getsockname()[1]; gw.port = port
            from cfp.node import execute

            async def agent(nid, cls, profile):
                ws = await connect("127.0.0.1", port)
                await ws.send(json.dumps({"op": "join", "ticket": gw.fabric.attestor.issue(nid, cls), "profile": profile}))
                inbox = asyncio.Queue()

                async def pump():
                    while True:
                        m = json.loads(await ws.recv())
                        if m["op"] == "exec":
                            await ws.send(json.dumps({"op": "result", "job": m["job"], "result": execute(m["task"])}))
                        else:
                            await inbox.put(m)
                task = asyncio.create_task(pump())
                while (await asyncio.wait_for(inbox.get(), 5))["op"] != "welcome":
                    pass
                return ws, inbox, task

            async def term(ws, inbox, line, want="out", contains=""):
                await ws.send(json.dumps({"op": "term", "line": line}))
                while True:
                    m = await asyncio.wait_for(inbox.get(), 5)
                    if m["op"] == want and contains in m.get("text", ""):
                        return m.get("text", "")

            con = await agent("console", "local", {"tier": "N_SMALL"})
            cld = await agent("cloud-1", "cloud", {"tier": "N_LARGE", "zone": "us-west"})
            mob = await agent("phone-1", "mobile", {"battery": 0.9, "gravity": ["photos"]})
            self.assertIn("phone-1", await term(*con[:2], "nodes"))
            self.assertIn("-> cloud-1", await term(*mob[:2], "run echo hi"))
            self.assertIn('"hi"', await self._wait(mob[1], '"hi"'))
            self.assertIn("-> phone-1", await term(*con[:2], "run sha256 abc --on-data photos"))
            await self._wait(con[1], "ba7816bf")
            # partition: phone writes offline, cloud writes online, both converge
            await term(*mob[:2], "offline")
            self.assertIn("queued offline", await term(*mob[:2], "set mode edge"))
            await term(*cld[:2], "set region us-west")
            self.assertIn("pulled", await term(*mob[:2], "online"))
            self.assertIn("'us-west'", await term(*mob[:2], "get region"))
            self.assertIn("converged", await term(*cld[:2], "sync"))
            self.assertIn("'edge'", await term(*cld[:2], "get mode"))
            self.assertIn("FORBIDDEN", await term(*mob[:2], "ticket x local"))
            self.assertIn("join URL", await term(*con[:2], "ticket tablet-2 mobile"))
            for ws, _, task in (con, cld, mob):
                task.cancel(); await ws.close()
            srv.close()

    async def _wait(self, inbox, needle):
        while True:
            m = await asyncio.wait_for(inbox.get(), 5)
            if needle in m.get("text", ""):
                return m["text"]


if __name__ == "__main__":
    unittest.main()
