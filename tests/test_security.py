"""Regression coverage for the 1.0.1 audit findings."""
import asyncio
import json
import struct
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from cfp import gate, vendor
from cfp.fabric import Fabric, FabricError, ReplicatedState
from cfp.node import execute
from cfp.server import Gateway
from cfp.ws import WebSocket, Closed, MAX_FRAME, connect


class FabricSecurity(unittest.TestCase):
    def test_empty_grant_does_not_receive_defaults(self):
        f = Fabric()
        node, sess = f.join(f.attestor.issue('restricted', 'mobile', set()), {})
        self.assertEqual(node.caps, set())
        with self.assertRaises(FabricError):
            f.submit(sess.id, {'task': 'echo'})

    def test_grants_cannot_exceed_class(self):
        with self.assertRaises(FabricError):
            Fabric().attestor.issue('phone', 'mobile', {'device'})

    def test_invalid_ticket_types_and_ids(self):
        f = Fabric()
        for value in (None, [], {}, 'a' * 9000, '00.é'):
            with self.subTest(value=type(value)), self.assertRaises(FabricError):
                f.attestor.verify(value)
        with self.assertRaises(FabricError):
            f.attestor.issue('../../x', 'local')

    def test_profiles_reject_nonfinite_and_malformed_values(self):
        f = Fabric()
        for p in ({'battery': float('nan')}, {'thermal': 4}, {'gravity': 'data'}, {'tier': 'root'}, {'tier': []}, []):
            with self.subTest(p=p), self.assertRaises(FabricError):
                f.join(f.attestor.issue('test', 'mobile'), p)

    def test_duplicate_identity_cannot_replace_active_node(self):
        f = Fabric()
        f.join(f.attestor.issue('test', 'mobile'), {})
        with self.assertRaises(FabricError):
            f.join(f.attestor.issue('test', 'local'), {})
        self.assertEqual(f.nodes['test'].cls, 'mobile')

    def test_result_requires_assigned_node_and_is_single_use(self):
        f = Fabric()
        _, s = f.join(f.attestor.issue('phone', 'mobile'), {})
        f.join(f.attestor.issue('worker', 'cloud'), {'tier': 'N_LARGE'})
        j = f.submit(s.id, {'task': 'echo'})
        with self.assertRaises(FabricError):
            f.complete(j['id'], 'forged', 'phone')
        self.assertEqual(j['state'], 'placed')
        f.complete(j['id'], 'real', 'worker')
        with self.assertRaises(FabricError):
            f.complete(j['id'], 'replayed', 'worker')
        self.assertEqual(j['result'], 'real')

    def test_dialect_must_be_advertised(self):
        f = Fabric()
        f.join(f.attestor.issue('worker', 'cloud'), {})
        with self.assertRaises(FabricError):
            f.place({'task': 'echo', 'dialect': 'sealed'})

    def test_mobile_cannot_request_code_import(self):
        f = Fabric()
        _, s = f.join(f.attestor.issue('phone', 'mobile'), {})
        with self.assertRaises(FabricError):
            f.submit(s.id, {'task': 'probe', 'args': ['atom']})

    def test_departure_cleans_sessions_and_pending_jobs(self):
        f = Fabric()
        _, s = f.join(f.attestor.issue('worker', 'cloud'), {})
        j = f.submit(s.id, {'task': 'echo'})
        f.leave('worker')
        self.assertEqual(len(f.sessions), 0)
        self.assertEqual(j['state'], 'failed')
        self.assertEqual(f.nodes['worker'].load, 0)

    def test_heartbeat_cannot_override_scheduler_load(self):
        f = Fabric()
        n, _ = f.join(f.attestor.issue('worker', 'cloud'), {})
        n.load = 3
        f.heartbeat(n.id, {'load': -100})
        self.assertEqual(n.load, 3)
        with self.assertRaises(FabricError):
            f.heartbeat(n.id, {'battery': float('inf')})

    def test_timestamp_zero_is_preserved(self):
        s = ReplicatedState('a')
        self.assertEqual(s.set('key', 'value', ts=0)['ts'], 0)

    def test_sync_returns_missing_keys_even_with_newer_vector_clock(self):
        f = Fabric()
        a, _ = f.join(f.attestor.issue('a', 'cloud'), {})
        b, _ = f.join(f.attestor.issue('b', 'cloud'), {})
        first = a.state.set('first', 1, ts=1)
        second = a.state.set('second', 2, ts=2)
        f.sync('a', a.state.drain())
        b.state.merge([second])
        self.assertEqual(b.state.clock['a'], 2)
        self.assertIsNone(b.state.get('first'))
        f.sync('b', [])
        self.assertEqual(b.state.get('first'), 1)


class VendorSecurity(unittest.TestCase):
    def test_empty_vendor_is_not_verified(self):
        with tempfile.TemporaryDirectory() as t:
            self.assertFalse(vendor.verify(Path(t))['ok'])

    def test_manifest_cannot_escape_root_or_ignore_extra_files(self):
        with tempfile.TemporaryDirectory() as t:
            root = Path(t)
            atom = root / 'atom'; atom.mkdir()
            (atom / 'safe.txt').write_text('safe')
            files = {'safe.txt': vendor._sha(atom / 'safe.txt')}
            manifest = atom / '.cfp_vendor.json'
            manifest.write_text(json.dumps({'files': files, 'tree_sha256': vendor._tree(files)}))
            self.assertTrue(vendor.verify_atom(atom)['ok'])
            (atom / 'extra.py').write_text('raise RuntimeError()')
            self.assertFalse(vendor.verify_atom(atom)['ok'])
            files = {'../outside.txt': 'a' * 64}
            manifest.write_text(json.dumps({'files': files, 'tree_sha256': vendor._tree(files)}))
            with patch.object(vendor, '_sha', side_effect=AssertionError('must not read outside')):
                self.assertFalse(vendor.verify_atom(atom)['ok'])

    def test_probe_rejects_traversal_and_unverified_code(self):
        with tempfile.TemporaryDirectory() as t:
            for name in ('../outside', '/absolute', 'C:\\outside', '..'):
                self.assertIn('error', execute({'task': 'probe', 'args': [name]}, Path(t)))
            (Path(t) / 'atom').mkdir()
            self.assertIn('error', execute({'task': 'probe', 'args': ['atom']}, Path(t)))

    def test_zero_discovered_tests_do_not_promote(self):
        with tempfile.TemporaryDirectory() as t:
            root = Path(t)
            (root / 'tests').mkdir()
            (root / 'tests' / 'test_empty.py').write_text('# no tests here\n')
            rec = gate.run_gate({'name': 'empty', 'package_dir': str(root)}, root / 'evidence')
            self.assertEqual(rec['status'], 'GATED_FAIL')

    def test_evidence_path_cannot_escape(self):
        with tempfile.TemporaryDirectory() as t, self.assertRaises(ValueError):
            gate.run_gate({'name': '../escape', 'package_dir': t}, Path(t))


class Writer:
    def __init__(self):
        self.data = bytearray()
        self.closed = False
    def write(self, data): self.data.extend(data)
    async def drain(self): pass
    def close(self): self.closed = True
    async def wait_closed(self): pass


def frame(data=b'', opcode=1, fin=True, mask=True):
    n = len(data)
    head = bytes([(128 if fin else 0) | opcode])
    flag = 128 if mask else 0
    head += bytes([flag | n]) if n < 126 else bytes([flag | 126]) + struct.pack('!H', n) if n < 65536 else bytes([flag | 127]) + struct.pack('!Q', n)
    return head + (b'\0' * 4 if mask else b'') + data


class WebSocketSecurity(unittest.IsolatedAsyncioTestCase):
    def socket(self, data, client=False):
        reader = asyncio.StreamReader(); reader.feed_data(data); reader.feed_eof()
        return WebSocket(reader, Writer(), mask=client)

    async def test_valid_fragmented_unicode_and_ping(self):
        data = frame(b'\xc3', fin=False) + frame(b'ping', opcode=9) + frame(b'\xa9', opcode=0)
        ws = self.socket(data)
        self.assertEqual(await ws.recv(), 'é')
        self.assertEqual(ws.w.data, b'\x8a\x04ping')

    async def test_protocol_violations_close_socket(self):
        cases = [frame(b'x', mask=False), frame(b'x', opcode=0), frame(b'x', opcode=2),
                 frame(b'x', opcode=9, fin=False), frame(b'x' * 126, opcode=9),
                 frame(b'\xff'), frame(b'x', opcode=8), b'\xc1\x80' + b'\0' * 4,
                 frame(b'a', fin=False) + frame(b'b')]
        for data in cases:
            with self.subTest(data=data[:8]):
                ws = self.socket(data)
                with self.assertRaises(Closed): await ws.recv()
                self.assertTrue(ws.w.closed)

    async def test_fragmented_message_limit_is_aggregate(self):
        ws = self.socket(frame(b'a' * MAX_FRAME, fin=False) + frame(b'b', opcode=0))
        with self.assertRaises(Closed): await ws.recv()

    async def test_client_masks_control_frames_and_closes_transport(self):
        ws = self.socket(frame(b'ping', opcode=9, mask=False) + frame(b'ok', mask=False), client=True)
        self.assertEqual(await ws.recv(), 'ok')
        self.assertTrue(ws.w.data[1] & 128)
        await ws.close()
        self.assertTrue(ws.w.closed)


class GatewaySecurity(unittest.IsolatedAsyncioTestCase):
    async def asyncSetUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.gw = Gateway(Path(self.tmp.name), Fabric(), port=0)
        self.server = await self.gw.serve()
        self.port = self.server.sockets[0].getsockname()[1]

    async def asyncTearDown(self):
        for ws in list(self.gw.conns.values()): await ws.close()
        self.server.close(); await self.server.wait_closed()
        self.tmp.cleanup()

    async def request(self, request):
        r, w = await asyncio.open_connection('127.0.0.1', self.port)
        w.write(request); await w.drain()
        response = await asyncio.wait_for(r.read(), 3)
        w.close(); await w.wait_closed()
        return response

    async def test_http_restricts_metadata_methods_and_bad_upgrades(self):
        for request, code in [(b'GET /api/atlas HTTP/1.1\r\n\r\n', b'403'),
                              (b'POST / HTTP/1.1\r\n\r\n', b'405'),
                              (b'GET /vws HTTP/1.1\r\nUpgrade: websocket\r\n\r\n', b'400')]:
            self.assertIn(code, (await self.request(request)).split(b'\r\n')[0])

    async def test_http_serves_packaged_ui(self):
        response = await self.request(b'GET / HTTP/1.1\r\n\r\n')
        self.assertIn(b'200 OK', response)
        self.assertIn(b'CFP Fabric Terminal', response)
        self.assertIn(b'frame-ancestors', response)

    async def test_cross_origin_upgrade_is_rejected(self):
        request = (b'GET /vws HTTP/1.1\r\nHost: localhost\r\nOrigin: https://attacker.invalid\r\n'
                   b'Upgrade: websocket\r\nConnection: Upgrade\r\nSec-WebSocket-Version: 13\r\n'
                   b'Sec-WebSocket-Key: dGhlIHNhbXBsZSBub25jZQ==\r\n\r\n')
        self.assertIn(b'400', await self.request(request))

    async def test_client_cannot_inject_replication_clocks(self):
        n, s = self.gw.fabric.join(self.gw.fabric.attestor.issue('phone', 'mobile'), {})
        with self.assertRaises(FabricError):
            await self.gw.dispatch(n.id, s, {'op': 'sync', 'ops': [{'node': 'other'}]}, None)

    async def test_empty_capability_grant_has_no_terminal(self):
        n, s = self.gw.fabric.join(self.gw.fabric.attestor.issue('phone', 'mobile', set()), {})
        with self.assertRaises(FabricError):
            await self.gw.terminal(n.id, s, 'nodes')

    async def test_malformed_commands_return_usage_without_disconnect(self):
        n, s = self.gw.fabric.join(self.gw.fabric.attestor.issue('phone', 'mobile'), {})
        ws = self.socket_stub = type('Socket', (), {'send': self.capture})()
        for line in ('get', 'job', 'set', 'events invalid', '"unterminated'):
            await self.gw.dispatch(n.id, s, {'op': 'term', 'line': line}, ws)
            self.assertIn('USAGE', self.captured['text'])

    async def capture(self, data): self.captured = json.loads(data)

    async def test_deny_policy_enforced_for_library_callers(self):
        gw = Gateway(Path(self.tmp.name), Fabric(), host='0.0.0.0', port=0)
        with self.assertRaises(FabricError): await gw.serve()
