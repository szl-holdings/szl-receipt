"""Release gate byte conformance and controls; standard library only."""
import importlib.util
import json
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest
from unittest import mock

ROOT = Path(__file__).resolve().parents[1]

def load_source(name, path):
    spec = importlib.util.spec_from_file_location(name, path)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module

gate = load_source("szl_release_pae_gate_tests", ROOT / "conformance/run_vectors.py")
production = load_source("szl_canonical_pae_tests", ROOT / "src/szl_receipt/_canonical.py")
VECTORS = json.loads((ROOT / "conformance/pae_byte_vectors.json").read_text(encoding="utf-8"))["vectors"]

def old_context_length_encoding(context, payload_type, payload):
    """Preserve the pre-repair divergence as a negative control only."""
    return b" ".join(
        value for field in (context.encode(), payload_type.encode(), payload)
        for value in (str(len(field)).encode("ascii"), field)
    )

class ReleasePAEConformanceTests(unittest.TestCase):
    def test_fixed_vectors_match_both_production_and_release(self):
        for vector in VECTORS:
            with self.subTest(vector=vector["id"]):
                payload = bytes.fromhex(vector["payload_hex"])
                expected = bytes.fromhex(vector["expected_pae_hex"])
                self.assertEqual(production.pae(vector["payload_type"], payload), expected)
                self.assertEqual(gate.pae("DSSEv1", vector["payload_type"], payload), expected)

    def test_arbitrary_context_is_refused(self):
        with self.assertRaises(ValueError):
            gate.pae("DSSEv2", "application/x-test", b"body")

    def test_old_context_length_encoding_fails_fixed_vector(self):
        vector = VECTORS[0]
        self.assertNotEqual(
            old_context_length_encoding("DSSEv1", vector["payload_type"], bytes.fromhex(vector["payload_hex"])),
            bytes.fromhex(vector["expected_pae_hex"]),
        )

    def test_v02_refuses_old_context_length_encoder(self):
        with mock.patch.object(gate, "pae", old_context_length_encoding):
            ok, _ = gate.v02_pae_byte_length({"sample": True}, b'{"sample":true}')
        self.assertFalse(ok, "A self-consistent nonstandard encoder cannot qualify the release gate")

    def test_v02_refuses_binary_length_encoder(self):
        def binary_prefix(context, payload_type, payload):
            return b"DSSEv1 " + len(payload_type.encode()).to_bytes(8, "little") + b" " + payload_type.encode() + b" " + len(payload).to_bytes(8, "little") + b" " + payload
        with mock.patch.object(gate, "pae", binary_prefix):
            ok, _ = gate.v02_pae_byte_length({"sample": True}, b'{"sample":true}')
        self.assertFalse(ok)

    def test_v02_refuses_trailing_and_wrong_payload_bytes(self):
        original = gate.pae
        for suffix in (b" ", b"tamper"):
            with self.subTest(suffix=suffix), mock.patch.object(gate, "pae", lambda *args: original(*args) + suffix):
                ok, _ = gate.v02_pae_byte_length({"sample": True}, b'{"sample":true}')
                self.assertFalse(ok)

    def test_v02_accepts_production_bytes_for_unicode_manifest(self):
        ok, detail = gate.v02_pae_byte_length({"sample": "π"}, b'{"sample":"\\u03c0"}')
        self.assertTrue(ok, detail)

    def test_manifest_only_controls_reach_the_parser(self):
        original = gate.pae
        payload_type = gate.PAYLOAD_TYPE.encode()
        length = str(len(payload_type)).encode()
        mutations = {
            "trailing": lambda value: value + b" ",
            "payload": lambda value: value[:-1] + b"x",
            "type": lambda value: value.replace(payload_type, payload_type[:-1] + b"x", 1),
            "separator": lambda value: value.replace(payload_type + b" ", payload_type + b"X", 1),
            "overrun": lambda value: value.replace(b"DSSEv1 " + length, b"DSSEv1 999999", 1),
            "padding": lambda value: value.replace(b"DSSEv1 " + length, b"DSSEv1 0" + length, 1),
        }
        for name, mutate in mutations.items():
            def manifest_only(context, kind, body):
                value = original(context, kind, body)
                return value if kind == "http://example.com/HelloWorld" else mutate(value)
            with self.subTest(control=name), mock.patch.object(gate, "pae", manifest_only):
                ok, _ = gate.v02_pae_byte_length({"sample": True}, b'{"sample":true}')
                self.assertFalse(ok)

    def test_cli_runs_with_site_packages_disabled(self):
        with tempfile.TemporaryDirectory() as directory:
            receipt = Path(directory) / "sample-manifest.json"
            receipt.write_text(json.dumps({
                "sample": True, "chain": {"prev_hash": "genesis"},
                "issued_at": "2026-10-07T00:00:00Z", "signatures": {"manifest": False},
            }), encoding="utf-8")
            completed = subprocess.run(
                [sys.executable, "-S", "-X", "utf8", str(ROOT / "conformance/run_vectors.py"),
                 "--vectors", str(ROOT / "conformance/vectors"), "--receipt", str(receipt), "--require-all-pass"],
                capture_output=True, text=True, timeout=20, check=False,
            )
        self.assertEqual(completed.returncode, 0, completed.stdout + completed.stderr)
        self.assertIn("5 vectors, 0 gate failure(s)", completed.stdout)

if __name__ == "__main__":
    unittest.main()
