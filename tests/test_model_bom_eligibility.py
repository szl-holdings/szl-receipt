"""Publication eligibility in the signed model BOM requires literal booleans."""

import json
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest


ROOT = Path(__file__).resolve().parents[1]
SCRIPT = ROOT / "scripts" / "build_model_bom.py"


def _eligibility(heldout, refusal):
    with tempfile.TemporaryDirectory(prefix="szl-model-bom-") as directory:
        root = Path(directory)
        model = root / "model"
        model.mkdir()
        (model / "weights.safetensors").write_bytes(b"synthetic")
        evidence = root / "eval.json"
        evidence.write_text(
            json.dumps(
                {
                    "pass_rate": 1,
                    "heldout_passed": heldout,
                    "refusal_no_regression": refusal,
                }
            ),
            encoding="utf-8",
        )
        output = root / "model-bom.cdx.json"
        result = subprocess.run(
            [
                sys.executable,
                str(SCRIPT),
                "--model-dir",
                str(model),
                "--eval",
                str(evidence),
                "--out",
                str(output),
            ],
            capture_output=True,
            text=True,
            timeout=10,
        )
        if result.returncode != 0:
            raise AssertionError(result.stderr)
        bom = json.loads(output.read_text(encoding="utf-8"))
        properties = {
            item["name"]: item["value"]
            for item in bom["metadata"]["component"]["properties"]
        }
        return properties["szl:publication_eligible"]


class ModelBomEligibilityTests(unittest.TestCase):
    def test_only_literal_true_verdicts_are_eligible(self):
        self.assertEqual(_eligibility(True, True), "true")
        false_like = [False, "false", "true", "", 0, 1, None, [], [True], {}, {"pass": True}]
        for value in false_like:
            with self.subTest(field="heldout_passed", value=value):
                self.assertEqual(_eligibility(value, True), "false")
            with self.subTest(field="refusal_no_regression", value=value):
                self.assertEqual(_eligibility(True, value), "false")


if __name__ == "__main__":
    unittest.main()
