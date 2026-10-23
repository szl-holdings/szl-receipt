"""Run the publication workflow's actual secret scan on bounded SAMPLE files."""
import os
import shutil
import subprocess
from pathlib import Path

import pytest


ROOT = Path(__file__).resolve().parents[1]
WORKFLOW = ROOT / ".github" / "workflows" / "model-publish-gate.yml"


@pytest.fixture(scope="module")
def shell():
    if os.name == "nt":
        git = shutil.which("git")
        if git:
            base = Path(git).resolve().parents[1]
            for candidate in (base / "bin" / "bash.exe", base / "usr" / "bin" / "bash.exe"):
                if candidate.is_file():
                    return str(candidate)
        pytest.skip("Git Bash is required for the Windows shell regression")
    bash = shutil.which("bash")
    if not bash:
        pytest.skip("Bash is required for the workflow shell regression")
    return bash


@pytest.fixture(scope="module")
def scan_command():
    lines = WORKFLOW.read_text(encoding="utf-8").splitlines()
    marker = "      - name: Secret pattern scan (stdlib)"
    start = lines.index(marker)
    assert lines[start + 1] == "        run: |"
    body = []
    for line in lines[start + 2:]:
        if line.startswith("          "):
            body.append(line[10:])
        elif line.strip():
            break
    assert body
    return "\n".join(body) + "\n"


def run_scan(shell, command, folder):
    return subprocess.run(
        [shell, "--noprofile", "--norc", "-e", "-o", "pipefail", "-c", command],
        cwd=folder, capture_output=True, timeout=20,
    )


def test_clean_source_and_scanner_source_pass(shell, scan_command, tmp_path):
    (tmp_path / "safe.txt").write_text("Ordinary SAMPLE fixture.\n", encoding="utf-8")
    (tmp_path / "workflow.yml").write_bytes(WORKFLOW.read_bytes())
    (tmp_path / "regression.py").write_bytes(Path(__file__).read_bytes())
    result = run_scan(shell, scan_command, tmp_path)
    assert result.returncode == 0
    assert result.stdout == b""


@pytest.mark.parametrize("sample", [
    "AI" + "za" + "A" * 35,
    "gh" + "p_" + "B" * 36,
    "s" + "k-" + "C" * 20,
    "-----BEGIN " + "PRIVATE KEY-----",
], ids=["google-key-shape", "github-token-shape", "api-token-shape", "pem-header"])
def test_all_existing_secret_families_block_without_echo(shell, scan_command, tmp_path, sample):
    nested = tmp_path / "source"
    nested.mkdir()
    (nested / "sample.txt").write_text(sample, encoding="utf-8")
    result = run_scan(shell, scan_command, tmp_path)
    assert result.returncode != 0
    assert sample.encode() not in result.stdout + result.stderr


def test_scan_input_error_blocks(shell, scan_command, tmp_path):
    # A real grep input error, without relying on POSIX permission bits on Windows.
    command = scan_command.replace('"$pattern" .', '"$pattern" missing-selected-input')
    assert command != scan_command
    result = run_scan(shell, command, tmp_path)
    assert result.returncode != 0
    assert b"Secret scan failed" in result.stdout


def test_existing_git_metadata_exclusion_is_preserved(shell, scan_command, tmp_path):
    metadata = tmp_path / ".git"
    metadata.mkdir()
    (metadata / "sample.txt").write_text("gh" + "p_" + "D" * 36, encoding="utf-8")
    assert run_scan(shell, scan_command, tmp_path).returncode == 0
