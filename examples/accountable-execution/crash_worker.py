"""Subprocess worker that performs ONE governed execution and hard-crashes
(os._exit) at a named injection point, to prove durability across a real process
death. Run isolated: `python3 -I crash_worker.py job.json`.

job.json: {ledger, world, authorizer_pub(hex), exec_priv(hex), action, grant_env,
crash_point}. The grant must already be registered in the ledger by the parent.
"""
import json
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import gexec
from cryptography.hazmat.primitives.asymmetric.ed25519 import (
    Ed25519PrivateKey,
    Ed25519PublicKey,
)


def main():
    job = json.load(open(sys.argv[1]))
    ledger = gexec.AuthorityLedger(job["ledger"])
    world = gexec.ExternalWorld(job["world"])
    apub = Ed25519PublicKey.from_public_bytes(bytes.fromhex(job["authorizer_pub"]))
    epriv = Ed25519PrivateKey.from_private_bytes(bytes.fromhex(job["exec_priv"]))
    ex = gexec.GovernedExecutor(ledger, world, apub, epriv)
    target = job["crash_point"]

    def hook(point):
        if point == target:
            # hard crash: durable SQLite state is already fsync'd; this process
            # dies without recording a receipt or any success signal.
            sys.stdout.flush()
            os._exit(42)

    out = ex.execute(job["action"], job["grant_env"], crash_hook=hook)
    # Only reached if the crash point was never hit.
    print(json.dumps({"status": out.status, "reason": out.reason}))


if __name__ == "__main__":
    main()
