#!/usr/bin/env python3
"""One-shot subprocess probe for restart/concurrent replay behavior."""
import hashlib
import json
import sys
from pathlib import Path

import state_store

root = Path(sys.argv[1]).resolve()
try:
    state_store.verify(root, root, enforce_acl=False)
    consumed = root / "consumed"; consumed.mkdir(exist_ok=True)
    token = hashlib.sha256(b"pgk-v6-probe:one-nonce").hexdigest()
    raw = json.dumps({"probe": "pgk-v8", "nonce": "one-nonce"}, sort_keys=True).encode() + b"\n"
    state_store.consume_atomic(consumed / (token + ".json"), raw)
    print("ALLOW_ONCE")
    raise SystemExit(0)
except state_store.StoreReplay:
    print("DENY_REPLAY")
    raise SystemExit(2)
except Exception:
    print("DENY_INVALID")
    raise SystemExit(3)
