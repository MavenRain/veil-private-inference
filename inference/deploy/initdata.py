"""Parse bounded, local init-data. Its digest covers the original TOML bytes."""
import json
import sys
import tomllib

raw = sys.stdin.buffer.read(2_000_001)
if len(raw) > 2_000_000:
    raise ValueError("init-data too large")
value = tomllib.loads(raw.decode("utf-8"))
if (set(value) != {"version", "algorithm", "data"}
        or value["version"] != "0.1.0"
        or value["algorithm"] not in {"sha256", "sha384"}
        or not isinstance(value["data"], dict)
        or not all(isinstance(k, str) and isinstance(v, str) for k, v in value["data"].items())):
    raise ValueError("unsupported init-data")
print(json.dumps(value, ensure_ascii=False))
