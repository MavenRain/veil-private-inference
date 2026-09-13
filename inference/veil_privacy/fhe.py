"""A depth-one BFV circuit over exact 256-bit receipt digests.

This backend provides ciphertext privacy, not evaluator integrity. A relying
party must authenticate the evaluator separately when it needs that guarantee.
"""

import argparse
import base64
import hashlib
import json
import os
import re
from pathlib import Path

import tenseal as ts

FIELDS = ("model", "prompt_commit", "output_commit", "gpu_measurement")
MODULUS = 1032193
MAX_BYTES = 64 * 1024 * 1024


def canonical(value):
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=True).encode()


def digest(value):
    return hashlib.sha256(value).hexdigest()


def require(condition, code):
    if not condition:
        raise ValueError(code)


def read_bytes(path):
    fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
    try:
        import stat

        require(stat.S_ISREG(os.fstat(fd).st_mode), "input-not-file")
        with os.fdopen(fd, "rb", closefd=False) as stream:
            data = stream.read(MAX_BYTES + 1)
        require(len(data) <= MAX_BYTES, "input-size")
        return data
    finally:
        os.close(fd)


def write_private(path, data):
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    with os.fdopen(fd, "wb") as stream:
        stream.write(data)
        stream.flush()
        os.fsync(stream.fileno())


def read_json(path):
    def pairs(items):
        result = {}
        for key, value in items:
            require(key not in result, "json-duplicate-key")
            result[key] = value
        return result

    return json.loads(read_bytes(path), object_pairs_hook=pairs)


def bits(receipt):
    require(isinstance(receipt, dict) and set(receipt) == set(FIELDS), "receipt-fields")
    result = []
    for field in FIELDS:
        value = receipt[field]
        require(isinstance(value, str) and re.fullmatch(r"[0-9a-f]{64}", value), "digest-encoding")
        for byte in bytes.fromhex(value):
            result.extend((byte >> shift) & 1 for shift in range(7, -1, -1))
    return result


def decode(text):
    require(isinstance(text, str) and len(text) <= MAX_BYTES, "ciphertext-size")
    data = base64.b64decode(text, validate=True)
    require(base64.b64encode(data).decode() == text, "base64-encoding")
    return data


def keygen():
    context = ts.context(ts.SCHEME_TYPE.BFV, poly_modulus_degree=4096,
                         plain_modulus=MODULUS, n_threads=1)
    context.generate_galois_keys()
    secret = context.serialize(save_secret_key=True)
    public = context.serialize(save_secret_key=False)
    require(not ts.context_from(public, n_threads=1).has_secret_key(), "public-context-secret")
    return secret, public


def encrypt_receipt(public_bytes, receipt):
    context = ts.context_from(public_bytes, n_threads=1)
    require(not context.has_secret_key(), "public-context-secret")
    vector = ts.bfv_vector(context, bits(receipt))
    return {"version": "veil.bfv-request.v2", "context_sha256": digest(public_bytes),
            "ciphertext": base64.b64encode(vector.serialize()).decode()}


def task_id(request, expected):
    bits(expected)
    return digest(b"veil/bfv-task/v2\0" + canonical({"request": request, "expected": expected}))


def evaluate(public_bytes, request, expected):
    require(isinstance(request, dict) and set(request) == {"version", "context_sha256", "ciphertext"}
            and request["version"] == "veil.bfv-request.v2"
            and request["context_sha256"] == digest(public_bytes), "request-context")
    context = ts.context_from(public_bytes, n_threads=1)
    require(not context.has_secret_key(), "public-context-secret")
    encrypted = ts.bfv_vector_from(context, decode(request["ciphertext"]))
    require(encrypted.size() == 1024, "ciphertext-shape")
    difference = encrypted - bits(expected)
    # Bit encoding bounds the honest result to [0, 1024], strictly below the
    # plaintext modulus. No modular alias can turn a valid mismatch into zero.
    distance = (difference * difference).sum()
    return {"version": "veil.bfv-result.v2", "context_sha256": digest(public_bytes),
            "task_id": task_id(request, expected),
            "ciphertext": base64.b64encode(distance.serialize()).decode()}


def decrypt_result(secret_bytes, public_bytes, result, expected_task):
    require(isinstance(result, dict) and set(result) == {"version", "context_sha256", "task_id", "ciphertext"}
            and result["version"] == "veil.bfv-result.v2"
            and result["context_sha256"] == digest(public_bytes)
            and result["task_id"] == expected_task, "result-task")
    context = ts.context_from(secret_bytes, n_threads=1)
    require(context.has_secret_key(), "missing-secret-key")
    distance = ts.bfv_vector_from(context, decode(result["ciphertext"])).decrypt()
    require(len(distance) == 1 and isinstance(distance[0], int) and 0 <= distance[0] <= 1024, "result-range")
    return {"accepted": distance[0] == 0, "distance": distance[0],
            "assurance": "encrypted-evaluation-only", "task_id": expected_task}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    sub = parser.add_subparsers(dest="command", required=True)
    generate = sub.add_parser("keygen")
    generate.add_argument("directory")
    enc = sub.add_parser("encrypt")
    for name in ("public_context", "receipt", "output"):
        enc.add_argument(name)
    ev = sub.add_parser("evaluate")
    for name in ("public_context", "request", "expected", "output"):
        ev.add_argument(name)
    dec = sub.add_parser("decrypt")
    for name in ("secret_context", "public_context", "request", "expected", "result"):
        dec.add_argument(name)
    args = parser.parse_args()
    if args.command == "keygen":
        path = Path(args.directory)
        path.mkdir(mode=0o700)
        secret, public = keygen()
        write_private(path / "secret.tenseal", secret)
        write_private(path / "public.tenseal", public)
        print(canonical({"context_sha256": digest(public)}).decode())
    elif args.command == "encrypt":
        write_private(args.output, canonical(encrypt_receipt(read_bytes(args.public_context), read_json(args.receipt))))
    elif args.command == "evaluate":
        write_private(args.output, canonical(evaluate(read_bytes(args.public_context), read_json(args.request), read_json(args.expected))))
    else:
        expected_task = task_id(read_json(args.request), read_json(args.expected))
        result = decrypt_result(read_bytes(args.secret_context), read_bytes(args.public_context), read_json(args.result), expected_task)
        print(canonical(result).decode())
        if not result["accepted"]:
            raise SystemExit(1)


if __name__ == "__main__":
    main()
