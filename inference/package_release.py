"""Package recorded validation, preserving any explicit candidate qualification."""
import argparse
import gzip
import hashlib
import io
import json
import os
import subprocess
import tarfile
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
VERSION = "0.2.0"
EXCLUDED = {"node_modules", ".venv", "artifacts", "dist", "__pycache__"}


def digest(data):
    return hashlib.sha256(data).hexdigest()


def public_source(path):
    return not any(p.startswith(".") or p in EXCLUDED for p in path.parts)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--allow-performance-failures", action="store_true",
                        help="create a candidate only when the sole failed checks are parent timing bounds")
    args = parser.parse_args()
    report = json.loads((ROOT / "inference/artifacts/software-validation.json").read_bytes())
    if report["version"] != "veil.software-validation.v2" or report["release"] != VERSION:
        raise ValueError("run the complete release gate first")
    candidate = report.get("status") == "performance-unvalidated"
    if report.get("status") != "software-validated" and not (candidate and args.allow_performance_failures):
        raise ValueError("release gate failed; only timing failures can be packaged as an explicit candidate")
    label = VERSION + ("-candidate" if candidate else "")
    for name, expected in report["source_sha256"].items():
        if digest((ROOT / name).read_bytes()) != expected:
            raise ValueError(f"source changed since validation: {name}")
    tracked = subprocess.run(["git", "ls-files", "--recurse-submodules", "-z"], cwd=ROOT, check=True, capture_output=True).stdout
    names = {p for p in tracked.decode().split("\0") if p and not p.startswith("inference/")}
    names.discard(".gitmodules")  # The archive contains the pinned vendor tree without local checkout URLs.
    for directory, dirs, files in os.walk(ROOT / "inference", followlinks=False):
        dirs[:] = [d for d in dirs if not d.startswith(".") and d not in EXCLUDED]
        for name in files:
            path = (Path(directory) / name).relative_to(ROOT)
            if public_source(path) and not name.endswith(".pyc"):
                names.add(path.as_posix())
    names.add("inference/.gitignore")
    names.add("dev/private-inference-release.sh")
    names.add("inference/artifacts/receipt.wasm")
    names.add("inference/artifacts/parent-gates.log")
    names.add("inference/veil_privacy/assets/privacy.wasm")
    zk_root = ROOT / "inference/artifacts/zk"
    zk = json.loads((zk_root / "manifest.json").read_bytes())
    if zk["circuit_sha256"] != digest((ROOT / "inference/zk/receipt.circom").read_bytes()):
        raise ValueError("circuit changed since ZK setup")
    for name, expected in zk["artifacts"].items():
        if Path(name).is_absolute() or ".." in Path(name).parts or digest((zk_root / name).read_bytes()) != expected:
            raise ValueError("ZK artifact integrity")
        names.add("inference/artifacts/zk/" + name)
    names.add("inference/artifacts/zk/manifest.json")
    data = {}
    for name in sorted(names):
        source = ROOT / name
        if source.is_symlink() or not source.is_file():
            raise ValueError(f"non-regular release source: {name}")
        if any(part in {"node_modules", ".venv", "dist", ".git"} for part in source.relative_to(ROOT).parts):
            raise ValueError("private build data in archive")
        data[name] = source.read_bytes()
    data["inference/validation.json"] = json.dumps(report, sort_keys=True, separators=(",", ":")).encode() + b"\n"
    inventory = {name: {"sha256": digest(value), "bytes": len(value)} for name, value in sorted(data.items())}
    manifest = {"version": "veil.release-manifest.v2", "release": VERSION,
                "status": report["status"], "candidate": candidate,
                "base_commit": report["base_commit"], "hardware_validated": False,
                "container_images_built": False, "files": inventory}
    data["RELEASE-MANIFEST.json"] = json.dumps(manifest, sort_keys=True, separators=(",", ":")).encode() + b"\n"
    destination = ROOT / "inference/dist"
    destination.mkdir(mode=0o700, exist_ok=True)
    archive = destination / f"veil-private-inference-{label}.tar.gz"
    temporary = archive.with_suffix(".tmp")
    with temporary.open("wb") as output:
        with gzip.GzipFile(fileobj=output, mode="wb", filename="", mtime=0) as compressed:
            with tarfile.open(fileobj=compressed, mode="w|", format=tarfile.PAX_FORMAT) as tar:
                for name, value in sorted(data.items()):
                    member = tarfile.TarInfo(f"veil-private-inference-{label}/{name}")
                    member.size = len(value)
                    member.mode = 0o755 if name.endswith(".sh") else 0o644
                    member.uid = member.gid = member.mtime = 0
                    tar.addfile(member, io.BytesIO(value))
        output.flush()
        os.fsync(output.fileno())
    temporary.replace(archive)
    checksum = digest(archive.read_bytes())
    (destination / "SHA256SUMS").write_text(f"{checksum}  {archive.name}\n")
    (destination / "release-manifest.json").write_bytes(data["RELEASE-MANIFEST.json"])
    print(json.dumps({"archive": str(archive), "sha256": checksum, "files": len(data),
                      "bytes": archive.stat().st_size, "status": report["status"], "hardware_validated": False}))


if __name__ == "__main__":
    main()
