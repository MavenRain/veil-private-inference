"""Build and run a two-client NVFlare job with DP, CKKS and veil receipts."""

import argparse
import codecs
import json
import multiprocessing
import os
import sys
from pathlib import Path

import numpy as np
import tenseal as ts
from nvflare.apis.dxo import DataKind
from nvflare.app_common.workflows.scatter_and_gather import ScatterAndGather
from nvflare.app_opt.he.intime_accumulate_model_aggregator import HEInTimeAccumulateWeightedAggregator
from nvflare.job_config.api import FedJob
from nvflare.job_config.defs import FilterType
from nvflare.private.fed.app.simulator.simulator_runner import SimulatorRunner
from veil_privacy.components import BoundedSVT, CiphertextPersistor, ClientReceiptFilter, PinnedDecryptor, PinnedEncryptor
from veil_privacy.components import PinnedShareableGenerator, RoundLedger, RoundResultFilter, RoundTaskFilter, TinyTrainer
from veil_privacy.fhe import canonical, digest, read_bytes, read_json, require, write_private


def keys(directory):
    directory.mkdir(mode=0o700)
    context = ts.context(ts.SCHEME_TYPE.CKKS, poly_modulus_degree=8192,
                         coeff_mod_bit_sizes=[60, 40, 40, 60], n_threads=1)
    context.global_scale = 2 ** 40
    secret = context.serialize(save_secret_key=True)
    public = context.serialize(save_secret_key=False)
    write_private(directory / "secret.tenseal", secret)
    write_private(directory / "public.tenseal", public)


def make_job(key_dir, simulation=False, rounds=3):
    public = read_bytes(key_dir / "public.tenseal")
    secret = read_bytes(key_dir / "secret.tenseal")
    require(not ts.context_from(public, n_threads=1).has_secret_key(), "server-secret")
    clients = ["site-1", "site-2"]
    job = FedJob(name="veil-private-rounds", min_clients=2)
    job.to_server(RoundLedger(clients, rounds, rounds * 1000, simulation), id="veil_ledger")
    job.to_server(HEInTimeAccumulateWeightedAggregator(expected_data_kind=DataKind.WEIGHT_DIFF), id="aggregator")
    job.to_server(PinnedShareableGenerator(digest(public)), id="shareable_generator")
    job.to_server(CiphertextPersistor(), id="persistor")
    job.to_server(ScatterAndGather(min_clients=2, num_rounds=rounds, wait_time_after_min_received=0,
                                  aggregator_id="aggregator", persistor_id="persistor",
                                  shareable_generator_id="shareable_generator", train_timeout=90,
                                  snapshot_every_n_rounds=0))
    job.to_server(RoundTaskFilter(), filter_type=FilterType.TASK_DATA, tasks=["train"])
    job.to_server(RoundResultFilter(), filter_type=FilterType.TASK_RESULT, tasks=["train"])
    job.add_file_to_server(str(key_dir / "public.tenseal"), dest_dir="keys", app_folder_type="custom")
    for name in ("protocol-check.mjs", "privacy.wasm"):
        job.add_file_to_server(str(Path(__file__).parent / "assets" / name),
                               dest_dir="veil_privacy/assets", app_folder_type="custom")
    for client in clients:
        job.to(TinyTrainer(), client, tasks=["train"])
        job.to(PinnedDecryptor(digest(secret), simulation=simulation), client,
               filter_type=FilterType.TASK_DATA, tasks=["train"])
        job.to(BoundedSVT(), client, filter_type=FilterType.TASK_RESULT, tasks=["train"])
        job.to(PinnedEncryptor(digest(public)), client, filter_type=FilterType.TASK_RESULT, tasks=["train"])
        job.to(ClientReceiptFilter(), client, filter_type=FilterType.TASK_RESULT, tasks=["train"])
        # The whole submitted job passes through the server. Production keys
        # must arrive privately at each client, outside the job archive.
        for name in (("secret.tenseal", "public.tenseal") if simulation else ("public.tenseal",)):
            job.add_file_to(str(key_dir / name), client, dest_dir="keys", app_folder_type="custom")
    return job


def validate_run(workspace, key_dir, rounds):
    receipts = list(workspace.rglob("round-*-site-*.json"))
    models = sorted(workspace.rglob("round-*.ckks"), key=lambda p: int(p.stem.split("-")[1]))
    require(len(receipts) == rounds * 2 and len(models) == rounds, "incomplete-federation")
    groups = {}
    for file in receipts:
        receipt = read_json(file)
        require(receipt["assurance"] == "simulation" and receipt["cost"] == 1000, "federation-receipt")
        groups.setdefault(receipt["client"], []).append(receipt)
    for group in groups.values():
        ordered = sorted(group, key=lambda r: r["round"])
        require([r["round"] for r in ordered] == list(range(rounds))
                and [r["spent"] for r in ordered] == [(i + 1) * 1000 for i in range(rounds)], "federation-budget")
    context = ts.context_from(read_bytes(key_dir / "secret.tenseal"), n_threads=1)
    final = ts.ckks_vector_from(context, read_bytes(models[-1])).decrypt()
    require(len(final) == 4 and np.isfinite(final).all(), "federation-model")
    report = {"accepted": True, "assurance": "simulation", "clients": 2, "rounds": rounds,
              "receipts": len(receipts), "encrypted_checkpoints": len(models),
              "epsilon_per_client": rounds, "server_has_secret_key": False}
    write_private(workspace / "validation.json", canonical(report))
    return report


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("command", choices=["keygen", "export", "simulate"])
    parser.add_argument("directory", type=Path)
    parser.add_argument("--keys", type=Path)
    parser.add_argument("--rounds", type=int, default=3)
    args = parser.parse_args()
    require(1 <= args.rounds <= 20, "round-count")
    os.umask(0o077)
    if args.command == "keygen":
        keys(args.directory.resolve())
        return
    key_dir = args.keys.resolve() if args.keys else args.directory.resolve() / "keys"
    require(not args.directory.exists(), "output-exists")
    args.directory.mkdir(mode=0o700, parents=True)
    if args.keys is None:
        require(args.command == "simulate", "export-requires-keys")
        keys(key_dir)
    job = make_job(key_dir, simulation=args.command == "simulate", rounds=args.rounds)
    job.export_job(str(args.directory / "jobs"))
    if args.command == "simulate":
        workspace = args.directory.resolve() / "workspace"
        # Resolve the ZIP filename codec before NVFlare starts its logging and
        # worker threads. CPython 3.13.2 can fail a concurrent first lookup here.
        codecs.lookup("cp437")
        if sys.platform == "darwin":
            multiprocessing.set_start_method("spawn", force=True)
        simulator = SimulatorRunner(job_folder=str(args.directory.resolve() / "jobs" / "veil-private-rounds"),
                                    workspace=str(workspace), clients="site-1,site-2", threads=2,
                                    log_config="concise")
        require(simulator.run() == 0, "simulator-failed")
        print(canonical(validate_run(workspace, key_dir, args.rounds)).decode())
    else:
        print(json.dumps({"exported": True, "requires_mtls": True, "contains_private_client_keys": True}))


if __name__ == "__main__":
    main()
