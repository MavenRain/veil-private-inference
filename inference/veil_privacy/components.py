"""NVFlare components enforcing the veil federated round relation."""

import hashlib
import json
import secrets
import subprocess
from pathlib import Path
from threading import Lock

import numpy as np
import tenseal as ts
from nvflare.apis.dxo import DXO, DataKind, MetaKey, from_shareable
from nvflare.apis.dxo_filter import DXOFilter
from nvflare.apis.event_type import EventType
from nvflare.apis.executor import Executor
from nvflare.apis.filter import Filter
from nvflare.apis.fl_component import FLComponent
from nvflare.apis.fl_constant import FLContextKey
from nvflare.app_common.abstract.model import ModelLearnableKey, make_model_learnable
from nvflare.app_common.abstract.model_persistor import ModelPersistor
from nvflare.app_common.app_constant import AppConstants
from nvflare.app_common.filters.svt_privacy import SVTPrivacy
from nvflare.app_opt.he.constant import HE_ALGORITHM_CKKS
from nvflare.app_opt.he.model_decryptor import HEModelDecryptor
from nvflare.app_opt.he.model_encryptor import HEModelEncryptor
from nvflare.app_opt.he.model_shareable_generator import HEModelShareableGenerator
from veil_privacy.fhe import canonical, digest, read_bytes, require, write_private


def app_file(fl_ctx, name):
    require(name in ("keys/public.tenseal", "keys/secret.tenseal"), "context-path")
    return Path(fl_ctx.get_workspace().get_app_dir(fl_ctx.get_job_id())) / "custom" / name


def load_context(fl_ctx, name, expected_hash, secret=False, simulation=False):
    path = Path("/run/veil-keys/secret.tenseal") if secret and not simulation else app_file(fl_ctx, name)
    data = read_bytes(path)
    require(digest(data) == expected_hash, "context-integrity")
    context = ts.context_from(data, n_threads=1)
    require(context.has_secret_key() == secret, "context-key-role")
    return context


class QuietPrivacyLogs:
    # Upstream filters log private value ranges at INFO. Suppress their dynamic
    # messages while retaining our fixed protocol failures and public ledgers.
    def log_info(self, fl_ctx, msg, *args, **kwargs):
        pass

    def log_debug(self, fl_ctx, msg, *args, **kwargs):
        pass


class PinnedEncryptor(QuietPrivacyLogs, HEModelEncryptor):
    def __init__(self, context_sha256):
        super().__init__(weigh_by_local_iter=True, encrypt_layers=["w"])
        self.context_sha256 = context_sha256

    def handle_event(self, event_type, fl_ctx):
        if event_type == EventType.START_RUN:
            self.tenseal_context = load_context(fl_ctx, "keys/public.tenseal", self.context_sha256)
        elif event_type == EventType.END_RUN:
            self.tenseal_context = None


class PinnedDecryptor(QuietPrivacyLogs, HEModelDecryptor):
    def __init__(self, context_sha256, simulation=False):
        super().__init__()
        self.context_sha256 = context_sha256
        self.simulation = simulation

    def handle_event(self, event_type, fl_ctx):
        if event_type == EventType.START_RUN:
            self.tenseal_context = load_context(fl_ctx, "keys/secret.tenseal", self.context_sha256,
                                               secret=True, simulation=self.simulation)
        elif event_type == EventType.END_RUN:
            self.tenseal_context = None


class PinnedShareableGenerator(HEModelShareableGenerator):
    def __init__(self, context_sha256):
        super().__init__()
        self.context_sha256 = context_sha256

    def handle_event(self, event_type, fl_ctx):
        if event_type == EventType.START_RUN:
            self.tenseal_context = load_context(fl_ctx, "keys/public.tenseal", self.context_sha256)
        elif event_type == EventType.END_RUN:
            self.tenseal_context = None


class BoundedSVT(QuietPrivacyLogs, SVTPrivacy):
    def __init__(self):
        super().__init__(fraction=0.5, epsilon=0.5, epsilon_release=0.5,
                         gamma=0.01, tau=0.001, replace=False)

    def process_dxo(self, dxo, shareable, fl_ctx):
        require(dxo.data_kind == DataKind.WEIGHT_DIFF and set(dxo.data) == {"w"}, "dp-shape")
        values = np.asarray(dxo.data["w"], dtype=np.float64)
        require(values.shape == (4,) and np.isfinite(values).all()
                and dxo.get_meta_prop(MetaKey.NUM_STEPS_CURRENT_ROUND) == 1, "dp-input")
        # Whole-client replacement adjacency: two clipped updates differ by at
        # most 0.01 in L1. No unprotected scalar parameter is passed through.
        norm = float(np.linalg.norm(values, ord=1))
        dxo.data["w"] = values * min(1.0, 0.005 / max(norm, 1e-30))
        output = super().process_dxo(dxo, shareable, fl_ctx)
        output.set_meta_prop("veil.dp_cost", 1000)
        output.set_meta_prop("veil.dp_spent", round(self.get_privacy_spent() * 1000))
        return output


def weights_digest(weights):
    require(isinstance(weights, dict) and set(weights) == {"w"}, "weight-shape")
    value = weights["w"]
    if isinstance(value, bytes):
        require(0 < len(value) <= 1048576, "encrypted-size")
        return digest(b"veil/ckks-update/v2\0" + value)
    if isinstance(value, ts.CKKSVector):
        require(value.size() == 4 and not value.context().has_secret_key(), "encrypted-shape")
        return digest(b"veil/ckks-update/v2\0" + value.serialize())
    require(isinstance(value, (np.ndarray, list)), "weight-type")
    value = np.asarray(value, dtype=np.float64)
    require(value.shape == (4,) and np.isfinite(value).all(), "weight-shape")
    return digest(b"veil/initial-model/v2\0" + canonical(value.tolist()))


def round_code(**values):
    checker = Path(__file__).parent / "assets" / "protocol-check.mjs"
    result = subprocess.run(["node", str(checker)], input=canonical(values),
                            capture_output=True, timeout=20, check=False)
    require(result.returncode == 0 and len(result.stdout) <= 100, "veil-checker")
    return json.loads(result.stdout)["code"]


class RoundLedger(FLComponent):
    def __init__(self, clients, rounds=3, budget=3000, simulation=False):
        super().__init__()
        require(isinstance(clients, list) and len(clients) == len(set(clients)) == 2
                and rounds > 0 and budget == rounds * 1000, "federation-policy")
        self.clients = clients
        self.rounds = rounds
        self.budget = budget
        self.simulation = simulation
        self.lock = Lock()
        self.parents = {}
        self.seen = set()
        self.spent = {client: 0 for client in clients}
        self.run_nonce = secrets.token_hex(32)

    def parent(self, round_number, weights):
        parent = weights_digest(weights)
        with self.lock:
            require(round_number not in self.parents or self.parents[round_number] == parent, "round-parent")
            self.parents[round_number] = parent
        return parent

    def accept(self, receipt, weights, peer, expected_round, secure, fl_ctx=None):
        require(self.simulation or secure, "federation-requires-mtls")
        require(isinstance(receipt, dict) and set(receipt) == {"run", "round", "client", "parent", "update", "cost", "spent"}, "round-receipt")
        require(peer in self.clients and receipt["client"] == peer and receipt["run"] == self.run_nonce, "round-identity")
        require(isinstance(expected_round, int) and 0 <= expected_round < self.rounds, "round-limit")
        with self.lock:
            require((expected_round, peer) not in self.seen, "round-replay")
            encrypted = isinstance(weights.get("w"), ts.CKKSVector)
            bound = receipt["parent"] == self.parents.get(expected_round) and receipt["update"] == weights_digest(weights)
            dp = receipt["cost"] == 1000 and receipt["spent"] == self.spent[peer] + 1000
            code = round_code(round=receipt["round"], expected=expected_round, party=self.clients.index(peer) + 1,
                              parties=len(self.clients), spent=self.spent[peer], cost=receipt["cost"],
                              budget=self.budget, encrypted=int(encrypted), dp=int(dp), bound=int(bound))
            require(code == 0, f"veil-round-{code}")
            if fl_ctx is not None:
                directory = Path(fl_ctx.get_workspace().get_run_dir(fl_ctx.get_job_id())) / "receipts"
                directory.mkdir(mode=0o700, exist_ok=True)
                write_private(directory / f"round-{expected_round}-{peer}.json", canonical({**receipt,
                              "assurance": "simulation" if self.simulation else "nvflare-authenticated-peer"}))
            self.seen.add((expected_round, peer))
            self.spent[peer] += receipt["cost"]


class RoundTaskFilter(Filter):
    def process(self, shareable, fl_ctx):
        ledger = fl_ctx.get_engine().get_component("veil_ledger")
        round_number = shareable.get_header(AppConstants.CURRENT_ROUND)
        parent = ledger.parent(round_number, from_shareable(shareable).data)
        shareable.set_header("veil.round", {"run": ledger.run_nonce, "round": round_number, "parent": parent})
        return shareable


class RoundResultFilter(Filter):
    def process(self, shareable, fl_ctx):
        dxo = from_shareable(shareable)
        require(dxo.data_kind == DataKind.WEIGHT_DIFF and dxo.get_meta_prop(MetaKey.PROCESSED_ALGORITHM) == HE_ALGORITHM_CKKS, "round-encryption")
        peer = fl_ctx.get_peer_context().get_identity_name()
        ledger = fl_ctx.get_engine().get_component("veil_ledger")
        ledger.accept(dxo.get_meta_prop("veil.receipt"), dxo.data, peer,
                      fl_ctx.get_prop(AppConstants.CURRENT_ROUND),
                      fl_ctx.get_prop(FLContextKey.SECURE_MODE, False), fl_ctx)
        return shareable


class ClientReceiptFilter(DXOFilter):
    def __init__(self):
        super().__init__(supported_data_kinds=[DataKind.WEIGHT_DIFF], data_kinds_to_filter=[DataKind.WEIGHT_DIFF])

    def process_dxo(self, dxo, shareable, fl_ctx):
        require(isinstance(dxo.data.get("w"), ts.CKKSVector), "client-encryption")
        basis = dxo.get_meta_prop("veil.round")
        require(isinstance(basis, dict), "client-round")
        dxo.set_meta_prop("veil.receipt", {**basis, "client": fl_ctx.get_identity_name(),
                          "update": weights_digest(dxo.data), "cost": dxo.get_meta_prop("veil.dp_cost"),
                          "spent": dxo.get_meta_prop("veil.dp_spent")})
        return dxo


class TinyTrainer(Executor):
    """A four-parameter synthetic local update for the runnable release example."""

    def execute(self, task_name, shareable, fl_ctx, abort_signal):
        require(task_name == "train" and not abort_signal.triggered, "training-task")
        dxo = from_shareable(shareable)
        values = np.asarray(dxo.data["w"], dtype=np.float64)
        require(values.shape == (4,) and np.isfinite(values).all(), "training-model")
        site = fl_ctx.get_identity_name()
        require(site in ("site-1", "site-2"), "training-site")
        target = np.array([1, 2, 3, 4], dtype=np.float64) * (1 if site == "site-1" else 2)
        update = 0.1 * (target - values)
        return DXO(DataKind.WEIGHT_DIFF, {"w": update}, {
            MetaKey.NUM_STEPS_CURRENT_ROUND: 1, "veil.round": shareable.get_header("veil.round")}).to_shareable()


class CiphertextPersistor(ModelPersistor):
    def load_model(self, fl_ctx):
        return make_model_learnable({"w": np.zeros(4, dtype=np.float64)}, {})

    def save_model(self, model, fl_ctx):
        value = model[ModelLearnableKey.WEIGHTS]["w"]
        require(isinstance(value, ts.CKKSVector) and not value.context().has_secret_key(), "persist-encrypted-only")
        directory = Path(fl_ctx.get_workspace().get_run_dir(fl_ctx.get_job_id())) / "encrypted-models"
        directory.mkdir(mode=0o700, exist_ok=True)
        round_number = fl_ctx.get_prop(AppConstants.CURRENT_ROUND)
        path = directory / f"round-{round_number}.ckks"
        if not path.exists():
            write_private(path, value.serialize())
