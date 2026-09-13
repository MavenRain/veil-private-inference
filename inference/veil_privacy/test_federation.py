import unittest
import tempfile
from pathlib import Path

import numpy as np
import tenseal as ts
from nvflare.apis.dxo import DXO, DataKind, MetaKey
from nvflare.apis.fl_context import FLContext
from veil_privacy.components import BoundedSVT, RoundLedger, round_code, weights_digest
from veil_privacy.federation import keys, make_job


class FederatedPolicyTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        private = ts.context(ts.SCHEME_TYPE.CKKS, poly_modulus_degree=8192,
                             coeff_mod_bit_sizes=[60, 40, 40, 60], n_threads=1)
        private.global_scale = 2 ** 40
        cls.context = ts.context_from(private.serialize(save_secret_key=False), n_threads=1)

    def basis(self, simulation=True):
        ledger = RoundLedger(["site-1", "site-2"], simulation=simulation)
        parent = ledger.parent(0, {"w": np.zeros(4)})
        weights = {"w": ts.ckks_vector(self.context, [0.1, 0.2, 0.3, 0.4])}
        receipt = {"run": ledger.run_nonce, "round": 0, "client": "site-1", "parent": parent,
                   "update": weights_digest(weights), "cost": 1000, "spent": 1000}
        return ledger, weights, receipt

    def test_accept_replay_and_insecure_peer(self):
        ledger, weights, receipt = self.basis()
        ledger.accept(receipt, weights, "site-1", 0, False)
        with self.assertRaisesRegex(ValueError, "round-replay"):
            ledger.accept(receipt, weights, "site-1", 0, False)
        ledger, weights, receipt = self.basis(simulation=False)
        with self.assertRaisesRegex(ValueError, "requires-mtls"):
            ledger.accept(receipt, weights, "site-1", 0, False)
        ledger.accept(receipt, weights, "site-1", 0, True)

    def test_binding_identity_budget_and_cleartext_downgrade(self):
        for key, value in (("run", "other"), ("client", "unknown"), ("round", 1),
                           ("parent", "other"), ("update", "other"), ("cost", 0), ("spent", 0)):
            ledger, weights, receipt = self.basis()
            with self.assertRaises(ValueError, msg=key):
                ledger.accept({**receipt, key: value}, weights, "site-1", 0, False)
        ledger, _, receipt = self.basis()
        weights = {"w": np.ones(4)}
        receipt["update"] = weights_digest(weights)
        with self.assertRaisesRegex(ValueError, "veil-round-4"):
            ledger.accept(receipt, weights, "site-1", 0, False)
        self.assertEqual(round_code(round=2, expected=2, party=1, parties=2, spent=3000,
                                    cost=1000, budget=3000, encrypted=1, dp=1, bound=1), 3)

    def test_serialized_ciphertext_parent_is_stable(self):
        _, weights, _ = self.basis()
        self.assertEqual(weights_digest(weights), weights_digest({"w": weights["w"].serialize()}))
        self.assertFalse(weights["w"].context().has_secret_key())

    def test_production_job_never_transports_client_secret_keys(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            keys(root / "keys")
            make_job(root / "keys", simulation=False).export_job(str(root / "jobs"))
            self.assertEqual(list((root / "jobs").rglob("secret.tenseal")), [])
            self.assertEqual(len(list((root / "jobs").rglob("public.tenseal"))), 3)

    def test_real_svt_accountant_composes_and_rejects_unbounded_shapes(self):
        privacy = BoundedSVT()
        for round_number in range(3):
            dxo = DXO(DataKind.WEIGHT_DIFF, {"w": np.array([10.0, 20.0, 30.0, 40.0])},
                      {MetaKey.NUM_STEPS_CURRENT_ROUND: 1})
            filtered = privacy.process_dxo(dxo, dxo.to_shareable(), FLContext())
            self.assertEqual(filtered.get_meta_prop("veil.dp_cost"), 1000)
            self.assertEqual(filtered.get_meta_prop("veil.dp_spent"), (round_number + 1) * 1000)
            self.assertTrue(np.isfinite(filtered.data["w"]).all())
        self.assertAlmostEqual(privacy.get_privacy_spent(), 3.0)
        for values in (np.array(1.0), np.ones(5), np.array([1.0, 2.0, 3.0, np.nan])):
            dxo = DXO(DataKind.WEIGHT_DIFF, {"w": values}, {MetaKey.NUM_STEPS_CURRENT_ROUND: 1})
            with self.assertRaisesRegex(ValueError, "dp-input"):
                privacy.process_dxo(dxo, dxo.to_shareable(), FLContext())


if __name__ == "__main__":
    unittest.main()
