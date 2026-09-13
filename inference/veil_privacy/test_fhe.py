import unittest

import tenseal as ts

from veil_privacy.fhe import FIELDS, bits, decrypt_result, encrypt_receipt, evaluate, keygen, task_id


class ExactBfvTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.secret, cls.public = keygen()
        cls.receipt = {key: "ff" * 32 for key in FIELDS}
        cls.request = encrypt_receipt(cls.public, cls.receipt)

    def test_matching_tuple_and_public_context(self):
        self.assertFalse(ts.context_from(self.public, n_threads=1).has_secret_key())
        result = evaluate(self.public, self.request, self.receipt)
        self.assertTrue(decrypt_result(self.secret, self.public, result, task_id(self.request, self.receipt))["accepted"])

    def test_every_digest_and_maximum_distance(self):
        for key in FIELDS:
            changed = {**self.receipt, key: "fe" + "ff" * 31}
            result = evaluate(self.public, self.request, changed)
            opened = decrypt_result(self.secret, self.public, result, task_id(self.request, changed))
            self.assertFalse(opened["accepted"])
            self.assertEqual(opened["distance"], 1)
        opposite = {key: "00" * 32 for key in FIELDS}
        result = evaluate(self.public, self.request, opposite)
        self.assertEqual(decrypt_result(self.secret, self.public, result, task_id(self.request, opposite))["distance"], 1024)

    def test_task_and_context_substitution(self):
        result = evaluate(self.public, self.request, self.receipt)
        with self.assertRaises(ValueError):
            decrypt_result(self.secret, self.public, result, "wrong-task")
        with self.assertRaises(ValueError):
            evaluate(self.secret, self.request, self.receipt)
        with self.assertRaises(ValueError):
            encrypt_receipt(self.secret, self.receipt)

    def test_exact_digest_representation(self):
        self.assertEqual(len(bits(self.receipt)), 1024)
        for value in ("f" * 63, "FF" * 32, 123, "g" * 64):
            with self.assertRaises(ValueError):
                bits({**self.receipt, "model": value})


if __name__ == "__main__":
    unittest.main()
