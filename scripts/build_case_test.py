import importlib.util
import unittest
from pathlib import Path


MODULE_PATH = Path(__file__).with_name("build-case.py")
SPEC = importlib.util.spec_from_file_location("build_case", MODULE_PATH)
build_case = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(build_case)


class BuildCaseTests(unittest.TestCase):
    def test_settled_topic_matches_deployed_event(self):
        self.assertEqual(
            build_case.SETTLED_TOPIC,
            "0x0b287f37d8bd14ef37f2966734ab387c243cc1a1663616a25a4cc259877736b1",
        )

    def test_required_funding_uses_only_period_end_balance(self):
        self.assertEqual(build_case.required_funding(100, 10), 105)
        self.assertEqual(build_case.required_funding(100, 0), 96)

    def test_selection_satisfies_each_buyer_before_aggregate_top_up(self):
        buyers = ["0xaaa", "0xbbb"]
        settlements = {
            "0xaaa": [{"amount": 100}],
            "0xbbb": [{"amount": 100}],
        }
        fundings = {
            "0xaaa": [
                {"tx": "0xa1", "amount": 100},
                {"tx": "0xa2", "amount": 100},
            ],
            "0xbbb": [
                {"tx": "0xb1", "amount": 50},
                {"tx": "0xb2", "amount": 50},
            ],
        }

        selected = build_case.select_case_fundings(
            buyers,
            settlements,
            fundings,
            {buyer: 0 for buyer in buyers},
        )

        self.assertEqual({entry["tx"] for entry in selected}, {"0xa1", "0xb1", "0xb2"})

    def test_insufficient_buyer_funding_is_rejected(self):
        with self.assertRaisesRegex(ValueError, "needs 105 for ledger coverage"):
            build_case.select_case_fundings(
                ["0xaaa"],
                {"0xaaa": [{"amount": 100}]},
                {"0xaaa": [{"tx": "0xa1", "amount": 104}]},
                {"0xaaa": 10},
            )


    def test_cohort_excludes_the_funder(self):
        fundings = {"0xaaa": [], "0xbbb": []}
        settlements = {"0xaaa": [], "0xbbb": []}
        self.assertEqual(build_case.cohort(fundings, settlements, "0xAAA"), ["0xbbb"])

    def test_oversized_range_is_distinguished_from_rate_limiting(self):
        self.assertTrue(build_case._is_response_too_large(Exception("Log response size exceeded")))
        self.assertFalse(
            build_case._is_response_too_large(
                Exception("Your app has exceeded its compute units per second capacity")
            )
        )

    def test_selection_carries_the_funding_kind(self):
        buyers = ["0xaaa"]
        settlements = {"0xaaa": [{"amount": 100}]}
        fundings = {"0xaaa": [{"tx": "0x1", "amount": 100, "block": 1}]}
        selected = build_case.select_case_fundings(
            buyers, settlements, fundings, {"0xaaa": 0}, kind="deposit"
        )
        self.assertTrue(all(entry["kind"] == "deposit" for entry in selected))

if __name__ == "__main__":
    unittest.main()
