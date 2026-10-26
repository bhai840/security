import unittest
from unittest.mock import patch

from galileo_eval import (
    load_cases,
    run_model_experiment_in_galileo,
    score_classifications,
)


class GalileoEvaluationTests(unittest.TestCase):
    def test_fixture_has_labeled_cases_for_each_classification(self):
        from pathlib import Path

        cases = load_cases(Path(__file__).with_name("evaluation_cases.json"))
        labels = {case["expected_classification"] for case in cases}

        self.assertEqual(
            labels,
            {"PHISHING_HIGH", "PHISHING_MEDIUM", "PHISHING_LOW", "BENIGN"},
        )

    def test_score_classifications_returns_exact_match_metrics(self):
        result = score_classifications(
            ["PHISHING_HIGH", "BENIGN", "PHISHING_LOW"],
            ["PHISHING_HIGH", "PHISHING_LOW", "PHISHING_LOW"],
        )

        self.assertEqual(result["count"], 3)
        self.assertAlmostEqual(result["accuracy"], 2 / 3)
        self.assertEqual(
            result["confusion_matrix"]["BENIGN"]["PHISHING_LOW"],
            1,
        )

    def test_score_classifications_rejects_mismatched_inputs(self):
        with self.assertRaises(ValueError):
            score_classifications(["BENIGN"], [])

    @patch("galileo.prompts.create_prompt")
    @patch("galileo.experiments.run_experiment")
    @patch("galileo.datasets.create_dataset")
    @patch.dict(
        "os.environ",
        {
            "GALILEO_API_KEY": "test-key",
            "GALILEO_PROJECT": "test-project",
            "GALILEO_MODEL_ALIAS": "OpenRouter Nemotron Free",
        },
    )
    def test_galileo_runner_submits_inputs_for_remote_generation(
        self,
        create_dataset,
        run_experiment,
        create_prompt,
    ):
        create_dataset.return_value = "test-dataset"
        cases = [
            {
                "subject": "Test subject",
                "body": "Synthetic test body",
                "expected_classification": "BENIGN",
            }
        ]

        result = run_model_experiment_in_galileo(cases)

        submitted_case = create_dataset.call_args.kwargs["content"][0]
        self.assertIn("input", submitted_case)
        self.assertEqual(submitted_case["ground_truth"], "BENIGN")
        self.assertNotIn("generated_output", submitted_case)
        self.assertEqual(result["execution"], "galileo")
        create_prompt.assert_called_once()
        experiment_settings = run_experiment.call_args.kwargs["prompt_settings"]
        self.assertEqual(experiment_settings.model_alias, "OpenRouter Nemotron Free")
        self.assertEqual(
            run_experiment.call_args.kwargs["dataset"],
            "test-dataset",
        )


if __name__ == "__main__":
    unittest.main()
