"""Regression checks for false passes, token semantics and frozen-input judging."""
from contextlib import redirect_stdout, redirect_stderr
import io
import json
from pathlib import Path
import shutil
import sys
import tempfile
import unittest
from unittest.mock import patch
import xml.etree.ElementTree as ET

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "tools"))
import benchmark as bench

for prefix, namespace in [
    ("bpmn", bench.B[1:-1]), ("bpmndi", "http://www.omg.org/spec/BPMN/20100524/DI"),
    ("dc", "http://www.omg.org/spec/DD/20100524/DC"), ("di", "http://www.omg.org/spec/DD/20100524/DI"),
    ("xsi", "http://www.w3.org/2001/XMLSchema-instance"),
]:
    ET.register_namespace(prefix, namespace)


class BenchmarkTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.base = Path(self.temp.name)
        self.out = self.base / "run"
        self.manifest, self.cases = bench.load_benchmark(ROOT / "benchmark/mock/manifest.json")

    def call(self, *args):
        with redirect_stdout(io.StringIO()), redirect_stderr(io.StringIO()):
            return bench.main(list(args))

    def candidates(self):
        folder = self.base / "candidates"
        folder.mkdir()
        for case in self.cases:
            shutil.copyfile(case["reference"], folder / (case["id"] + ".bpmn"))
        return folder

    def run_candidates(self, folder):
        return self.call("run", "--candidates", str(folder), "--out", str(self.out))

    def report(self):
        return bench.read_json(self.out / "report.json")

    def write_test_judgments(self):
        # These deliberately synthetic labels test merging, never judge accuracy.
        for case in bench.read_json(self.out / "run.json")["cases"]:
            record = bench.read_json(self.out / "judge-inputs" / (case["id"] + ".template.json"))
            record["model"] = "unit-test-double"
            for row in record["checks"]:
                row.update(status="pass", reason="Synthetic merge test only", evidence_ids=["start"])
            bench.write_json(self.out / "judgments" / (case["id"] + ".json"), record)

    def mutate(self, folder, case_id, fn):
        path = folder / (case_id + ".bpmn")
        root = ET.parse(path).getroot()
        fn(root)
        ET.ElementTree(root).write(path, encoding="utf-8", xml_declaration=True)

    def test_demo_needs_real_judgments(self):
        self.assertEqual(self.call("run", "--demo", "--out", str(self.out)), 2)
        report = self.report()
        self.assertEqual(report["summary"], {"total": 3, "pass": 0, "fail": 0, "review": 3, "pass_rate": 0})
        self.assertTrue(all(c["automatic"] == "PASS" for c in report["cases"]))
        self.assertTrue(report["mock"])

    def test_finalization_merges_all_checks(self):
        self.call("run", "--demo", "--out", str(self.out))
        self.write_test_judgments()
        self.assertEqual(self.call("finalize", str(self.out)), 0)
        self.assertEqual(self.report()["summary"]["pass"], 3)

    def test_ids_are_not_compared_to_reference(self):
        folder = self.candidates()
        def rename(root):
            mapping = {e.get("id"): "uuid_" + e.get("id") for e in root.iter() if e.get("id")}
            for e in root.iter():
                for key, value in list(e.attrib.items()):
                    if value in mapping:
                        e.set(key, mapping[value])
                if (e.text or "").strip() in mapping:
                    e.text = mapping[e.text.strip()]
        for case in self.cases:
            self.mutate(folder, case["id"], rename)
        self.run_candidates(folder)
        self.assertTrue(all(c["automatic"] == "PASS" for c in self.report()["cases"]))

    def test_synonym_binding_rechecks_automatic_rules(self):
        folder = self.candidates()
        def synonym(root):
            root.find(".//" + bench.B + "userTask[@id='grant']").set("name", "Выдать права")
        self.mutate(folder, "01-simple", synonym)
        self.run_candidates(folder)
        self.assertEqual(self.report()["cases"][0]["automatic"], "REVIEW")
        self.write_test_judgments()
        path = self.out / "judgments/01-simple.json"
        record = bench.read_json(path)
        record["bindings"] = {"grant": "grant"}
        bench.write_json(path, record)
        self.assertEqual(self.call("finalize", str(self.out)), 0)

    def test_duplicate_ids_and_malformed_xml_fail(self):
        folder = self.candidates()
        def duplicate(root):
            process = root.find(bench.B + "process")
            ET.SubElement(process, bench.B + "task", id="grant")
        self.mutate(folder, "01-simple", duplicate)
        (folder / "02-rework.bpmn").write_text("<broken", encoding="utf-8")
        self.assertEqual(self.run_candidates(folder), 1)
        self.assertEqual(self.report()["summary"]["fail"], 2)

    def test_and_join_changed_to_xor_is_rejected(self):
        folder = self.candidates()
        def change(root):
            root.find(".//" + bench.B + "parallelGateway[@id='join']").tag = bench.B + "exclusiveGateway"
        self.mutate(folder, "03-parallel", change)
        self.assertEqual(self.run_candidates(folder), 1)
        case = self.report()["cases"][2]
        self.assertEqual(next(c for c in case["checks"] if c["id"] == "R-type-join")["status"], "fail")
        self.assertTrue(any(c["id"].startswith("S-") and c["status"] == "fail" for c in case["checks"]))

    def test_refusal_bypass_is_rejected(self):
        folder = self.candidates()
        def bypass(root):
            root.find(".//" + bench.B + "sequenceFlow[@sourceRef='notify']").set("targetRef", "grant")
        self.mutate(folder, "01-simple", bypass)
        self.assertEqual(self.run_candidates(folder), 1)
        self.assertEqual(next(c for c in self.report()["cases"][0]["checks"] if c["id"] == "R-refusal")["status"], "fail")

    def test_token_deadlock_is_detected(self):
        folder = self.candidates()
        def deadlock(root):
            process = root.find(bench.B + "process")
            ET.SubElement(process, bench.B + "task", id="never")
            ET.SubElement(process, bench.B + "sequenceFlow", id="never_loop", sourceRef="never", targetRef="never")
            ET.SubElement(process, bench.B + "sequenceFlow", id="never_join", sourceRef="never", targetRef="join")
        self.mutate(folder, "03-parallel", deadlock)
        self.assertEqual(self.run_candidates(folder), 1)
        self.assertTrue(any("Deadlock" in c["reason"] for c in self.report()["cases"][2]["checks"]))

    def test_special_events_remain_review_even_with_positive_judge(self):
        folder = self.candidates()
        def event(root):
            start = root.find(".//" + bench.B + "startEvent")
            timer = ET.SubElement(start, bench.B + "timerEventDefinition", id="timer")
            ET.SubElement(timer, bench.B + "timeDuration").text = "PT1H"
        self.mutate(folder, "01-simple", event)
        self.run_candidates(folder)
        self.write_test_judgments()
        self.assertEqual(self.call("finalize", str(self.out)), 2)
        case = self.report()["cases"][0]
        self.assertEqual(case["automatic"], "REVIEW")
        self.assertTrue(any("need an engine" in c["reason"] for c in case["checks"]))

    def test_bad_judge_provenance_and_evidence_do_not_pass(self):
        self.call("run", "--demo", "--out", str(self.out))
        self.write_test_judgments()
        for case_id, field, value in [("01-simple", "candidate_sha256", "stale"),
                                       ("02-rework", "evidence", "does_not_exist")]:
            path = self.out / "judgments" / (case_id + ".json")
            record = bench.read_json(path)
            if field == "evidence":
                record["checks"][0]["evidence_ids"] = [value]
            else:
                record[field] = value
            bench.write_json(path, record)
        self.assertEqual(self.call("finalize", str(self.out)), 2)
        self.assertEqual(self.report()["summary"]["review"], 2)

    def test_missing_semantic_check_is_review(self):
        self.call("run", "--demo", "--out", str(self.out))
        self.write_test_judgments()
        path = self.out / "judgments/01-simple.json"
        record = bench.read_json(path)
        record["checks"].pop()
        bench.write_json(path, record)
        self.assertEqual(self.call("finalize", str(self.out)), 2)

    def test_missing_files_and_non_utf8_are_counted(self):
        folder = self.candidates()
        (folder / "01-simple.bpmn").unlink()
        (folder / "02-rework.bpmn").write_bytes(b"\xff\xfeinvalid")
        self.assertEqual(self.run_candidates(folder), 1)
        self.assertEqual(self.report()["summary"]["total"], 3)
        self.assertEqual(self.report()["summary"]["fail"], 2)

    def test_generator_contract_and_error_accounting(self):
        adapter = self.base / "adapter.py"
        adapter.write_text(
            "import json, pathlib, sys\n"
            "r=json.load(sys.stdin)\n"
            "assert 'Построй' in r['prompt']\n"
            "if r['case_id']=='03-parallel': sys.exit(7)\n"
            f"p=pathlib.Path({str(ROOT / 'benchmark/mock')!r})/r['case_id']/'reference.bpmn'\n"
            "sys.stdout.write(p.read_text(encoding='utf-8'))\n", encoding="utf-8")
        command = f"{sys.executable} {adapter}"
        self.assertEqual(self.call("run", "--generator", command, "--out", str(self.out)), 1)
        self.assertEqual(self.report()["summary"]["fail"], 1)
        self.assertEqual(self.report()["summary"]["review"], 2)

    def test_generator_timeout_is_a_failure(self):
        adapter = self.base / "slow.py"
        adapter.write_text("import time\ntime.sleep(1)\n", encoding="utf-8")
        self.assertEqual(self.call("run", "--generator", f"{sys.executable} {adapter}",
                                  "--timeout", "0.05", "--out", str(self.out)), 1)
        self.assertEqual(self.report()["summary"]["fail"], 3)

    def test_input_tampering_and_run_overwrite_are_refused(self):
        self.call("run", "--demo", "--out", str(self.out))
        self.assertEqual(self.call("run", "--demo", "--out", str(self.out)), 2)
        path = self.out / "inputs/01-simple/prompt.md"
        path.write_text("changed", encoding="utf-8")
        self.assertEqual(self.call("finalize", str(self.out)), 2)

    def test_unavailable_xsd_validation_is_review(self):
        folder = self.candidates()
        spec = bench.read_json(self.cases[0]["spec"])
        fixture = self.base / "fixture"
        fixture.mkdir()
        shutil.copyfile(folder / "01-simple.bpmn", fixture / "candidate.bpmn")
        with patch("audit.subprocess.run", side_effect=FileNotFoundError("xmllint missing")):
            evaluated = bench.evaluate_case(fixture, spec, {}, self.base / "no-judgment.json")
        self.assertEqual(evaluated["automatic"], "REVIEW")

    def test_unknown_rule_is_a_configuration_error(self):
        spec = bench.read_json(self.cases[0]["spec"])
        spec["checks"][0]["kind"] = "typo"
        with self.assertRaises(ValueError):
            bench.validate_spec(spec)
        spec = bench.read_json(self.cases[0]["spec"])
        spec["scenarios"][0]["kind"] = "judge"
        with self.assertRaises(ValueError):
            bench.validate_spec(spec)

    def test_data_input_must_belong_to_receiving_task(self):
        folder = self.candidates()
        def wrong_owner(root):
            task = root.find(".//" + bench.B + "userTask[@id='review']")
            task.find(bench.B + "dataInputAssociation/" + bench.B + "targetRef").text = "create_property_0"
        self.mutate(folder, "02-rework", wrong_owner)
        self.assertEqual(self.run_candidates(folder), 1)
        check = next(c for c in self.report()["cases"][1]["checks"] if c["id"] == "R-data-1")
        self.assertEqual(check["status"], "fail")

    def test_empty_generator_is_a_configuration_error(self):
        self.assertEqual(self.call("run", "--generator", "", "--out", str(self.out)), 2)
        self.assertFalse(self.out.exists())


if __name__ == "__main__":
    unittest.main()
