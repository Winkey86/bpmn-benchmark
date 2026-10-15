#!/usr/bin/env python3
"""Run BPMN benchmarks locally; Codex supplies a separate, evidence-based review."""
import argparse
from collections import Counter, defaultdict, deque
from datetime import datetime, timezone
import hashlib
import json
import math
from pathlib import Path
import re
import shlex
import subprocess
import sys
import unicodedata
import xml.etree.ElementTree as ET

from audit import B, NODE_TYPES, ROOT, audit, local

RUBRIC = ROOT / "CODEX_BENCHMARK.md"
EVALUATOR_FILES = [Path(__file__).resolve(), ROOT / "tools/audit.py"]
KINDS = {"type", "lane", "flow", "reachable", "data", "judge"}
SUPPORTED = {
    "startEvent", "endEvent", "task", "userTask", "manualTask", "serviceTask",
    "scriptTask", "businessRuleTask", "exclusiveGateway", "parallelGateway",
}


def digest(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()


def read_json(path):
    return json.loads(path.read_text(encoding="utf-8"))


def write_json(path, value):
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(value, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")


def norm(value):
    return " ".join(unicodedata.normalize("NFKC", value or "").casefold().split())


def result(check_id, status, reason, evidence=()):
    return {"id": check_id, "status": status, "reason": reason, "evidence_ids": list(evidence)}


class Unresolved(Exception):
    """Matching or semantics require review rather than a guessed answer."""


class Absent(Exception):
    """The reviewer explicitly confirmed an element is absent."""


class Model:
    def __init__(self, path):
        raw = path.read_text(encoding="utf-8")
        if re.search(r"<!\s*(DOCTYPE|ENTITY)\b", raw, re.I):
            raise ValueError("DTD/entities are outside the benchmark XML contract")
        self.root = ET.fromstring(raw)
        if self.root.tag != B + "definitions":
            raise ValueError("Expected BPMN 2.0 definitions namespace")
        self.items = list(self.root.iter())
        self.parents = {child: parent for parent in self.items for child in parent}
        self.by_id = {e.get("id"): e for e in self.items if e.get("id")}
        self.nodes = {k: e for k, e in self.by_id.items() if e.tag.startswith(B) and local(e) in NODE_TYPES}
        self.flows = {k: e for k, e in self.by_id.items() if e.tag == B + "sequenceFlow"}
        self.incoming, self.outgoing = defaultdict(list), defaultdict(list)
        for key, flow in self.flows.items():
            self.incoming[flow.get("targetRef")].append(key)
            self.outgoing[flow.get("sourceRef")].append(key)

    def resolve(self, symbol, spec, bindings):
        if symbol in bindings:
            if bindings[symbol] is None:
                raise Absent(f"Reviewer confirmed absence: {symbol}")
            return bindings[symbol]
        names = {norm(name) for name in spec["selectors"][symbol]}
        found = [key for key, e in self.by_id.items() if norm(e.get("name")) in names]
        if len(found) > 1:
            types = {t for c in spec["checks"] if c["kind"] == "type" and c["element"] == symbol for t in c["types"]}
            typed = [key for key in found if self.by_id[key].tag.startswith(B) and local(self.by_id[key]) in types]
            if len(typed) == 1:
                found = typed
        if len(found) != 1:
            raise Unresolved(f"{symbol}: matched {len(found)} elements; Codex must supply a binding")
        return found[0]

    def graph(self):
        rows = []
        for key, e in self.by_id.items():
            parent = self.parents.get(e)
            rows.append({
                "id": key, "type": local(e), "attributes": dict(e.attrib),
                "parent_id": parent.get("id") if parent is not None else None,
                "text": (e.text or "").strip(),
                "children": [
                    {"type": local(c), "attributes": dict(c.attrib), "text": "".join(c.itertext()).strip()}
                    for c in e
                ],
            })
        return rows


def validate_spec(spec):
    selectors = spec.get("selectors")
    if not isinstance(selectors, dict) or not selectors:
        raise ValueError("spec.selectors must be a nonempty object")
    for key, names in selectors.items():
        if not isinstance(key, str) or not isinstance(names, list) or not names or not all(
            isinstance(name, str) and name.strip() for name in names
        ):
            raise ValueError(f"Invalid selector: {key}")
    checks, scenarios = spec.get("checks"), spec.get("scenarios")
    if not isinstance(checks, list) or not checks or not isinstance(scenarios, list) or not scenarios:
        raise ValueError("Every case needs checks and at least one scenario")
    ids = set()
    for check in checks + scenarios:
        key = check.get("id")
        if not isinstance(key, str) or not key or key in ids or key.startswith("system:"):
            raise ValueError(f"Invalid/duplicate check ID: {key}")
        ids.add(key)
    for check in checks:
        kind = check.get("kind")
        if kind not in KINDS or not isinstance(check.get("description"), str) or not check["description"].strip():
            raise ValueError(f"Invalid check: {check['id']}")
        fields = {
            "type": ["element"], "lane": ["element"], "flow": ["from", "to"],
            "reachable": ["from", "to"], "data": ["from", "to"], "judge": [],
        }[kind]
        allowed = {"id", "kind", "description"} | {
            "type": {"element", "types"}, "lane": {"element", "lane"},
            "flow": {"from", "to", "flow_type", "name"},
            "reachable": {"from", "to", "avoid", "expected"},
            "data": {"from", "to", "direction"}, "judge": set(),
        }[kind]
        if set(check) - allowed:
            raise ValueError(f"{check['id']}: unknown check fields")
        for field in fields:
            if check.get(field) not in selectors:
                raise ValueError(f"{check['id']}: unknown selector in {field}")
        if kind == "type" and (not isinstance(check.get("types"), list) or not check["types"]
                               or not all(isinstance(t, str) for t in check["types"])):
            raise ValueError(f"{check['id']}: types must be a nonempty string list")
        if kind == "lane" and not isinstance(check.get("lane"), str):
            raise ValueError(f"{check['id']}: lane must be a string")
        if kind == "flow" and check.get("flow_type", "sequenceFlow") not in {"sequenceFlow", "messageFlow"}:
            raise ValueError(f"{check['id']}: unknown flow_type")
        if kind == "reachable":
            if type(check.get("expected", True)) is not bool:
                raise ValueError(f"{check['id']}: expected must be boolean")
            if any(s not in selectors for s in check.get("avoid", [])):
                raise ValueError(f"{check['id']}: unknown avoid selector")
        if kind == "data" and check.get("direction") not in {"input", "output"}:
            raise ValueError(f"{check['id']}: data direction must be input or output")
    if not any(c["kind"] == "judge" for c in checks):
        raise ValueError("Each case needs at least one semantic judge requirement")
    for scenario in scenarios:
        if set(scenario) - {"id", "description", "start", "ends", "must_visit", "must_not_visit",
                            "visit_counts", "before", "choices"}:
            raise ValueError(f"{scenario['id']}: unknown scenario fields")
        symbols = [scenario.get("start")] + scenario.get("ends", [])
        symbols += scenario.get("must_visit", []) + scenario.get("must_not_visit", [])
        symbols += list(scenario.get("visit_counts", {}))
        for pair in scenario.get("before", []):
            if not isinstance(pair, list) or len(pair) != 2:
                raise ValueError("before entries must contain two selectors")
            symbols += pair
        for source, choices in scenario.get("choices", {}).items():
            if not isinstance(choices, list) or not choices:
                raise ValueError("choices must be nonempty lists of target selectors")
            symbols += [source] + choices
        if not scenario.get("ends") or any(s not in selectors for s in symbols):
            raise ValueError(f"{scenario['id']}: unknown selector or no expected ends")
        if any(type(n) is not int or n < 0 for n in scenario.get("visit_counts", {}).values()):
            raise ValueError("visit_counts must be nonnegative integers")


def check_requirement(model, spec, check, bindings):
    resolve = lambda key: model.resolve(check[key], spec, bindings)
    kind, evidence = check["kind"], []
    if kind == "type":
        key = resolve("element")
        ok = model.by_id[key].tag.startswith(B) and local(model.by_id[key]) in check["types"]
        evidence = [key]
    elif kind == "lane":
        key = resolve("element")
        lanes = [e for e in model.items if e.tag == B + "lane" and norm(e.get("name")) == norm(check["lane"])]
        ok = any(key in {(ref.text or "").strip() for ref in e.findall(B + "flowNodeRef")} for e in lanes)
        evidence = [key] + [e.get("id") for e in lanes if e.get("id")]
    elif kind == "flow":
        source, target = resolve("from"), resolve("to")
        flows = [e for e in model.items if e.tag == B + check.get("flow_type", "sequenceFlow")
                 and e.get("sourceRef") == source and e.get("targetRef") == target
                 and ("name" not in check or norm(e.get("name")) == norm(check["name"]))]
        ok, evidence = bool(flows), [source, target] + [e.get("id") for e in flows]
    elif kind == "reachable":
        source, target = resolve("from"), resolve("to")
        blocked = {model.resolve(s, spec, bindings) for s in check.get("avoid", [])}
        queue, visited = deque([source]), set()
        while queue:
            key = queue.popleft()
            if key in visited or key in blocked:
                continue
            visited.add(key)
            queue.extend(model.flows[f].get("targetRef") for f in model.outgoing[key])
        ok, evidence = (target in visited) == check.get("expected", True), [source, target]
    elif kind == "data":
        source, target = resolve("from"), resolve("to")
        owner, data = (target, source) if check["direction"] == "input" else (source, target)
        associations = model.by_id[owner].findall(B + "data" + check["direction"].title() + "Association")
        ref_tag = B + ("sourceRef" if check["direction"] == "input" else "targetRef")
        def owned(ref):
            item = model.by_id.get((ref.text or "").strip())
            while item is not None:
                if item.get("id") == owner:
                    return True
                item = model.parents.get(item)
            return False
        item_tag = B + ("targetRef" if check["direction"] == "input" else "sourceRef")
        matches = [e for e in associations if any((r.text or "").strip() == data for r in e.findall(ref_tag))
                   and any(owned(r) for r in e.findall(item_tag))]
        ok, evidence = bool(matches), [source, target] + [e.get("id") for e in matches if e.get("id")]
    else:
        raise ValueError(f"Unhandled check kind: {kind}")
    return result(check["id"], "pass" if ok else "fail", check["description"], evidence)


def scenario_check(model, spec, scenario, bindings):
    """Explore all firing orders for a small, explicitly supported BPMN subset."""
    resolve = lambda symbol: model.resolve(symbol, spec, bindings)
    key = scenario["id"]
    unsupported = [k for k, e in model.nodes.items() if local(e) not in SUPPORTED]
    if len(model.root.findall(B + "process")) != 1 or unsupported:
        raise Unresolved("Token scenarios support one flat process; unsupported nodes: " + ", ".join(unsupported))
    for node_id, e in model.nodes.items():
        if any(local(c).endswith(("EventDefinition", "LoopCharacteristics")) or
               local(c) in {"eventDefinitionRef", "loopCharacteristics"} for c in e):
            raise Unresolved(f"Event/loop activity semantics need an engine: {node_id}")
        if local(e) != "exclusiveGateway" and any(
            model.flows[f].find(B + "conditionExpression") is not None for f in model.outgoing[node_id]
        ):
            raise Unresolved(f"Conditional task/parallel flows need an engine: {node_id}")
        if e.get("isForCompensation") == "true" or e.get("startQuantity", "1") != "1" or e.get("completionQuantity", "1") != "1":
            raise Unresolved(f"Unsupported activity token semantics: {node_id}")
    if model.root.findall(".//" + B + "messageFlow"):
        raise Unresolved("Message exchange scenarios need an engine")
    start = resolve(scenario["start"])
    if start not in model.nodes or local(model.nodes[start]) != "startEvent":
        return result(key, "fail", "Scenario start is not a startEvent", [start])
    starts = [k for k, e in model.nodes.items() if local(e) == "startEvent"]
    if starts != [start]:
        raise Unresolved("Multiple process starts are outside token scenario support")
    if any(model.incoming[k] for k in starts) or any(
        model.outgoing[k] for k, e in model.nodes.items() if local(e) == "endEvent"
    ):
        return result(key, "fail", "Start has an incoming flow or end has an outgoing flow")
    choices = {resolve(k): [resolve(v) for v in values] for k, values in scenario.get("choices", {}).items()}
    must = {resolve(k) for k in scenario.get("must_visit", [])}
    forbidden = {resolve(k) for k in scenario.get("must_not_visit", [])}
    ends_expected = Counter(resolve(k) for k in scenario["ends"])
    counts_expected = {resolve(k): n for k, n in scenario.get("visit_counts", {}).items()}
    before = [(resolve(a), resolve(b)) for a, b in scenario.get("before", [])]
    initial = ((("@start", 1),), (), (), ())
    queue, seen, completed = deque([(initial, [])]), set(), 0
    while queue:
        state, trace = queue.popleft()
        if state in seen:
            continue
        seen.add(state)
        if len(seen) > 10000 or len(trace) > 200:
            raise Unresolved("Scenario exploration bound reached (10000 states / 200 firings)")
        marking, used, counts, ends = (Counter(dict(part)) for part in state)
        if not marking:
            if ends != ends_expected or not must.issubset(counts) or any(
                counts[k] != n for k, n in counts_expected.items()
            ) or any(used[k] != len(v) for k, v in choices.items()):
                return result(key, "fail", "Unexpected end, missing activity, visit count or unused XOR choice", trace)
            completed += 1
            continue
        enabled = []
        for node_id, e in model.nodes.items():
            incoming = ["@start"] if node_id == start else model.incoming[node_id]
            if local(e) == "parallelGateway" and len(incoming) > 1:
                if all(marking[f] for f in incoming):
                    enabled.append((node_id, incoming))
            else:
                enabled.extend((node_id, [f]) for f in incoming if marking[f])
        if not enabled:
            return result(key, "fail", "Deadlock: tokens remain but no node can fire", trace)
        for node_id, consumed in enabled:
            e, next_trace = model.nodes[node_id], trace + [node_id]
            if node_id in forbidden or any(node_id == b and not counts[a] for a, b in before):
                return result(key, "fail", "Forbidden activity or required order violated", next_trace)
            outgoing, next_used = model.outgoing[node_id], used.copy()
            if local(e) == "exclusiveGateway" and len(outgoing) > 1:
                if node_id not in choices:
                    raise Unresolved(f"Scenario has no scripted choice for XOR {node_id}")
                index = used[node_id]
                if index >= len(choices[node_id]):
                    return result(key, "fail", "More XOR visits than the scenario specifies", next_trace)
                target = choices[node_id][index]
                outgoing = [f for f in outgoing if model.flows[f].get("targetRef") == target]
                if len(outgoing) != 1:
                    raise Unresolved(f"XOR {node_id}: cannot bind a unique direct branch to {target}")
                next_used[node_id] += 1
            next_marking, next_counts, next_ends = marking.copy(), counts.copy(), ends.copy()
            next_marking.subtract(consumed)
            next_marking.update(outgoing)
            next_counts[node_id] += 1
            if local(e) == "endEvent":
                next_ends[node_id] += 1
            parts = [next_marking, next_used, next_counts, next_ends]
            next_state = tuple(tuple(sorted((k, n) for k, n in part.items() if n)) for part in parts)
            queue.append((next_state, next_trace))
    return result(key, "pass", f"All {completed} terminal states passed; explored {len(seen)} states",
                  sorted(must | set(ends_expected)))


def judge_record(path, expected, model, spec):
    judge_checks = [c for c in spec["checks"] if c["kind"] == "judge"]
    if not path.exists():
        return {}, [result(c["id"], "review", "Codex review pending") for c in judge_checks]
    try:
        record = read_json(path)
        if any(record.get(k) != v for k, v in expected.items()):
            raise ValueError("Judgment provenance does not match this case/input/rubric")
        if not isinstance(record.get("model"), str) or not record["model"].strip():
            raise ValueError("Record the judge model")
        bindings = record.get("bindings", {})
        if not isinstance(bindings, dict) or any(
            key not in spec["selectors"] or (value is not None and
            (not isinstance(value, str) or value not in model.by_id)) for key, value in bindings.items()
        ):
            raise ValueError("Bindings must map known selectors to existing XML IDs or null")
        present = [value for value in bindings.values() if value is not None]
        if len(present) != len(set(present)):
            raise ValueError("Distinct selectors must bind to distinct XML elements")
        rows = record.get("checks", [])
        if not isinstance(rows, list) or Counter(r["id"] for r in rows) != Counter(c["id"] for c in judge_checks):
            raise ValueError("Exactly one verdict is required for each semantic check")
        for row in rows:
            evidence = row.get("evidence_ids")
            if row.get("status") not in {"pass", "fail", "review"} or not isinstance(row.get("reason"), str) or not row["reason"].strip():
                raise ValueError("Every verdict needs a valid status and reason")
            if not isinstance(evidence, list) or any(not isinstance(e, str) or e not in model.by_id for e in evidence):
                raise ValueError("Evidence must reference existing XML IDs")
            if row["status"] == "pass" and not evidence:
                raise ValueError("A semantic pass requires XML evidence")
        return bindings, rows
    except (ValueError, KeyError, TypeError, AttributeError) as exc:
        return {}, [result("system:judge", "review", f"Invalid judgment: {exc}")]


def verdict(rows):
    statuses = {r["status"] for r in rows}
    return "FAIL" if "fail" in statuses else "REVIEW" if "review" in statuses else "PASS"


def evaluate_case(folder, spec, expected, judgments):
    candidate = folder / "candidate.bpmn"
    try:
        model = Model(candidate)
        structural = audit(candidate)
    except (OSError, ValueError, ET.ParseError) as exc:
        return {"automatic": "FAIL", "verdict": "FAIL", "checks": [
            result("system:xml", "fail", str(exc))], "structural": None}
    rows = [result("system:xsd", {"pass": "pass", "fail": "fail", "not_checked": "review"}[
        structural["xsd"]["status"]], json.dumps(structural["xsd"], ensure_ascii=False))]
    for name in ("duplicate_ids", "unresolved_references", "ambiguous_references", "invalid_sequence_flows",
                 "message_flows_within_same_scope", "catch_events_without_definition"):
        values = structural[name]
        # shortcut: QName/external references require review until namespace-aware import support is added.
        uncertain = name == "unresolved_references" and any(
            ":" in v["reference"] or v["attribute"] == "calledElement" for v in values
        )
        rows.append(result("system:" + name, ("review" if uncertain else "fail") if values else "pass",
                           json.dumps(values, ensure_ascii=False)))
    missing_ids = [local(e) for e in model.items if e.tag.startswith(B) and local(e) in NODE_TYPES and not e.get("id")]
    rows.append(result("system:node_ids", "fail" if missing_ids else "pass", str(missing_ids)))
    if verdict(rows) != "PASS":
        rows += [result(c["id"], "review", "Blocked by structural validation") for c in spec["checks"]]
        rows += [result(c["id"], "review", "Blocked by structural validation") for c in spec["scenarios"]]
        return {"automatic": verdict(rows), "verdict": verdict(rows), "checks": rows, "structural": structural}
    bindings, judged = judge_record(judgments, expected, model, spec)
    matched = defaultdict(list)
    for symbol in spec["selectors"]:
        try:
            matched[model.resolve(symbol, spec, bindings)].append(symbol)
        except (Unresolved, Absent):
            pass
    collisions = [symbols for symbols in matched.values() if len(symbols) > 1]
    if collisions:
        rows.append(result("system:matching", "review", f"Distinct selectors matched one element: {collisions}"))
    for check in spec["checks"] + spec["scenarios"]:
        if check.get("kind") == "judge":
            continue
        try:
            row = check_requirement(model, spec, check, bindings) if "kind" in check else scenario_check(
                model, spec, check, bindings)
        except (Unresolved, Absent) as exc:
            row = result(check["id"], "fail" if isinstance(exc, Absent) else "review", str(exc))
        rows.append(row)
    automatic = verdict(rows)
    rows += judged
    return {"automatic": automatic, "verdict": verdict(rows), "checks": rows, "structural": structural}


def load_benchmark(path):
    manifest = read_json(path)
    if manifest.get("version") != 1 or type(manifest.get("mock")) is not bool or not manifest.get("cases"):
        raise ValueError("Benchmark needs version=1, mock=true/false, and nonempty cases")
    seen, cases = set(), []
    for case in manifest["cases"]:
        key = case["id"]
        if not isinstance(key, str) or not re.fullmatch(r"[a-zA-Z0-9][a-zA-Z0-9_-]*", key) or key in seen:
            raise ValueError(f"Invalid/duplicate case ID: {key}")
        seen.add(key)
        files = {}
        for field in ("prompt", "spec", "reference"):
            files[field] = (path.parent / case[field]).resolve()
            if not files[field].is_relative_to(path.parent.resolve()) or not files[field].is_file():
                raise ValueError(f"Case {key}: invalid {field} path")
        validate_spec(read_json(files["spec"]))
        cases.append({"id": key, **files})
    return manifest, cases


def evaluate_run(out):
    run = read_json(out / "run.json")
    if {p.name: digest(p) for p in EVALUATOR_FILES} != run["evaluator_sha256"]:
        raise ValueError("Evaluator code changed; start a new run")
    if digest(RUBRIC) != run["rubric_sha256"]:
        raise ValueError("Judge instruction changed; start a new run")
    cases = []
    for case in run["cases"]:
        folder = out / "inputs" / case["id"]
        for name, sha in case["files"].items():
            if digest(folder / name) != sha:
                raise ValueError(f"Input changed after capture: {case['id']}/{name}; start a new run")
        if case.get("generation_error"):
            evaluated = {"automatic": "FAIL", "verdict": "FAIL", "structural": None, "checks": [
                result("system:generation", "fail", case["generation_error"])]}
        else:
            evaluated = evaluate_case(folder, read_json(folder / "checks.json"), case["provenance"],
                                      out / "judgments" / (case["id"] + ".json"))
        cases.append({"id": case["id"], **evaluated})
    totals = Counter(c["verdict"] for c in cases)
    report = {
        "mock": run["mock"], "source": run["source"], "created_at": run["created_at"],
        "evaluated_at": datetime.now(timezone.utc).isoformat(),
        "summary": {"total": len(cases), "pass": totals["PASS"], "fail": totals["FAIL"],
                    "review": totals["REVIEW"], "pass_rate": totals["PASS"] / len(cases)},
        "limitations": [
            "Synthetic mock cases are plumbing checks, not a measurement of production quality.",
            "Bounded token scenarios: one flat process, ordinary tasks, none start/end events, XOR and AND.",
            "XOR branches are scripted; condition expressions, external services and data values are not executed.",
            "Other BPMN behavior requires engine checks; visual layout is not scored.",
            "Judge JSON validation checks provenance and evidence existence, not the truth of the judge reasoning.",
        ],
        "cases": cases,
    }
    write_json(out / "report.json", report)
    lines = ["# BPMN benchmark", "", "**MOCK — технический прогон**" if run["mock"] else "**Benchmark run**", "",
             f"PASS: {totals['PASS']} · FAIL: {totals['FAIL']} · REVIEW: {totals['REVIEW']} · всего: {len(cases)}",
             "", "| Кейс | Код | Итог |", "|---|---|---|"]
    lines += [f"| {c['id']} | {c['automatic']} | {c['verdict']} |" for c in cases]
    for case in cases:
        issues = [r for r in case["checks"] if r["status"] != "pass"]
        if issues:
            lines += ["", "## " + case["id"], ""]
            lines += [f"- **{r['status'].upper()} · {r['id']}**: " + " ".join(r["reason"].split())
                      for r in issues]
    lines += ["", "Ограничения: сценарии с заданными ветвями XOR, без вычисления выражений, интеграций и оценки геометрии.",
              "Неподдержанная семантика остаётся REVIEW; подробности и XML-доказательства — в report.json.", ""]
    (out / "report.md").write_text("\n".join(lines), encoding="utf-8")
    print(f"{'MOCK | ' if run['mock'] else ''}PASS {totals['PASS']} | FAIL {totals['FAIL']} | REVIEW {totals['REVIEW']}")
    print(out / "report.md")
    return 1 if totals["FAIL"] else 2 if totals["REVIEW"] else 0


def capture_run(args):
    manifest, cases = load_benchmark(args.benchmark.resolve())
    if args.demo and not manifest["mock"]:
        raise ValueError("--demo is only for explicitly mock benchmarks")
    command = shlex.split(args.generator) if args.generator is not None else None
    if command == []:
        raise ValueError("--generator needs a nonempty command")
    out = args.out.resolve()
    out.mkdir(parents=True, exist_ok=False)
    (out / "judgments").mkdir()
    run = {"version": 1, "mock": manifest["mock"], "created_at": datetime.now(timezone.utc).isoformat(),
           "evaluator_sha256": {p.name: digest(p) for p in EVALUATOR_FILES},
           "rubric_sha256": digest(RUBRIC), "benchmark": str(args.benchmark.resolve()),
           "benchmark_sha256": digest(args.benchmark), "source": "reference_demo" if args.demo else
           "generator" if args.generator else "candidate_files", "generator": args.generator, "cases": []}
    write_json(out / "benchmark.json", manifest)
    for case in cases:
        folder = out / "inputs" / case["id"]
        folder.mkdir(parents=True)
        for field, filename in (("prompt", "prompt.md"), ("spec", "checks.json"), ("reference", "reference.bpmn")):
            (folder / filename).write_bytes(case[field].read_bytes())
        candidate, error = folder / "candidate.bpmn", None
        try:
            if args.demo:
                candidate.write_bytes(case["reference"].read_bytes())
            elif args.candidates:
                candidate.write_bytes((args.candidates / (case["id"] + ".bpmn")).read_bytes())
            else:
                request = json.dumps({"case_id": case["id"], "prompt": case["prompt"].read_text(encoding="utf-8")},
                                     ensure_ascii=False)
                generated = subprocess.run(command, input=request, text=True, encoding="utf-8",
                                           capture_output=True, timeout=args.timeout)
                (folder / "generator.stderr.log").write_text(generated.stderr, encoding="utf-8")
                if generated.returncode:
                    raise ValueError(f"Generator exited {generated.returncode}; see generator.stderr.log")
                if not generated.stdout.strip():
                    raise ValueError("Generator returned empty stdout")
                candidate.write_text(generated.stdout, encoding="utf-8")
            candidate.read_text(encoding="utf-8")
        except (OSError, ValueError, subprocess.TimeoutExpired) as exc:
            error = str(exc)
        files = {p.name: digest(p) for p in folder.iterdir() if p.is_file()}
        provenance = {"case_id": case["id"], "prompt_sha256": files["prompt.md"], "spec_sha256": files["checks.json"],
                      "reference_sha256": files["reference.bpmn"], "rubric_sha256": run["rubric_sha256"],
                      "candidate_sha256": files.get("candidate.bpmn")}
        entry = {"id": case["id"], "files": files, "provenance": provenance, "generation_error": error}
        run["cases"].append(entry)
        spec = read_json(folder / "checks.json")
        graph = None
        if not error:
            try:
                graph = Model(candidate).graph()
            except (ValueError, ET.ParseError):
                pass
        bundle = {
            "provenance": provenance, "mock": run["mock"],
            "prompt": (folder / "prompt.md").read_text(encoding="utf-8"), "spec": spec,
            "candidate_xml": candidate.read_text(encoding="utf-8") if not error else None,
            "reference_xml": (folder / "reference.bpmn").read_text(encoding="utf-8"),
            "graph": graph, "generation_error": error,
        }
        write_json(out / "judge-inputs" / (case["id"] + ".json"), bundle)
        write_json(out / "judge-inputs" / (case["id"] + ".template.json"), {
            **provenance, "model": "", "bindings": {},
            "checks": [result(c["id"], "review", "Не оценено") for c in spec["checks"] if c["kind"] == "judge"],
        })
    write_json(out / "run.json", run)
    return evaluate_run(out)


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    commands = parser.add_subparsers(dest="command", required=True)
    run = commands.add_parser("run", help="Capture candidates and run code checks; prepare Codex inputs")
    run.add_argument("--benchmark", type=Path, default=ROOT / "benchmark/mock/manifest.json")
    mode = run.add_mutually_exclusive_group(required=True)
    mode.add_argument("--demo", action="store_true", help="Use mock references as candidates; no service quality claim")
    mode.add_argument("--candidates", type=Path, help="Directory of <case_id>.bpmn files")
    mode.add_argument("--generator", help="Command reading JSON on stdin and returning raw BPMN XML on stdout")
    run.add_argument("--out", type=Path, required=True, help="New run directory; existing directories are refused")
    run.add_argument("--timeout", type=float, default=90, help="Per generator call, seconds")
    finalize = commands.add_parser("finalize", help="Validate Codex judgments and rerun checks on frozen candidates")
    finalize.add_argument("run_dir", type=Path)
    args = parser.parse_args(argv)
    if args.command == "run" and (not math.isfinite(args.timeout) or args.timeout <= 0):
        parser.error("--timeout must be positive")
    try:
        return capture_run(args) if args.command == "run" else evaluate_run(args.run_dir.resolve())
    except (OSError, ValueError, KeyError, TypeError, AttributeError) as exc:
        print(f"Benchmark error: {exc}", file=sys.stderr)
        return 2


if __name__ == "__main__":
    sys.exit(main())
