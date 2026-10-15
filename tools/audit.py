#!/usr/bin/env python3
"""Limited structural BPMN audit; prompt fidelity and token semantics need review."""
from collections import Counter, defaultdict
from pathlib import Path
import hashlib
import json
import re
import subprocess
import xml.etree.ElementTree as ET

ROOT = Path(__file__).resolve().parents[1]
B = "{http://www.omg.org/spec/BPMN/20100524/MODEL}"
D = "{http://www.omg.org/spec/BPMN/20100524/DI}"
NODE_TYPES = {
    "task", "userTask", "serviceTask", "businessRuleTask", "sendTask", "receiveTask",
    "manualTask", "scriptTask", "subProcess", "transaction", "adHocSubProcess", "callActivity",
    "startEvent", "endEvent", "intermediateCatchEvent", "intermediateThrowEvent", "boundaryEvent",
    "exclusiveGateway", "parallelGateway", "inclusiveGateway", "complexGateway", "eventBasedGateway",
}


def local(element):
    return element.tag.rsplit("}", 1)[-1]


def audit(path):
    raw = path.read_text(encoding="utf-8")
    root = ET.fromstring(raw)
    elements = list(root.iter())
    parents = {child: parent for parent in elements for child in parent}
    by_id = defaultdict(list)
    for element in elements:
        if element.get("id"):
            by_id[element.get("id")].append(element)

    def scope(element):
        while element in parents:
            element = parents[element]
            if local(element) in {"process", "subProcess", "transaction", "adHocSubProcess"}:
                return element

    references = []
    for element in elements:
        for key in ("sourceRef", "targetRef", "processRef", "attachedToRef", "bpmnElement", "default",
                    "messageRef", "signalRef", "errorRef", "escalationRef", "dataObjectRef", "dataStoreRef",
                    "activityRef", "calledElement"):
            if element.get(key):
                references.append((element.get("id"), key, element.get(key)))
        if local(element) in {"flowNodeRef", "incoming", "outgoing", "sourceRef", "targetRef"} and element.text:
            references.append((parents[element].get("id"), local(element), element.text.strip()))
    unresolved = [{"element": e, "attribute": k, "reference": v}
                  for e, k, v in references if v not in by_id]
    ambiguous = [{"element": e, "attribute": k, "reference": v}
                 for e, k, v in references if len(by_id[v]) > 1]

    bad_sequence = []
    same_scope_messages = []
    for element in elements:
        kind = local(element)
        if kind not in {"sequenceFlow", "messageFlow"}:
            continue
        ends = [by_id.get(element.get(key), []) for key in ("sourceRef", "targetRef")]
        if any(len(end) != 1 for end in ends):
            continue  # Already reported as unresolved or ambiguous.
        source, target = (end[0] for end in ends)
        if kind == "sequenceFlow" and (
            local(source) not in NODE_TYPES or local(target) not in NODE_TYPES
            or scope(source) is not scope(element) or scope(target) is not scope(element)
        ):
            bad_sequence.append(element.get("id"))
        if kind == "messageFlow" and scope(source) is not None and scope(source) is scope(target):
            same_scope_messages.append(element.get("id"))

    nodes = [e for e in elements if e.tag.startswith(B) and local(e) in NODE_TYPES]
    flows = [e for e in elements if e.tag == B + "sequenceFlow"]
    incoming = Counter(e.get("targetRef") for e in flows)
    outgoing = Counter(e.get("sourceRef") for e in flows)
    shape_refs = Counter(e.get("bpmnElement") for e in elements if e.tag == D + "BPMNShape")
    edge_refs = Counter(e.get("bpmnElement") for e in elements if e.tag == D + "BPMNEdge")
    schema = ROOT / "tools/vendor/bpmn-2.0.2/BPMN20.xsd"
    xsd = {"status": "not_checked", "reason": "Official XSD not available"}
    if schema.exists():
        try:
            result = subprocess.run(["xmllint", "--nonet", "--noout", "--schema", str(schema), str(path)],
                                    capture_output=True, text=True, timeout=30)
            xsd = {"status": "pass" if result.returncode == 0 else "fail", "diagnostics": result.stderr.strip()}
        except (FileNotFoundError, subprocess.TimeoutExpired) as exc:
            xsd = {"status": "not_checked", "reason": str(exc)}
    counts = Counter(local(e) for e in elements if e.tag.startswith(B))
    line_by_id = defaultdict(list)
    for match in re.finditer(r'\bid="([^"]+)"', raw):
        line_by_id[match.group(1)].append(raw.count("\n", 0, match.start()) + 1)
    return {
        "file": str(path.resolve().relative_to(ROOT)) if path.resolve().is_relative_to(ROOT) else str(path.resolve()),
        "sha256": hashlib.sha256(path.read_bytes()).hexdigest(),
        "xml_parse": "pass", "xsd": xsd, "counts": dict(sorted(counts.items())),
        "duplicate_ids": {key: len(value) for key, value in by_id.items() if len(value) > 1},
        "unresolved_references": unresolved, "ambiguous_references": ambiguous,
        "invalid_sequence_flows": bad_sequence, "message_flows_within_same_scope": same_scope_messages,
        "catch_events_without_definition": [e.get("id") for e in nodes
            if local(e) == "intermediateCatchEvent" and not any(local(c).endswith("EventDefinition") for c in e)],
        "nodes_without_incoming_sequence": [e.get("id") for e in nodes
            if not incoming[e.get("id")] and local(e) not in {"startEvent", "boundaryEvent"}
            and e.get("isForCompensation") != "true"],
        "nodes_without_outgoing_sequence": [e.get("id") for e in nodes
            if not outgoing[e.get("id")] and local(e) not in {"endEvent"}
            and e.get("isForCompensation") != "true"],
        "missing_di_shapes": [e.get("id") for e in nodes if not shape_refs[e.get("id")]],
        "missing_di_edges": [e.get("id") for e in flows if not edge_refs[e.get("id")]],
        "nodes": [{"id": e.get("id"), "type": local(e), "name": e.get("name"),
                   "lines": line_by_id[e.get("id")]} for e in nodes],
    }


def self_check():
    # Confirm duplicate IDs, dangling references and cross-scope flows are detected.
    import tempfile
    with tempfile.TemporaryDirectory(dir=ROOT) as folder:
        fixture = Path(folder) / "fixture.bpmn"
        fixture.write_text(f'<definitions xmlns="{B[1:-1]}" targetNamespace="urn:test">'
            '<process id="p"><task id="a"/><task id="a"/>'
            '<sequenceFlow id="bad" sourceRef="a" targetRef="missing"/></process>'
            '<process id="q"><task id="b"/><task id="c"/>'
            '<sequenceFlow id="cross" sourceRef="b" targetRef="x"/></process>'
            '<process id="r"><task id="x"/></process></definitions>')
        result = audit(fixture)
        assert result["duplicate_ids"] == {"a": 2}
        assert any(ref["reference"] == "missing" for ref in result["unresolved_references"])
        assert result["invalid_sequence_flows"] == ["cross"]


if __name__ == "__main__":
    self_check()
    paths = sorted(ROOT.glob("cases/*/original.bpmn")) + sorted(ROOT.glob("cases/*/candidate.bpmn"))
    results = [audit(path) for path in paths]
    output = ROOT / "reports/structural-audit.json"
    output.write_text(json.dumps(results, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
    for result in results:
        counts = result["counts"]
        print(result["file"], "XSD=" + result["xsd"]["status"],
              "duplicate IDs=" + str(len(result["duplicate_ids"])),
              "start/end=" + str(counts.get("startEvent", 0)) + "/" + str(counts.get("endEvent", 0)))
