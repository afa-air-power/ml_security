"""Build an explainable graph from measured points, findings and gate inputs."""


def blocks_gate(finding: dict) -> bool:
    return (
        finding["severity"] in {"critical", "high"}
        and finding["status"] in {"confirmed", "needs_review"}
    )


def build_graph(findings: list[dict], warnings: list[dict], gate_passed: bool, is_blocking=blocks_gate) -> dict:
    nodes = [{"id": "gate", "type": "gate", "passed": gate_passed}]
    edges = []
    finding_nodes: dict[str, str] = {}

    for index, finding in enumerate(findings):
        node_id = f"finding-{index}"
        finding_nodes.setdefault(finding["key"], node_id)
        nodes.append({
            "id": node_id, "type": "finding", "key": finding["key"],
            "rule": finding["id"], "object": finding["object"], "severity": finding["severity"],
            "status": finding["status"], "blocking": is_blocking(finding),
        })
        if is_blocking(finding):
            edges.append({"from": node_id, "to": "gate", "type": "blocks"})
        if isinstance(finding.get("point"), dict):
            point_id = f"point-{index}"
            nodes.append({"id": point_id, "type": "point", "data": finding["point"]})
            edges.append({"from": point_id, "to": node_id, "type": "evidence"})

    for index, warning in enumerate(warnings):
        node_id = f"warning-{index}"
        nodes.append({"id": node_id, "type": "warning", **warning})
        if warning["blocking"]:
            edges.append({"from": node_id, "to": "gate", "type": "blocks"})
        finding_id = finding_nodes.get(warning["finding_key"])
        if finding_id is not None:
            edges.append({"from": finding_id, "to": node_id, "type": "coverage"})

    return {"version": 1, "nodes": nodes, "edges": edges}
