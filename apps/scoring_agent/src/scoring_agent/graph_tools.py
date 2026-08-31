from __future__ import annotations

from collections.abc import Mapping
from typing import Any

import networkx as nx

from .schemas import GraphMetrics


def parse_topology(data: Mapping[str, Any]) -> nx.DiGraph:
    graph = nx.DiGraph()
    for node in data.get("nodes", []):
        graph.add_node(node["id"], **node)
    for edge in data.get("edges", []):
        graph.add_edge(edge["source"], edge["target"])
    return graph


def find_entrypoint(graph: nx.DiGraph) -> str | None:
    for node, data in graph.nodes(data=True):
        if (
            data.get("type") in {"gateway", "ingress"}
            or data.get("zone") == "public"
            or data.get("is_public")
        ):
            return str(node)
    return None


def check_external_exposure(
    graph: nx.DiGraph,
    service: str,
    gateway: str | None = None,
) -> tuple[bool, int, list[str]]:
    if service not in graph:
        return False, -1, []
    gateway = gateway or find_entrypoint(graph)
    if not gateway or gateway not in graph or not nx.has_path(graph, gateway, service):
        return False, -1, []
    path = nx.shortest_path(graph, gateway, service)
    return True, len(path) - 1, [str(node) for node in path]


def get_blast_radius(graph: nx.DiGraph, service: str) -> list[str]:
    if service not in graph:
        return []
    result = []
    for node in nx.descendants(graph, service):
        data = graph.nodes[node]
        if data.get("type") in {"database", "vault", "secrets", "storage"} or data.get(
            "criticality"
        ) in {"critical", "high"}:
            result.append(str(node))
    return result


def get_node_centrality(graph: nx.DiGraph, service: str) -> float:
    if service not in graph or len(graph) <= 2:
        return 0.0
    centrality = nx.betweenness_centrality(graph)
    return round(float(centrality.get(service, 0.0)), 4)


def extract_node_metrics(graph: nx.DiGraph, service: str) -> GraphMetrics:
    exposed, hops, path = check_external_exposure(graph, service)
    return GraphMetrics(
        is_exposed=exposed,
        hops=hops,
        path=path,
        crit_assets=get_blast_radius(graph, service),
        centrality=get_node_centrality(graph, service),
    )
