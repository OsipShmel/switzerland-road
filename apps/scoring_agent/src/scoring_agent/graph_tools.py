import networkx as nx
from src.scoring_agent.schemas import GraphMetrics


def find_entrypoint(g: nx.DiGraph) -> str | None:
    for n, d in g.nodes(data=True):
        if d.get("type") in ("gateway", "ingress") or d.get("zone") == "public" or d.get("is_public"):
            return str(n)
    return None


def check_external_exposure(g: nx.DiGraph, s: str, gw: str | None = None) -> tuple[bool, int, list[str]]:
    if s not in g:
        return False, -1, []
    if gw is None:
        gw = find_entrypoint(g)
    if not gw or gw not in g:
        return False, -1, []
    if nx.has_path(g, gw, s):
        p = nx.shortest_path(g, gw, s)
        return True, len(p) - 1, [str(x) for x in p]
    return False, -1, []


def get_blast_radius(g: nx.DiGraph, s: str) -> list[str]:
    if s not in g:
        return []
    res = []
    for n in nx.descendants(g, s):
        d = g.nodes[n]
        if d.get("type") in ("database", "vault", "secrets", "storage") or d.get("criticality") in ("critical", "high"):
            res.append(str(n))
    return res


def get_node_centrality(g: nx.DiGraph, s: str) -> float:
    if s not in g or len(g) <= 2:
        return 0.0
    c = nx.betweenness_centrality(g)
    return round(float(c.get(s, 0.0)), 4)


def extract_node_metrics(g: nx.DiGraph, s: str) -> GraphMetrics:
    exp, h, p = check_external_exposure(g, s)
    b = get_blast_radius(g, s)
    c = get_node_centrality(g, s)
    return GraphMetrics(
        is_exposed=exp,
        hops=h,
        path=p,
        crit_assets=b,
        centrality=c
    )