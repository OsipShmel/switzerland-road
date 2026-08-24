import json
import networkx as nx
from openai import OpenAI
from src.scoring_agent.config import API_KEY, BASE_URL, MODEL, THRESHOLD
from src.scoring_agent.graph_tools import extract_node_metrics
from src.scoring_agent.schemas import (
    LLMScoringResponse,
    ScoringPipelineResult,
    VLSObject,
    SastBlock,
    VerificationHistory
)


SYS_PROMPT = """Ты — экспертная система анализа защищенности (AppSec). Твоя задача — проводить контекстный скоринг уязвимостей от SAST на основе сниппета кода и топологии сети.

Правила анализа:
1. Фильтрация False Positive: если в коде видна строгая санитизация (приведение типов, ORM, регулярки) или сервис полностью изолирован в сети (is_exposed=False и нет пути), установи is_false_positive=True, context_score < 4.0 и укажи причину в discard_reason.
2. Базовая иерархия уязвимостей: RCE / Command Injection > SQL Injection > SSRF > Path Traversal > XSS > Information Disclosure.
3. Корректировка балла:
   - Внешняя доступность (is_exposed=True, hops <= 1): повышать балл.
   - Достижимость критических БД/секретов (crit_assets не пустой): повышать балл.
   - Высокая центральность (> 0.3): повышать балл.
4. Извлеки точные координаты (target: endpoint, method, param) и сформируй емкую гипотезу для пентестера."""


def load_graph(p: str) -> nx.DiGraph:
    with open(p, "r", encoding="utf-8") as f:
        d = json.load(f)
    g = nx.DiGraph()
    for n in d.get("nodes", []):
        g.add_node(n["id"], **n)
    for e in d.get("edges", []):
        g.add_edge(e["source"], e["target"])
    return g


def load_sast(p: str) -> list[dict]:
    with open(p, "r", encoding="utf-8") as f:
        return json.load(f)


def build_prompt_payload(sast_list: list[dict], g: nx.DiGraph) -> str:
    ctx = []
    for x in sast_list:
        s_name = x.get("service_name", "")
        m = extract_node_metrics(g, s_name)
        ctx.append({
            "task_id": x.get("task_id"),
            "service": s_name,
            "title": x.get("title"),
            "file_path": x.get("file_path"),
            "line": x.get("line"),
            "code_snippet": x.get("code_snippet"),
            "raw_score": x.get("raw_score"),
            "graph_metrics": m.model_dump()
        })
    return json.dumps(ctx, ensure_ascii=False, indent=2)


def run_scoring(sast_path: str, topo_path: str) -> ScoringPipelineResult:
    g = load_graph(topo_path)
    sast_data = load_sast(sast_path)
    payload = build_prompt_payload(sast_data, g)

    cli = OpenAI(api_key=API_KEY, base_url=BASE_URL)
    res = cli.beta.chat.completions.parse(
        model=MODEL,
        messages=[
            {"role": "system", "content": SYS_PROMPT},
            {"role": "user", "content": f"Проанализируй находки:\n{payload}"}
        ],
        response_format=LLMScoringResponse
    )

    parsed = res.choices[0].message.parsed
    if not parsed:
        raise ValueError("LLM parsing error")

    sast_map = {x["task_id"]: x for x in sast_data}

    q: list[VLSObject] = []
    disc = []

    for it in parsed.items:
        if it.is_false_positive or it.context_score < THRESHOLD:
            disc.append(it)
            continue

        raw = sast_map.get(it.task_id, {})
        vls = VLSObject(
            vulnerability_id=it.task_id,
            title=raw.get("title", it.vuln_type),
            status="unchecked",
            verdict=None,
            confirmed_by=None,
            sast=SastBlock(
                tool="semgrep",
                rule_id=raw.get("rule_id", "custom"),
                file_path=raw.get("file_path", ""),
                line=raw.get("line", 0),
                score=it.context_score,
                code_snippet=raw.get("code_snippet")
            ),
            target=it.target,
            hypothesis=it.hypothesis,
            verification_history=VerificationHistory()
        )
        q.append(vls)

    q.sort(key=lambda x: x.sast.score if x.sast else 0.0, reverse=True)

    return ScoringPipelineResult(
        total_count=len(parsed.items),
        discarded_count=len(disc),
        queue=q,
        discarded=disc
    )


if __name__ == "__main__":
    out = run_scoring("test_data/sast_report.json", "test_data/topology.json")
    print(out.model_dump_json(indent=2))