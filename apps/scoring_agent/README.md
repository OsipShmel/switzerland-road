#  Scoring Agent

Микросервис контекстного скоринга уязвимостей (SAST) на основе топологии сетевого графа микросервисов (`NetworkX`) и больших языковых моделей (`LLM`).

Сервис фильтрует ложные срабатывания (*False Positives*), обогащает находки статического анализа топологическим контекстом (внешняя доступность, кратчайший путь до интернет-шлюзов, близость к базам данных и хранилищам секретов) и формирует приоритизированную очередь объектов `VLSObject` для динамической верификации агентом-пентестером (DAST).

---

## Стек технологий

- **Язык**: Python 3.14
- **Пакетный менеджер / Сборщик**: Astral `uv` (`pyproject.toml` workspace)
- **API фреймворк**: FastAPI + Uvicorn
- **Топологический анализ**: NetworkX
- **Валидация схем**: Pydantic v2
- **LLM Интеграция**: OpenAI API (Structured Outputs / JSON Schema)
- **Контейнеризация**: Docker (Multi-stage uv build) & Docker Compose

---

## Сетап проекта

```
apps/scoring_agent/
├── src/
│   └── scoring_agent/
│       ├── __init__.py
│       ├── agent.py            # Логика взаимодействия с LLM и скоринговый пайплайн
│       ├── app.py              # FastAPI веб-сервер и HTTP-эндпоинты
│       ├── config.py           # Загрузка и валидация переменных окружения
│       ├── graph_tools.py      # Алгоритмы топологического анализа NetworkX
│       └── schemas.py          # Pydantic v2 схемы (контракт VLSObject и API)
├── test_data/
│   ├── sast_report.json        # Пример отчета статического анализа (Semgrep)
│   └── topology.json           # Архитектурный граф сервисов (nodes & edges)
├── .dockerignore               # Исключения контекста сборки Docker
├── .env.example                # Шаблон конфигурации окружения
├── docker-compose.yml          # Локальная оркестрация сервиса
├── Dockerfile                  # Быстрая сборка контейнера через uv
├── pyproject.toml              # Метаданные пакета и зависимости uv
├── uv.lock                     # Зафиксированное дерево точных версий зависимостей
└── README.md                   # Документация модуля
```

---

## Переменные окружения (.env)

Для работы агента скоринга требуется настроить файл `.env` в корне сервиса:

```env
OPENAI_API_KEY=...
OPENAI_BASE_URL=...
MODEL_NAME=...
SCORE_THRESHOLD=4.0
```

---

## Запуск и развертывание

### Вариант 1: Запуск через Docker Compose

1. Собрать образ и запустить контейнер в фоновом режиме:
   ```
   docker compose up -d --build
   ```
2. Просмотр логов в реальном времени:
   ```
   docker compose logs -f
   ```
3. Остановка сервиса:
   ```
   docker compose down
   ```

### Вариант 2: Локальный запуск через `uv`

1. Установка точных версий зависимостей из uv.lock:
   ```
   uv sync
   ```
2. Запуск сервиса:
   ```
   uv run uvicorn src.scoring_agent.app:app --reload --port 8000
   ```

---

## Контракт взаимодействия (API Спецификация)

Интерактивная документация Swagger UI доступна по адресу:  
`http://localhost:8000/docs`

### Эндпоинты

#### 1. `GET /health`
Проверка готовности сервиса к обработке запросов.
- **Ответ (`200 OK`)**:
  ```json
  {
    "status": "ok"
  }
  ```

#### 2. `POST /api/v1/score`
Основной эндпоинт скоринга и генерации гипотез.

**Входные данные (`Request Body`):**
```json
{
  "sast_report": [
    {
      "task_id": "vuln-001",
      "service_name": "billing_svc",
      "title": "SQL Injection in invoice export",
      "rule_id": "python.lang.security.audit.sqli",
      "file_path": "services/billing/views.py",
      "line": 84,
      "code_snippet": "query = f\"SELECT * FROM invoices WHERE id = '{req.params.get('id')}'\"",
      "raw_score": 8.5
    }
  ],
  "topology": {
    "nodes": [
      {"id": "api_gw", "type": "gateway", "zone": "public"},
      {"id": "billing_svc", "type": "service", "zone": "internal"},
      {"id": "payments_vault", "type": "vault", "criticality": "critical"}
    ],
    "edges": [
      {"source": "api_gw", "target": "billing_svc"},
      {"source": "billing_svc", "target": "payments_vault"}
    ]
  }
}
```

**Формат ответа (`Response Body` / Очередь для DAST):**
```json
{
  "total_count": 1,
  "discarded_count": 0,
  "queue": [
    {
      "vulnerability_id": "vuln-001",
      "title": "SQL Injection in invoice export",
      "status": "unchecked",
      "verdict": null,
      "confirmed_by": null,
      "sast": {
        "tool": "semgrep",
        "rule_id": "python.lang.security.audit.sqli",
        "file_path": "services/billing/views.py",
        "line": 84,
        "score": 9.5,
        "code_snippet": "query = f\"SELECT * FROM invoices WHERE id = '{req.params.get('id')}'\""
      },
      "target": {
        "endpoint": "/billing/invoice/export",
        "method": "GET",
        "param": "id"
      },
      "hypothesis": "Злоумышленник может внедрить SQL-код через параметр id в запросе к эндпоинту экспорта счетов для извлечения конфиденциальных данных.",
      "verification_history": {
        "dast": {
          "run_executed": false
        }
      }
    }
  ],
  "discarded": []
}
```

---

## Архитектурная логика пайплайна

1. **Топологический анализ (`graph_tools.py`)**:
   - Построение направленного графа инфраструктуры через `networkx.DiGraph`.
   - Определение внешней доступности (`is_exposed`, расчет кратчайшего пути от шлюзов `gateway`).
   - Расчет метрик центральности (`betweenness_centrality`, `degree_centrality`).
   - Идентификация достижимости критических активов (`vault`, `database`, `auth`).
2. **Семантическая верификация (`agent.py`)**:
   - Оценка исходного кода на предмет санитизации и экранирования.
   - Детекция ложных срабатываний (`is_false_positive`).
   - Корректировка CVSS-балла с учетом графовых метрик (хопы, изоляция, blast radius).
   - Извлечение сетевых координат уязвимости (`endpoint`, `method`, `param`).
   - Формирование верификационной гипотезы для пентест-агента.
3. **Формирование очереди верификации**:
   - Отсев находок ниже `SCORE_THRESHOLD` в массив `discarded`.
   - Ранжирование очереди `queue` по убыванию итогового контекстного скора.