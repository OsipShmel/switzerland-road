FROM python:3.14-slim

WORKDIR /app

# Установка uv для сверхбыстрой сборки
COPY --from=ghcr.io/astral-sh/uv:latest /uv /bin/uv

# Установка зависимостей из pyproject.toml
COPY pyproject.toml .
RUN uv pip install --system -r pyproject.toml

# Копирование исходного кода
COPY . .

EXPOSE 8000

# Запуск приложения из структуры src
CMD ["uvicorn", "src.scoring_agent.app:app", "--host", "0.0.0.0", "--port", "8000"]