from __future__ import annotations

from enum import StrEnum
from typing import Any
from pydantic import BaseModel, ConfigDict, Field


class LogLevel(StrEnum):
    MODEL = "model"      # рассуждения, респонсы модели(контекст)
    DEBUG = "debug"      # дебаг лог, несущий доп нагрузку(результаты запроса и тп)
    INFO = "info"        # инфо о событии(старт/финиш тулкола)
    WARNING = "warning"
    ERROR = "error"


class ExplicitLogContext(StrEnum):
    """Контекст, который агент МОЖЕТ указать явно при необходимости.
    напоминаю что 'check' сюда не входит — он определяется sandboxd по активной сессии,
    агент не имеет права его подделать явным указанием"""
    GLOBAL = "global"


class AgentLog(BaseModel):
    """Request-модель метода log() — за подробностями иди в контракт, секция 10"""
    model_config = ConfigDict(frozen=True, extra="forbid")

    level: LogLevel
    event: str = Field(min_length=1)
    message: str = Field(default="")
    metadata: dict[str, Any] = Field(default_factory=dict)
    context: ExplicitLogContext | None = None


class AgentLogAcceptedResponse(BaseModel):
    model_config = ConfigDict(frozen=True, extra="forbid")
    accepted: bool = True