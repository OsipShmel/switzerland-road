from __future__ import annotations
from pydantic import BaseModel, ConfigDict, Field


class CheckSecretFlagRequest(BaseModel):
    model_config = ConfigDict(frozen=True, extra="forbid")
    flag: str = Field(min_length=1)


class CheckSecretFlagResponse(BaseModel):
    model_config = ConfigDict(frozen=True, extra="forbid")
    valid: bool