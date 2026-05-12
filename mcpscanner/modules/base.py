from __future__ import annotations
from abc import ABC, abstractmethod
from ..models import Finding, ToolSchema


class BaseAttackModule(ABC):
    name: str = ""

    @abstractmethod
    def run(self, schemas: list[ToolSchema]) -> list[Finding]:
        ...
