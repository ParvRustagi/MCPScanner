from __future__ import annotations
from abc import ABC, abstractmethod
from ..models import ToolSchema


class BaseIngester(ABC):
    @abstractmethod
    async def ingest(self) -> list[ToolSchema]:
        """Connect to target and return all discovered tool schemas."""
        ...
