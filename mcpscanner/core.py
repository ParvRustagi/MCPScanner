from __future__ import annotations
import asyncio
from pathlib import Path
from typing import Optional

from .models import ToolSchema
from .report import Report
from .ingestion import ConfigFileIngester, LiveServerIngester
from .modules import (
    BaseAttackModule,
    ALL_STATIC_MODULES,
    ALL_DYNAMIC_MODULES,
    MODULE_REGISTRY,
    LiveProbeModule,
    MultiStepAttackProbe,
    ToolArgumentInjectionProbe,
    AgenticAttackProbe,
)


class MCPScanner:
    def __init__(
        self,
        target: str,
        modules: Optional[list[BaseAttackModule]] = None,
        live: bool = False,
        agentic: bool = False,
        allow_execution: bool = False,
        attacker_provider: str = "anthropic",
        attacker_model: str = "claude-sonnet-4-6",
        max_steps: int = 6,
        module_names: Optional[list[str]] = None,
    ) -> None:
        self.target = target
        self.live = live
        self.agentic = agentic
        self.allow_execution = allow_execution
        self.attacker_provider = attacker_provider
        self.attacker_model = attacker_model
        self.max_steps = max_steps

        if modules is not None:
            self._modules = modules
        elif module_names:
            self._modules = [MODULE_REGISTRY[n]() for n in module_names if n in MODULE_REGISTRY]
        else:
            self._modules = [cls() for cls in ALL_STATIC_MODULES]
            if live:
                self._modules.append(LiveProbeModule(attacker_model=attacker_model, provider=attacker_provider))
                self._modules.append(MultiStepAttackProbe(attacker_model=attacker_model, provider=attacker_provider))
                self._modules.append(ToolArgumentInjectionProbe(attacker_model=attacker_model, provider=attacker_provider))
            if agentic:
                self._modules.append(AgenticAttackProbe(
                    attacker_model=attacker_model,
                    provider=attacker_provider,
                    target=target,
                    allow_execution=allow_execution,
                    max_steps=max_steps,
                ))

    def run(self) -> Report:
        tools = asyncio.run(self._ingest())
        findings = []
        for module in self._modules:
            findings.extend(module.run(tools))
        return Report(target=self.target, tools=tools, findings=findings)

    def run_all(self) -> Report:
        all_modules = [cls() for cls in ALL_STATIC_MODULES]
        all_modules.append(LiveProbeModule(attacker_model=self.attacker_model))
        self._modules = all_modules
        return self.run()

    async def _ingest(self) -> list[ToolSchema]:
        target = self.target
        if target.startswith("http://") or target.startswith("https://"):
            ingester = LiveServerIngester(url=target)
        else:
            ingester = ConfigFileIngester(config_path=target)
        return await ingester.ingest()
