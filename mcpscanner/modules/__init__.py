from .base import BaseAttackModule
from .description_poison import DescriptionPoisonModule
from .schema_injection import SchemaInjectionModule
from .scope_creep import ScopeCreepModule
from .privilege_bleed import PrivilegeBleedModule
from .tool_chain_abuse import ToolChainAbuseModule
from .live_probe import LiveProbeModule
from .multi_step_probe import MultiStepAttackProbe
from .tool_argument_injection import ToolArgumentInjectionProbe
from .agentic_probe import AgenticAttackProbe

ALL_STATIC_MODULES = [
    DescriptionPoisonModule,
    SchemaInjectionModule,
    ScopeCreepModule,
    PrivilegeBleedModule,
    ToolChainAbuseModule,
]

# Modules enabled by --live (single-turn / scripted dynamic probes).
ALL_DYNAMIC_MODULES = [
    LiveProbeModule,
    MultiStepAttackProbe,
    ToolArgumentInjectionProbe,
]

# Agentic module is gated by its own --agentic flag (separate cost profile).
ALL_AGENTIC_MODULES = [
    AgenticAttackProbe,
]

MODULE_REGISTRY: dict[str, type[BaseAttackModule]] = {
    "description_poison": DescriptionPoisonModule,
    "schema_injection": SchemaInjectionModule,
    "scope_creep": ScopeCreepModule,
    "privilege_bleed": PrivilegeBleedModule,
    "tool_chain_abuse": ToolChainAbuseModule,
    "live_probe": LiveProbeModule,
    "multi_step_probe": MultiStepAttackProbe,
    "tool_argument_injection": ToolArgumentInjectionProbe,
    "agentic_probe": AgenticAttackProbe,
}

__all__ = [
    "BaseAttackModule",
    "DescriptionPoisonModule",
    "SchemaInjectionModule",
    "ScopeCreepModule",
    "PrivilegeBleedModule",
    "ToolChainAbuseModule",
    "LiveProbeModule",
    "MultiStepAttackProbe",
    "ToolArgumentInjectionProbe",
    "AgenticAttackProbe",
    "ALL_STATIC_MODULES",
    "ALL_DYNAMIC_MODULES",
    "ALL_AGENTIC_MODULES",
    "MODULE_REGISTRY",
]
