from .base import BaseAttackModule
from .description_poison import DescriptionPoisonModule
from .schema_injection import SchemaInjectionModule
from .scope_creep import ScopeCreepModule
from .privilege_bleed import PrivilegeBleedModule
from .live_probe import LiveProbeModule

ALL_STATIC_MODULES = [
    DescriptionPoisonModule,
    SchemaInjectionModule,
    ScopeCreepModule,
    PrivilegeBleedModule,
]

MODULE_REGISTRY: dict[str, type[BaseAttackModule]] = {
    "description_poison": DescriptionPoisonModule,
    "schema_injection": SchemaInjectionModule,
    "scope_creep": ScopeCreepModule,
    "privilege_bleed": PrivilegeBleedModule,
    "live_probe": LiveProbeModule,
}

__all__ = [
    "BaseAttackModule",
    "DescriptionPoisonModule",
    "SchemaInjectionModule",
    "ScopeCreepModule",
    "PrivilegeBleedModule",
    "LiveProbeModule",
    "ALL_STATIC_MODULES",
    "MODULE_REGISTRY",
]
