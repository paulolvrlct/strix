from __future__ import annotations

import importlib
import inspect
import pkgutil

from strix import modules as _modules_pkg
from strix.modules.base import BaseModule


def discover_modules() -> list[BaseModule]:
    """Auto-discover and instantiate every concrete BaseModule in ``strix.modules``.

    The orchestrator never hard-codes module names: dropping a new file into
    ``strix/modules/`` is enough to register it.
    """
    found: dict[str, BaseModule] = {}
    for info in pkgutil.iter_modules(_modules_pkg.__path__):
        if info.name == "base" or info.name.startswith("_"):
            continue
        module = importlib.import_module(f"{_modules_pkg.__name__}.{info.name}")
        for _, obj in inspect.getmembers(module, inspect.isclass):
            if (
                issubclass(obj, BaseModule)
                and obj is not BaseModule
                and not inspect.isabstract(obj)
            ):
                instance = obj()
                found[instance.name] = instance
    return [found[name] for name in sorted(found)]


def modules_for(target_type) -> list[BaseModule]:
    """Return discovered modules that support the given target type."""
    return [m for m in discover_modules() if m.supports(target_type)]
