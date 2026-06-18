"""PatternRegistry and PluginRegistry — hot-loadable extension registries.

These classes form the Phase 1 extensibility layer of FourSight 2.0.  Users
can ship ``.py`` files that expose a module-level ``PATTERNS`` list and load
them at runtime via :meth:`PatternRegistry.load_from_dir`, without forking
or modifying the core package.

Example
-------
Provide a directory of custom patterns::

    from pathlib import Path
    from phoenix_scanner.registry import PatternRegistry

    reg = PatternRegistry()                       # starts with all built-ins
    reg.load_from_dir(Path("./custom_patterns"))  # hot-loads extra .py files
    print(reg.get_patterns())
"""

from __future__ import annotations

import importlib.util
import logging
from pathlib import Path
from typing import Any

from phoenix_scanner.patterns import PATTERNS, Pattern

logger = logging.getLogger(__name__)


class PluginRegistry:
    """A simple name-keyed registry for validated extension objects.

    Items must expose a non-empty ``name`` string attribute.  Subclasses
    override :meth:`_validate` to add type-specific checks.
    """

    def __init__(self) -> None:
        self._items: dict[str, Any] = {}

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------

    def register(self, item: Any) -> None:
        """Validate and add *item* to the registry.

        Parameters
        ----------
        item:
            Any object with a non-empty ``name`` string attribute.

        Raises
        ------
        ValueError
            If *item* lacks a valid ``name`` attribute or if
            :meth:`_validate` rejects it.
        """
        name = getattr(item, "name", None)
        if not name or not isinstance(name, str):
            raise ValueError(
                f"Registry items must have a non-empty 'name' string attribute; "
                f"got {item!r}"
            )
        self._validate(item)
        self._items[name] = item
        logger.debug("Registered %s: %r", type(item).__name__, name)

    def load_from_file(self, path: Path) -> None:
        """Dynamically import a Python module and register all items it exports.

        The module may expose items via:

        * A module-level ``PATTERNS`` list (preferred).
        * Any top-level attribute that carries a ``name`` string (fallback).

        Parameters
        ----------
        path:
            Path to a ``.py`` source file.

        Raises
        ------
        ImportError
            If the module cannot be created or executed.
        """
        spec = importlib.util.spec_from_file_location(path.stem, path)
        if spec is None or spec.loader is None:
            raise ImportError(f"Cannot create module spec from {path}")
        if not path.exists():
            raise ImportError(f"File not found: {path}")
        module = importlib.util.module_from_spec(spec)
        try:
            spec.loader.exec_module(module)  # type: ignore[union-attr]
        except FileNotFoundError as exc:
            raise ImportError(f"File not found: {path}") from exc

        loaded = 0
        if hasattr(module, "PATTERNS") and isinstance(module.PATTERNS, list):
            for item in module.PATTERNS:
                try:
                    self.register(item)
                    loaded += 1
                except (ValueError, TypeError) as exc:
                    logger.warning("Skipping item in %s PATTERNS: %s", path.name, exc)
        else:
            for attr_name in dir(module):
                if attr_name.startswith("_"):
                    continue
                obj = getattr(module, attr_name)
                name_attr = getattr(obj, "name", None)
                if name_attr and isinstance(name_attr, str) and name_attr not in self._items:
                    try:
                        self.register(obj)
                        loaded += 1
                    except (ValueError, TypeError) as exc:
                        logger.warning(
                            "Skipping attribute %s in %s: %s", attr_name, path.name, exc
                        )

        logger.info("Loaded %d item(s) from %s", loaded, path.name)

    # ------------------------------------------------------------------
    # Dunder helpers
    # ------------------------------------------------------------------

    def __len__(self) -> int:
        return len(self._items)

    def __contains__(self, name: str) -> bool:
        return name in self._items

    # ------------------------------------------------------------------
    # Overridable hook
    # ------------------------------------------------------------------

    def _validate(self, item: Any) -> None:
        """Override in subclasses to add type-specific validation."""


class PatternRegistry(PluginRegistry):
    """Specialized registry for :class:`~phoenix_scanner.patterns.Pattern` objects.

    By default all built-in :data:`~phoenix_scanner.patterns.PATTERNS` are
    pre-loaded.  Set ``load_builtins=False`` to start with an empty registry
    (useful in tests or for fully custom pattern sets).

    Parameters
    ----------
    load_builtins:
        When ``True`` (default), all built-in patterns are registered
        immediately on construction.

    Examples
    --------
    >>> reg = PatternRegistry()
    >>> "sha256_hex" in reg
    True
    >>> reg.load_from_dir(Path("./my_patterns"))
    """

    def __init__(self, *, load_builtins: bool = True) -> None:
        super().__init__()
        if load_builtins:
            for pattern in PATTERNS:
                self.register(pattern)

    def _validate(self, item: Any) -> None:
        if not isinstance(item, Pattern):
            raise ValueError(
                f"PatternRegistry only accepts Pattern objects; "
                f"got {type(item).__name__}"
            )

    def load_from_dir(self, directory: Path) -> None:
        """Load all ``*.py`` files in *directory* into this registry.

        Files are loaded in alphabetical order for determinism.  A failure
        in one file does not prevent subsequent files from loading.

        Parameters
        ----------
        directory:
            Path to a directory containing Python plugin files.

        Raises
        ------
        NotADirectoryError
            If *directory* does not exist or is not a directory.
        """
        if not directory.is_dir():
            raise NotADirectoryError(f"patterns-dir does not exist: {directory}")
        for py_file in sorted(directory.glob("*.py")):
            try:
                self.load_from_file(py_file)
            except Exception as exc:  # noqa: BLE001
                logger.warning("Failed to load patterns from %s: %s", py_file.name, exc)

    def get_patterns(self) -> list[Pattern]:
        """Return all registered :class:`Pattern` objects in registration order."""
        return [item for item in self._items.values() if isinstance(item, Pattern)]
