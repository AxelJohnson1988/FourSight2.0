"""Tests for phoenix_scanner.registry (Phase 1 — PatternRegistry)."""

from __future__ import annotations

import re
from pathlib import Path

import pytest

from phoenix_scanner.patterns import PATTERNS, Pattern
from phoenix_scanner.registry import PatternRegistry, PluginRegistry


# ---------------------------------------------------------------------------
# PluginRegistry — base class
# ---------------------------------------------------------------------------


def test_plugin_registry_register_and_contains():
    reg = PluginRegistry()
    item = Pattern(name="custom", regex=re.compile(r"x"), description="test")
    reg.register(item)
    assert "custom" in reg
    assert len(reg) == 1


def test_plugin_registry_rejects_nameless():
    reg = PluginRegistry()

    class Nameless:
        pass

    with pytest.raises(ValueError, match="non-empty 'name'"):
        reg.register(Nameless())


def test_plugin_registry_rejects_empty_name():
    reg = PluginRegistry()
    item = Pattern(name="", regex=re.compile(r"x"), description="test")
    with pytest.raises(ValueError):
        reg.register(item)


def test_plugin_registry_load_from_file_patterns_list(tmp_path: Path):
    """Module exposes a PATTERNS list — all items should be registered."""
    plugin_file = tmp_path / "my_patterns.py"
    plugin_file.write_text(
        "import re\n"
        "from phoenix_scanner.patterns import Pattern\n"
        "PATTERNS = [\n"
        "    Pattern(name='plugin_sha', regex=re.compile(r'PLUGIN_[0-9]{4}'),\n"
        "            description='plugin test'),\n"
        "]\n"
    )
    reg = PluginRegistry()
    reg.load_from_file(plugin_file)
    assert "plugin_sha" in reg


def test_plugin_registry_load_from_file_top_level_attrs(tmp_path: Path):
    """Module exposes a named Pattern as a top-level attribute (no PATTERNS list)."""
    plugin_file = tmp_path / "attr_pattern.py"
    plugin_file.write_text(
        "import re\n"
        "from phoenix_scanner.patterns import Pattern\n"
        "MY_PATTERN = Pattern(name='attr_pat', regex=re.compile(r'ATTR'),\n"
        "                     description='attr test')\n"
    )
    reg = PluginRegistry()
    reg.load_from_file(plugin_file)
    assert "attr_pat" in reg


def test_plugin_registry_load_from_file_bad_path():
    reg = PluginRegistry()
    with pytest.raises(ImportError):
        reg.load_from_file(Path("/nonexistent/missing.py"))


# ---------------------------------------------------------------------------
# PatternRegistry — built-ins and type validation
# ---------------------------------------------------------------------------


def test_pattern_registry_loads_builtins():
    reg = PatternRegistry()
    assert len(reg) >= len(PATTERNS)
    names = {p.name for p in reg.get_patterns()}
    assert "sha256_hex" in names
    assert "op_return_payload" in names
    assert "ipfs_cidv0" in names


def test_pattern_registry_empty_when_no_builtins():
    reg = PatternRegistry(load_builtins=False)
    assert len(reg) == 0
    assert reg.get_patterns() == []


def test_pattern_registry_rejects_non_pattern():
    reg = PatternRegistry(load_builtins=False)

    class FakeItem:
        name = "fake"

    with pytest.raises(ValueError, match="PatternRegistry only accepts Pattern"):
        reg.register(FakeItem())


def test_pattern_registry_get_patterns_returns_only_patterns():
    reg = PatternRegistry()
    patterns = reg.get_patterns()
    assert all(isinstance(p, Pattern) for p in patterns)


def test_pattern_registry_load_from_dir(tmp_path: Path):
    """load_from_dir registers all patterns from .py files in a directory."""
    (tmp_path / "extra.py").write_text(
        "import re\n"
        "from phoenix_scanner.patterns import Pattern\n"
        "PATTERNS = [\n"
        "    Pattern(name='extra_pat', regex=re.compile(r'EXTRA_[0-9]+'),\n"
        "            description='extra'),\n"
        "]\n"
    )
    reg = PatternRegistry(load_builtins=False)
    reg.load_from_dir(tmp_path)
    assert "extra_pat" in reg


def test_pattern_registry_load_from_dir_alphabetical_order(tmp_path: Path):
    """Files are loaded alphabetically so load order is deterministic."""
    for i in range(3):
        (tmp_path / f"p{i}.py").write_text(
            f"import re\n"
            f"from phoenix_scanner.patterns import Pattern\n"
            f"PATTERNS = [\n"
            f"    Pattern(name='pat_{i}', regex=re.compile(r'X{i}'),\n"
            f"            description='p{i}'),\n"
            f"]\n"
        )
    reg = PatternRegistry(load_builtins=False)
    reg.load_from_dir(tmp_path)
    assert len(reg) == 3
    for i in range(3):
        assert f"pat_{i}" in reg


def test_pattern_registry_load_from_dir_bad_file_skipped(tmp_path: Path):
    """A broken plugin file is logged and skipped; valid files still load."""
    (tmp_path / "a_broken.py").write_text("raise RuntimeError('bad plugin')\n")
    (tmp_path / "b_good.py").write_text(
        "import re\n"
        "from phoenix_scanner.patterns import Pattern\n"
        "PATTERNS = [\n"
        "    Pattern(name='good_pat', regex=re.compile(r'GOOD'),\n"
        "            description='good'),\n"
        "]\n"
    )
    reg = PatternRegistry(load_builtins=False)
    reg.load_from_dir(tmp_path)  # must not raise
    assert "good_pat" in reg


def test_pattern_registry_load_from_dir_nonexistent_raises(tmp_path: Path):
    reg = PatternRegistry(load_builtins=False)
    with pytest.raises(NotADirectoryError):
        reg.load_from_dir(tmp_path / "does_not_exist")


def test_pattern_registry_duplicate_name_overwrites():
    """Re-registering the same name replaces the previous entry (last-wins)."""
    reg = PatternRegistry(load_builtins=False)
    p1 = Pattern(name="dup", regex=re.compile(r"A"), description="first")
    p2 = Pattern(name="dup", regex=re.compile(r"B"), description="second")
    reg.register(p1)
    reg.register(p2)
    assert len(reg) == 1
    assert reg.get_patterns()[0].description == "second"
