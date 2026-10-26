"""AST-based architectural boundary and coding standard verifier (Phase 07).

Enforces E-WITNESS layered architecture rules without external dependencies:
1. Unidirectional layer import boundaries (`api`, `services`, `repositories`,
   `models`, `schemas`, `config`, `core`, `infrastructure`, `ai_services`).
2. Prohibition of direct `os.environ` / `os.getenv` access outside `backend/app/config/`.
3. Prohibition of blocking `time.sleep()` calls inside `async def` functions.
"""

from __future__ import annotations

import ast
from dataclasses import dataclass
from pathlib import Path

LAYER_FORBIDDEN_IMPORTS: dict[str, tuple[str, ...]] = {
    "api": (
        "backend.app.models",
        "backend.app.repositories",
        "sqlalchemy",
    ),
    "middleware": (
        "backend.app.models",
        "backend.app.repositories",
        "backend.app.services",
        "sqlalchemy",
    ),
    "services": (
        "fastapi",
        "starlette",
        "backend.app.api",
        "backend.app.middleware",
    ),
    "repositories": (
        "fastapi",
        "starlette",
        "backend.app.api",
        "backend.app.services",
        "backend.app.schemas",
        "backend.app.middleware",
    ),
    "models": (
        "fastapi",
        "starlette",
        "backend.app.api",
        "backend.app.services",
        "backend.app.repositories",
        "backend.app.schemas",
        "backend.app.middleware",
    ),
    "schemas": (
        "fastapi",
        "starlette",
        "sqlalchemy",
        "backend.app.api",
        "backend.app.services",
        "backend.app.repositories",
        "backend.app.models",
        "backend.app.infrastructure",
        "backend.app.middleware",
    ),
    "config": (
        "fastapi",
        "starlette",
        "sqlalchemy",
        "backend.app.api",
        "backend.app.services",
        "backend.app.repositories",
        "backend.app.models",
        "backend.app.schemas",
        "backend.app.infrastructure",
        "backend.app.middleware",
        "ai_services",
    ),
    "core": (
        "fastapi",
        "starlette",
        "sqlalchemy",
        "backend.app.api",
        "backend.app.services",
        "backend.app.repositories",
        "backend.app.models",
        "backend.app.schemas",
        "backend.app.infrastructure",
        "backend.app.middleware",
        "ai_services",
    ),
    "infrastructure": (
        "fastapi",
        "starlette",
        "backend.app.api",
        "backend.app.services",
        "backend.app.schemas",
        "backend.app.middleware",
    ),
    "ai_services": (
        "fastapi",
        "starlette",
        "sqlalchemy",
        "backend.app.api",
        "backend.app.repositories",
        "backend.app.models",
        "backend.app.middleware",
    ),
}


@dataclass(frozen=True)
class ArchitectureViolation:
    """Represents a single architectural boundary or coding standard violation."""

    module_path: str
    layer: str
    line: int
    rule_id: str
    message: str


def _matches_prefix(target: str, forbidden_prefix: str) -> bool:
    return target == forbidden_prefix or target.startswith(f"{forbidden_prefix}.")


class _ArchitectureVisitor(ast.NodeVisitor):
    """AST visitor that detects forbidden imports, raw env access, and async blocking calls."""

    def __init__(self, *, layer: str, module_path: str) -> None:
        self.layer = layer
        self.module_path = module_path
        self.forbidden_prefixes = LAYER_FORBIDDEN_IMPORTS.get(layer, ())
        self.violations: list[ArchitectureViolation] = []
        self._in_type_checking_block = False
        self._async_depth = 0

    def visit_If(self, node: ast.If) -> None:
        is_type_checking = (
            isinstance(node.test, ast.Name) and node.test.id == "TYPE_CHECKING"
        ) or (isinstance(node.test, ast.Attribute) and node.test.attr == "TYPE_CHECKING")
        if is_type_checking:
            prev = self._in_type_checking_block
            self._in_type_checking_block = True
            for child in node.body:
                self.visit(child)
            self._in_type_checking_block = prev
            for child in node.orelse:
                self.visit(child)
            return
        self.generic_visit(node)

    def visit_Import(self, node: ast.Import) -> None:
        if not self._in_type_checking_block:
            for alias in node.names:
                self._check_import_target(alias.name, node.lineno)
        self.generic_visit(node)

    def visit_ImportFrom(self, node: ast.ImportFrom) -> None:
        if not self._in_type_checking_block and node.module:
            self._check_import_target(node.module, node.lineno)
            for alias in node.names:
                full_target = f"{node.module}.{alias.name}"
                self._check_import_target(full_target, node.lineno)
                if (
                    node.module == "os"
                    and alias.name in {"environ", "getenv"}
                    and self.layer != "config"
                ):
                    self.violations.append(
                        ArchitectureViolation(
                            module_path=self.module_path,
                            layer=self.layer,
                            line=node.lineno,
                            rule_id="ARCH-SEC-ENV",
                            message=(
                                f"Direct import of 'os.{alias.name}' in layer '{self.layer}' is "
                                "forbidden; use validated Settings from 'backend.app.config'."
                            ),
                        )
                    )
        self.generic_visit(node)

    def visit_Attribute(self, node: ast.Attribute) -> None:
        if (
            self.layer != "config"
            and isinstance(node.value, ast.Name)
            and node.value.id == "os"
            and node.attr in {"environ", "getenv"}
        ):
            self.violations.append(
                ArchitectureViolation(
                    module_path=self.module_path,
                    layer=self.layer,
                    line=node.lineno,
                    rule_id="ARCH-SEC-ENV",
                    message=(
                        f"Direct access to 'os.{node.attr}' in layer '{self.layer}' is "
                        "forbidden; use validated Settings from 'backend.app.config'."
                    ),
                )
            )
        self.generic_visit(node)

    def visit_AsyncFunctionDef(self, node: ast.AsyncFunctionDef) -> None:
        self._async_depth += 1
        self.generic_visit(node)
        self._async_depth -= 1

    def visit_Call(self, node: ast.Call) -> None:
        if self._async_depth > 0:
            is_time_sleep = (
                isinstance(node.func, ast.Attribute)
                and isinstance(node.func.value, ast.Name)
                and node.func.value.id == "time"
                and node.func.attr == "sleep"
            ) or (isinstance(node.func, ast.Name) and node.func.id == "sleep")
            if is_time_sleep:
                self.violations.append(
                    ArchitectureViolation(
                        module_path=self.module_path,
                        layer=self.layer,
                        line=node.lineno,
                        rule_id="ARCH-ASYNC-BLOCK",
                        message=(
                            "Blocking 'time.sleep()' call inside an 'async def' function is "
                            "forbidden; use 'await asyncio.sleep()' if delay is required."
                        ),
                    )
                )
        self.generic_visit(node)

    def _check_import_target(self, target: str, lineno: int) -> None:
        for forbidden in self.forbidden_prefixes:
            if _matches_prefix(target, forbidden):
                self.violations.append(
                    ArchitectureViolation(
                        module_path=self.module_path,
                        layer=self.layer,
                        line=lineno,
                        rule_id="ARCH-LAYER-IMPORT",
                        message=(
                            f"Layer '{self.layer}' is not permitted to import '{target}' "
                            f"(violates forbidden dependency '{forbidden}')."
                        ),
                    )
                )
                return


def check_source_architecture(
    source_code: str,
    *,
    layer: str,
    module_path: str = "<memory>",
) -> list[ArchitectureViolation]:
    """Parse ``source_code`` and return any architectural boundary violations."""
    tree = ast.parse(source_code, filename=module_path)
    visitor = _ArchitectureVisitor(layer=layer, module_path=module_path)
    visitor.visit(tree)
    return visitor.violations


def infer_layer_for_path(file_path: Path, root_dir: Path) -> str | None:
    """Determine the architectural layer name for a project Python file."""
    rel = file_path.resolve().relative_to(root_dir.resolve())
    parts = rel.parts
    if not parts:
        return None
    if parts[0] == "ai_services":
        return "ai_services"
    if len(parts) >= 3 and parts[0] == "backend" and parts[1] == "app":
        sub = parts[2]
        if sub in LAYER_FORBIDDEN_IMPORTS:
            return sub
    return None


def scan_project_architecture(root_dir: Path) -> list[ArchitectureViolation]:
    """Scan all Python modules under ``backend/app`` and ``ai_services`` for violations."""
    violations: list[ArchitectureViolation] = []
    scan_roots = [root_dir / "backend" / "app", root_dir / "ai_services"]
    for scan_root in scan_roots:
        if not scan_root.exists():
            continue
        for py_file in sorted(scan_root.rglob("*.py")):
            layer = infer_layer_for_path(py_file, root_dir)
            if layer is None:
                continue
            rel_str = py_file.relative_to(root_dir).as_posix()
            source = py_file.read_text(encoding="utf-8")
            violations.extend(check_source_architecture(source, layer=layer, module_path=rel_str))
    return violations
