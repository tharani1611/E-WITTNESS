"""Application liveness and readiness domain service (Phases 06-07).

Contains zero HTTP framework dependencies (`fastapi`/`starlette`). Evaluates
process liveness and executes any registered asynchronous readiness probes while
honestly reporting `not_checked` for unconfigured infrastructure adapters.
"""

from __future__ import annotations

from collections.abc import Awaitable, Callable, Mapping

from backend.app.config.settings import Settings
from backend.app.core.logging import get_logger
from backend.app.schemas.health import (
    DependencyCheckStatus,
    LivenessResponse,
    ReadinessResponse,
)

ReadinessProbe = Callable[[], Awaitable[bool]]

EXPECTED_INFRASTRUCTURE_COMPONENTS: tuple[str, ...] = (
    "database",
    "redis",
    "object_storage",
)

logger = get_logger("services.health")


class HealthService:
    """Evaluates application liveness and infrastructure readiness."""

    def __init__(
        self,
        settings: Settings,
        probes: Mapping[str, ReadinessProbe] | None = None,
    ) -> None:
        self._settings = settings
        self._probes: dict[str, ReadinessProbe] = dict(probes) if probes else {}

    def get_liveness(self) -> LivenessResponse:
        """Return safe application liveness metadata without exposing secrets."""
        return LivenessResponse(
            status="ok",
            service=self._settings.APP_NAME,
            version=self._settings.APP_VERSION,
            environment=str(self._settings.ENVIRONMENT),
        )

    async def evaluate_readiness(self) -> ReadinessResponse:
        """Execute registered dependency probes and report truthful readiness status."""
        checks: dict[str, DependencyCheckStatus] = {}
        any_failed = False
        all_checked = True

        component_names = list(EXPECTED_INFRASTRUCTURE_COMPONENTS)
        for extra_name in self._probes:
            if extra_name not in component_names:
                component_names.append(extra_name)

        for component in component_names:
            probe = self._probes.get(component)
            if probe is None:
                checks[component] = DependencyCheckStatus.NOT_CHECKED
                all_checked = False
                continue

            try:
                is_ok = await probe()
            except Exception as exc:
                logger.warning(
                    "Readiness probe failed with exception",
                    extra={"component": component, "error_type": type(exc).__name__},
                )
                is_ok = False

            if is_ok:
                checks[component] = DependencyCheckStatus.READY
            else:
                checks[component] = DependencyCheckStatus.UNAVAILABLE
                any_failed = True

        if any_failed:
            return ReadinessResponse(
                status="degraded",
                ready=False,
                checks=checks,
                message="One or more registered infrastructure readiness checks failed.",
            )

        if not all_checked:
            return ReadinessResponse(
                status="unverified",
                ready=True,
                checks=checks,
                message=(
                    "Application process is ready; one or more infrastructure adapters "
                    "have no active readiness probe registered in this phase."
                ),
            )

        return ReadinessResponse(
            status="ok",
            ready=True,
            checks=checks,
            message="All registered infrastructure readiness checks passed.",
        )
