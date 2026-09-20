"""Composite Keenetic client combining HTTP transport, telemetry, policies, filtering, and packet capture."""
import logging
from typing import Any
from keenguard.core.keenetic.base import KeeneticBaseClient
from keenguard.core.keenetic.telemetry import KeeneticTelemetryMixin
from keenguard.core.keenetic.policies import KeeneticPoliciesMixin
from keenguard.core.keenetic.filtering import KeeneticFilteringMixin
from keenguard.core.keenetic.capture import KeeneticCaptureMixin

logger = logging.getLogger("keenguard.keenetic.client")


class KeeneticClient(
    KeeneticBaseClient,
    KeeneticTelemetryMixin,
    KeeneticPoliciesMixin,
    KeeneticFilteringMixin,
    KeeneticCaptureMixin
):
    """Full-featured asynchronous KeeneticOS RCI client."""
    pass


keenetic_client = KeeneticClient()


def _on_router_config_change(key: str, value: Any) -> None:
    if key == "router_host" and value:
        keenetic_client.host = str(value)
        keenetic_client.base_url = f"{keenetic_client.schema}://{keenetic_client.host}:{keenetic_client.port}"
        keenetic_client.router_ips.add(str(value))
    elif key == "router_port" and value is not None:
        try:
            keenetic_client.port = int(value)
            keenetic_client.base_url = f"{keenetic_client.schema}://{keenetic_client.host}:{keenetic_client.port}"
        except (ValueError, TypeError):
            pass
    elif key == "router_user" and value:
        keenetic_client.user = str(value)
    elif key == "router_password" and value is not None:
        keenetic_client.password = str(value)
    elif key == "router_use_https" and value is not None:
        keenetic_client.use_https = bool(value)
        keenetic_client.schema = "https" if keenetic_client.use_https else "http"
        keenetic_client.base_url = f"{keenetic_client.schema}://{keenetic_client.host}:{keenetic_client.port}"


try:
    from keenguard.core.config_service import config_service
    for _k in ("router_host", "router_port", "router_user", "router_password", "router_use_https"):
        config_service.subscribe(_k, _on_router_config_change)
except ImportError:
    pass
