"""
Unified Reactive Configuration Service for KeenGuard.
Provides a single source of truth for runtime parameters, eliminating configuration drift
between .env, SQLite (app_settings), in-memory Pydantic Settings, and core singletons.
"""
import json
import logging
from pathlib import Path
from typing import Any, Dict, Optional, Callable, List

from keenguard.config import (
    settings as pydantic_settings,
    Settings,
    save_env_router_credentials,
    save_env_telegram_settings,
    save_env_dns_provider_settings,
)

logger = logging.getLogger("keenguard.config_service")

_UNSET = object()


class ConfigService:
    """
    Unified reactive configuration service.
    Priority: SQLite (app_settings) > .env environment variables > Pydantic defaults.
    """

    def __init__(self, settings_instance: Settings = pydantic_settings):
        # Use object.__setattr__ to avoid triggering custom __setattr__ during init
        object.__setattr__(self, "_settings", settings_instance)
        object.__setattr__(self, "_cache", dict(settings_instance.model_dump()))
        object.__setattr__(self, "_subscribers", {})
        object.__setattr__(self, "_initialized", False)

    @property
    def is_initialized(self) -> bool:
        return self._initialized

    def _coerce_type(self, key: str, str_val: str) -> Any:
        """Coerces a string value from SQLite app_settings to the appropriate Python type."""
        if str_val is None:
            return None

        # Look up field definition in Pydantic Settings model
        fields = getattr(Settings, "model_fields", {})
        field_info = fields.get(key)

        # Fallback to current settings value type if field info is missing
        target_type = None
        if field_info and field_info.annotation is not None:
            target_type = field_info.annotation
        elif hasattr(self._settings, key):
            target_type = type(getattr(self._settings, key))

        # Check for boolean
        if target_type is bool or str(target_type).lower().endswith("bool"):
            return str_val.strip().lower() in ("true", "1", "yes", "on")

        # Check for integer
        if target_type is int or str(target_type).lower().endswith("int"):
            try:
                return int(str_val.strip())
            except (ValueError, TypeError):
                return getattr(self._settings, key, str_val)

        # Check for float
        if target_type is float or str(target_type).lower().endswith("float"):
            try:
                return float(str_val.strip())
            except (ValueError, TypeError):
                return getattr(self._settings, key, str_val)

        # Check for dict or list (JSON stored)
        if target_type in (dict, list) or (isinstance(target_type, type) and issubclass(target_type, (dict, list))):
            try:
                return json.loads(str_val)
            except Exception:
                return getattr(self._settings, key, str_val)

        # Check for Path
        if target_type is Path:
            return Path(str_val)

        # Fallback: if it starts with { or [, attempt JSON parse anyway
        stripped = str_val.strip()
        if (stripped.startswith("{") and stripped.endswith("}")) or (stripped.startswith("[") and stripped.endswith("]")):
            try:
                return json.loads(stripped)
            except Exception:
                pass

        return str_val

    async def initialize(self, database: Optional[Any] = None) -> None:
        """
        Loads all persisted settings from SQLite, coerces types,
        updates in-memory cache and settings instance, and notifies subscribers.
        """
        if database is None:
            from keenguard.db.database import db
            database = db

        # 1. Start from current Pydantic settings values
        current_dump = self._settings.model_dump()
        self._cache.update(current_dump)

        # 2. Overlay values from SQLite app_settings table
        try:
            db_settings = await database.get_all_settings()
            for k, str_val in db_settings.items():
                coerced = self._coerce_type(k, str_val)
                self._cache[k] = coerced
                if hasattr(self._settings, k):
                    try:
                        setattr(self._settings, k, coerced)
                    except Exception as ex:
                        logger.warning("Could not set attribute '%s' on Settings: %s", k, ex)

            # Seed database if credentials exist in .env but not yet in SQLite
            if getattr(self._settings, "telegram_bot_token", None) and "telegram_bot_token" not in db_settings:
                await database.save_setting("telegram_bot_token", self._settings.telegram_bot_token)
            if getattr(self._settings, "telegram_chat_id", None) and "telegram_chat_id" not in db_settings:
                await database.save_setting("telegram_chat_id", self._settings.telegram_chat_id)
        except Exception as e:
            logger.error("Failed to load settings from database during initialize: %s", e)

        object.__setattr__(self, "_initialized", True)
        logger.info("ConfigService initialized with %d parameters.", len(self._cache))

        # 3. Notify initial subscribers
        for k, v in self._cache.items():
            self._notify(k, v)

    def get(self, key: str, default: Any = _UNSET) -> Any:
        """Synchronous, fast in-memory parameter lookup."""
        if key in self._cache:
            return self._cache[key]
        if hasattr(self._settings, key):
            return getattr(self._settings, key)
        if default is not _UNSET:
            return default
        return None

    async def set(
        self,
        key: str,
        value: Any,
        persist_db: bool = True,
        persist_env: bool = False,
        database: Optional[Any] = None,
    ) -> None:
        """Sets a single parameter in memory and persists to SQLite and/or .env."""
        self._cache[key] = value
        if hasattr(self._settings, key):
            try:
                setattr(self._settings, key, value)
            except Exception as ex:
                logger.warning("Could not update '%s' on Settings instance: %s", key, ex)

        if persist_db:
            if database is None:
                from keenguard.db.database import db
                database = db
            if isinstance(value, (dict, list)):
                str_val = json.dumps(value, ensure_ascii=False)
            elif isinstance(value, bool):
                str_val = "true" if value else "false"
            elif value is None:
                str_val = ""
            else:
                str_val = str(value)
            await database.save_setting(key, str_val)

        if persist_env:
            self._persist_to_env(key, value)

        self._notify(key, value)

    async def update_bulk(
        self,
        settings_dict: Dict[str, Any],
        persist_db: bool = True,
        persist_env: bool = False,
        database: Optional[Any] = None,
    ) -> None:
        """Batch updates parameters in memory and persists to SQLite."""
        if not settings_dict:
            return

        for k, v in settings_dict.items():
            self._cache[k] = v
            if hasattr(self._settings, k):
                try:
                    setattr(self._settings, k, v)
                except Exception as ex:
                    logger.warning("Could not update '%s' on Settings instance: %s", k, ex)

        if persist_db:
            if database is None:
                from keenguard.db.database import db
                database = db
            await database.set_settings_bulk(settings_dict)

        if persist_env:
            for k, v in settings_dict.items():
                self._persist_to_env(k, v)

        for k, v in settings_dict.items():
            self._notify(k, v)

    def _persist_to_env(self, key: str, value: Any) -> None:
        """Helper to persist specific security-critical settings to .env."""
        try:
            if key in ("router_host", "router_user", "router_password", "router_port"):
                save_env_router_credentials(
                    host=self.get("router_host", "192.168.1.1"),
                    user=self.get("router_user", "admin"),
                    password=self.get("router_password", ""),
                    port=self.get("router_port", 80),
                )
            elif key.startswith("telegram_"):
                save_env_telegram_settings(
                    token=self.get("telegram_bot_token", ""),
                    chat_id=self.get("telegram_chat_id", ""),
                    enabled=bool(self.get("telegram_enabled", False)),
                    api_url=self.get("telegram_api_url", "https://api.telegram.org"),
                    proxy=self.get("telegram_proxy"),
                )
            elif key.startswith("dns_security_") or key.startswith("nextdns_") or key.startswith("controld_") or key.startswith("adguard_") or key.startswith("pihole_"):
                save_env_dns_provider_settings(
                    provider=self.get("dns_security_provider", "none"),
                    sync_interval=self.get("dns_security_sync_interval", 60),
                    auto_sync=bool(self.get("dns_security_auto_sync", False)),
                    nextdns_api_key=self.get("nextdns_api_key"),
                    nextdns_profile_id=self.get("nextdns_profile_id"),
                    controld_api_key=self.get("controld_api_key"),
                    controld_device_id=self.get("controld_device_id"),
                    adguard_url=self.get("adguard_url"),
                    adguard_username=self.get("adguard_username"),
                    adguard_password=self.get("adguard_password"),
                    pihole_url=self.get("pihole_url"),
                    pihole_api_token=self.get("pihole_api_token"),
                    pihole_password=self.get("pihole_password"),
                )
        except Exception as e:
            logger.warning("Failed to persist setting '%s' to .env: %s", key, e)

    def subscribe(self, key: str, callback: Callable[[str, Any], None]) -> None:
        """Registers a listener for changes to a parameter (or '*' for all)."""
        if key not in self._subscribers:
            self._subscribers[key] = []
        if callback not in self._subscribers[key]:
            self._subscribers[key].append(callback)

    def unsubscribe(self, key: str, callback: Callable[[str, Any], None]) -> None:
        """Removes a previously registered listener."""
        if key in self._subscribers and callback in self._subscribers[key]:
            self._subscribers[key].remove(callback)

    def _notify(self, key: str, value: Any) -> None:
        """Notifies registered listeners of a parameter change."""
        callbacks = list(self._subscribers.get(key, [])) + list(self._subscribers.get("*", []))
        for cb in callbacks:
            try:
                cb(key, value)
            except Exception as e:
                logger.error("Error in config subscriber for key '%s': %s", key, e)

    def __getattr__(self, name: str) -> Any:
        if name.startswith("_"):
            return object.__getattribute__(self, name)
        return self.get(name)

    def __setattr__(self, name: str, value: Any) -> None:
        if name.startswith("_"):
            object.__setattr__(self, name, value)
        else:
            self._cache[name] = value
            if hasattr(self._settings, name):
                try:
                    setattr(self._settings, name, value)
                except Exception:
                    pass
            self._notify(name, value)


config_service = ConfigService()
