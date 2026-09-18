import logging
import os
from typing import Optional
from pathlib import Path
from dotenv import load_dotenv, set_key
from pydantic import BaseModel, Field

logger = logging.getLogger("keenguard.config")

BASE_DIR = Path(__file__).resolve().parent.parent
ENV_FILE = BASE_DIR / ".env"
load_dotenv(ENV_FILE)

DATA_DIR = BASE_DIR / "data"
PCAP_DIR = DATA_DIR / "pcaps"

DATA_DIR.mkdir(parents=True, exist_ok=True)
PCAP_DIR.mkdir(parents=True, exist_ok=True)

def save_env_router_credentials(host: str, user: str, password: str, port: int = 80):
    """Persists router credentials to .env so user never has to re-type them."""
    try:
        ENV_FILE.touch(exist_ok=True)
        set_key(str(ENV_FILE), "KEENETIC_HOST", host)
        set_key(str(ENV_FILE), "KEENETIC_USER", user)
        if password:
            set_key(str(ENV_FILE), "KEENETIC_PASSWORD", password)
        set_key(str(ENV_FILE), "KEENETIC_PORT", str(port))
    except Exception as e:
        logger.warning("Failed to persist router credentials to .env: %s", e)

def save_env_telegram_settings(token: str, chat_id: str, enabled: bool, api_url: str = "https://api.telegram.org", proxy: Optional[str] = None):
    """Persists Telegram notification settings to .env."""
    try:
        ENV_FILE.touch(exist_ok=True)
        set_key(str(ENV_FILE), "TELEGRAM_BOT_TOKEN", token)
        set_key(str(ENV_FILE), "TELEGRAM_CHAT_ID", chat_id)
        set_key(str(ENV_FILE), "TELEGRAM_ENABLED", "true" if enabled else "false")
        set_key(str(ENV_FILE), "TELEGRAM_API_URL", api_url or "https://api.telegram.org")
        if proxy:
            set_key(str(ENV_FILE), "TELEGRAM_PROXY", proxy)
        else:
            set_key(str(ENV_FILE), "TELEGRAM_PROXY", "")
    except Exception as e:
        logger.warning("Failed to persist Telegram settings to .env: %s", e)

def save_env_dns_provider_settings(
    provider: str,
    sync_interval: int = 60,
    auto_sync: bool = False,
    nextdns_api_key: Optional[str] = None,
    nextdns_profile_id: Optional[str] = None,
    controld_api_key: Optional[str] = None,
    controld_device_id: Optional[str] = None,
    adguard_url: Optional[str] = None,
    adguard_username: Optional[str] = None,
    adguard_password: Optional[str] = None,
    pihole_url: Optional[str] = None,
    pihole_api_token: Optional[str] = None,
    pihole_password: Optional[str] = None,
):
    """Persists DNS security provider settings to .env."""
    try:
        ENV_FILE.touch(exist_ok=True)
        set_key(str(ENV_FILE), "DNS_SECURITY_PROVIDER", provider or "none")
        set_key(str(ENV_FILE), "DNS_SECURITY_SYNC_INTERVAL", str(sync_interval or 60))
        set_key(str(ENV_FILE), "DNS_SECURITY_AUTO_SYNC", "true" if auto_sync else "false")
        if nextdns_api_key is not None:
            set_key(str(ENV_FILE), "NEXTDNS_API_KEY", nextdns_api_key)
        if nextdns_profile_id is not None:
            set_key(str(ENV_FILE), "NEXTDNS_PROFILE_ID", nextdns_profile_id)
        if controld_api_key is not None:
            set_key(str(ENV_FILE), "CONTROLD_API_KEY", controld_api_key)
        if controld_device_id is not None:
            set_key(str(ENV_FILE), "CONTROLD_DEVICE_ID", controld_device_id)
        if adguard_url is not None:
            set_key(str(ENV_FILE), "ADGUARD_URL", adguard_url)
        if adguard_username is not None:
            set_key(str(ENV_FILE), "ADGUARD_USERNAME", adguard_username)
        if adguard_password is not None:
            set_key(str(ENV_FILE), "ADGUARD_PASSWORD", adguard_password)
        if pihole_url is not None:
            set_key(str(ENV_FILE), "PIHOLE_URL", pihole_url)
        if pihole_api_token is not None:
            set_key(str(ENV_FILE), "PIHOLE_API_TOKEN", pihole_api_token)
        if pihole_password is not None:
            set_key(str(ENV_FILE), "PIHOLE_PASSWORD", pihole_password)
    except Exception as e:
        logger.warning("Failed to persist DNS provider settings to .env: %s", e)

class Settings(BaseModel):
    # Web server configuration (User selected port 9989)
    web_host: str = Field(default="0.0.0.0", description="Web interface bind host")
    web_port: int = Field(default=9989, description="Web interface bind port")

    # Keenetic Router configuration
    router_host: str = Field(default=os.getenv("KEENETIC_HOST", "192.168.1.1"))
    router_port: int = Field(default=int(os.getenv("KEENETIC_PORT", "80")))
    router_user: str = Field(default=os.getenv("KEENETIC_USER", "admin"))
    router_password: str = Field(default=os.getenv("KEENETIC_PASSWORD", ""))
    router_use_https: bool = Field(default=False)
    router_poll_interval: int = Field(default=5, description="Seconds between RCI polling")

    # Database & PCAP storage
    db_path: Path = Field(default=DATA_DIR / "keenguard.db")
    pcap_dir: Path = Field(default=PCAP_DIR)
    max_pcap_files: int = Field(default=50)

    # Smart TV & Media settings
    night_mode_start_hour: int = Field(default=0)  # 00:00
    night_mode_end_hour: int = Field(default=7)    # 07:00
    airplay_passthrough: bool = Field(default=True)
    cast_passthrough: bool = Field(default=True)
    tv_wake_pre_record_seconds: int = Field(default=30, description="Seconds of traffic to retain in PCAP before TV wake event")
    tv_wake_post_record_seconds: int = Field(default=60, description="Seconds to keep recording packets into PCAP after TV wake event")
    tv_day_tracking_mode: str = Field(default="autonomous_only", description="'autonomous_only' or 'all'")
    tv_wake_trigger_ttl_seconds: int = Field(default=60, description="Maximum age in seconds for a trigger (WOL, AirPlay) to be associated with a TV wake")

    # Camera monitoring settings
    camera_notify_wan_stream: bool = Field(default=True, description="Alert on video stream to public WAN/Internet")
    camera_notify_lan_stream: bool = Field(default=False, description="Alert on video stream to local LAN client (except NVR)")

    # Auto-quarantine targeting & scopes
    auto_quarantine_scope: str = Field(default="iot_camera", description="'iot_camera', 'all_except_trusted', 'custom_devices', or 'disabled'")

    # Anomaly detection & Network integrity thresholds
    camera_upload_threshold_kbps: float = Field(default=1500.0, description="1.5 Mbps upload limit for camera alert")
    iot_packet_rate_threshold: int = Field(default=100, description="Max packets/sec from an IoT device before alert")
    lan_scan_threshold: int = Field(default=10, description="Distinct internal IPs probed within 10s")
    mac_conflict_detection_enabled: bool = Field(default=True, description="Detect duplicate MAC addresses or ARP spoofing")
    notification_dedup_window_seconds: int = Field(default=60, description="Sliding window in seconds to aggregate duplicate alerts")

    # Telegram alerts
    telegram_bot_token: str = Field(default=os.getenv("TELEGRAM_BOT_TOKEN", ""))
    telegram_chat_id: str = Field(default=os.getenv("TELEGRAM_CHAT_ID", ""))
    telegram_enabled: bool = Field(default=os.getenv("TELEGRAM_ENABLED", "false").lower() in ("true", "1", "yes"))
    telegram_api_url: str = Field(default=os.getenv("TELEGRAM_API_URL", "https://api.telegram.org"))
    telegram_proxy: Optional[str] = Field(default=os.getenv("TELEGRAM_PROXY", None))

    # New device policy & reactions (independent modular toggles & category-based matrix)
    new_device_policy_mode: str = Field(default="category", description="'global' or 'category'")
    new_device_action: str = Field(default="notify")  # Backwards compatibility
    new_device_quarantine_wan: bool = Field(default=False, description="Block internet WAN on new devices (global mode)")
    new_device_isolate_lan: bool = Field(default=False, description="Isolate new devices from local LAN (global mode)")
    new_device_auto_audit: bool = Field(default=False, description="Auto-start traffic audit on new devices (global mode)")
    new_device_audit_duration: int = Field(default=3600, description="Audit duration in seconds if auto-audit is chosen")
    new_device_continuous_audit: bool = Field(default=True, description="Run hourly continuous audit until device is registered")

    # Category-based new device policy matrix
    new_device_category_policies: dict = Field(default_factory=lambda: {
        "trusted": {"quarantine_wan": False, "isolate_lan": False, "auto_audit": False, "audit_duration": 300, "telegram_alert": True},
        "iot": {"quarantine_wan": False, "isolate_lan": False, "auto_audit": True, "audit_duration": 900, "telegram_alert": True},
        "camera": {"quarantine_wan": False, "isolate_lan": False, "auto_audit": True, "audit_duration": 900, "telegram_alert": True},
        "random_mac": {"quarantine_wan": False, "isolate_lan": False, "auto_audit": True, "audit_duration": 1800, "telegram_alert": True},
        "unknown": {"quarantine_wan": False, "isolate_lan": False, "auto_audit": True, "audit_duration": 900, "telegram_alert": True},
    })

    # Traffic Audit Guard: auto-quarantine suspicious devices during individual or network-wide audits
    audit_auto_quarantine_suspicious: bool = Field(default=True, description="Auto-quarantine devices exhibiting suspicious behavior during traffic audit")

    # Security Digest settings
    digest_enabled: bool = Field(default=False)
    digest_schedule_hour: int = Field(default=9)
    digest_condition: str = Field(default="only_on_issues")  # "always" or "only_on_issues"

    # Scheduled automated audit settings
    scheduled_audit_enabled: bool = Field(default=False)
    scheduled_audit_hour: int = Field(default=3)  # 03:00
    scheduled_audit_scope: str = Field(default="all", description="Audit target scope: all, iot_only, or untrusted")
    scheduled_audit_duration: int = Field(default=60, description="Duration in seconds per device during scheduled audit")

    # IoT Payload capture and storage limits (User requested GB limit & days retention)
    iot_payload_capture_enabled: bool = Field(default=True, description="Continuous capture of IoT payload data")
    iot_payload_max_storage_gb: float = Field(default=1.0, description="Max disk storage for IoT payloads in GB")
    iot_payload_retention_days: int = Field(default=7, description="Automatically delete IoT payload logs older than N days")

    # External DNS security provider settings (NextDNS, Control D, AdGuard Home, Pi-hole)
    dns_security_provider: str = Field(default=os.getenv("DNS_SECURITY_PROVIDER", "none"), description="'none', 'nextdns', 'controld', 'adguard_home', or 'pihole'")
    dns_security_sync_interval: int = Field(default=int(os.getenv("DNS_SECURITY_SYNC_INTERVAL", "60")), description="Seconds between external DNS sync")
    dns_security_auto_sync: bool = Field(default=os.getenv("DNS_SECURITY_AUTO_SYNC", "false").lower() in ("true", "1", "yes"))
    nextdns_api_key: str = Field(default=os.getenv("NEXTDNS_API_KEY", ""))
    nextdns_profile_id: str = Field(default=os.getenv("NEXTDNS_PROFILE_ID", ""))
    controld_api_key: str = Field(default=os.getenv("CONTROLD_API_KEY", ""))
    controld_device_id: str = Field(default=os.getenv("CONTROLD_DEVICE_ID", ""))
    adguard_url: str = Field(default=os.getenv("ADGUARD_URL", ""))
    adguard_username: str = Field(default=os.getenv("ADGUARD_USERNAME", ""))
    adguard_password: str = Field(default=os.getenv("ADGUARD_PASSWORD", ""))
    pihole_url: str = Field(default=os.getenv("PIHOLE_URL", ""))
    pihole_api_token: str = Field(default=os.getenv("PIHOLE_API_TOKEN", ""))
    pihole_password: str = Field(default=os.getenv("PIHOLE_PASSWORD", ""))

settings = Settings()


