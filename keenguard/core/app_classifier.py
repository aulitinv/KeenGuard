"""Lightweight L7 Application Classifier (App ID via SNI, DNS context, and transport signatures)."""
from typing import Dict, Any, List, Optional, Union
import logging
import time

logger = logging.getLogger("keenguard.core.app_classifier")

APP_CATALOG: Dict[str, Dict[str, Any]] = {
    # Streaming / Video
    "youtube": {
        "name": "YouTube",
        "category": "streaming",
        "domains": ["googlevideo.com", "youtube.com", "youtu.be", "ytimg.com"],
        "ports": [],
        "icon": "video"
    },
    "netflix": {
        "name": "Netflix",
        "category": "streaming",
        "domains": ["netflix.com", "nflxvideo.net", "nflximg.net", "nflxext.com"],
        "ports": [],
        "icon": "film"
    },
    "twitch": {
        "name": "Twitch",
        "category": "streaming",
        "domains": ["twitch.tv", "ttvnw.net", "jtvnw.net"],
        "ports": [],
        "icon": "tv"
    },
    "spotify": {
        "name": "Spotify",
        "category": "streaming",
        "domains": ["spotify.com", "scdn.co", "spoti.fi"],
        "ports": [],
        "icon": "music"
    },
    "apple_media": {
        "name": "Apple Media / TV",
        "category": "streaming",
        "domains": ["tv.apple.com", "music.apple.com", "itunes.apple.com"],
        "ports": [],
        "icon": "apple"
    },
    "kinopoisk": {
        "name": "Кинопоиск",
        "category": "streaming",
        "domains": ["kinopoisk.ru", "ott.yandex.net"],
        "ports": [],
        "icon": "film"
    },
    "rutube": {
        "name": "RuTube",
        "category": "streaming",
        "domains": ["rutube.ru", "rutube.media"],
        "ports": [],
        "icon": "play"
    },

    # Messengers & Communication
    "telegram": {
        "name": "Telegram",
        "category": "communication",
        "domains": ["telegram.org", "t.me", "telesco.pe"],
        "ports": [],
        "icon": "send"
    },
    "whatsapp": {
        "name": "WhatsApp",
        "category": "communication",
        "domains": ["whatsapp.com", "whatsapp.net"],
        "ports": [],
        "icon": "message-circle"
    },
    "discord": {
        "name": "Discord",
        "category": "communication",
        "domains": ["discord.gg", "discord.com", "discordapp.com", "discordapp.net"],
        "ports": [range(50000, 65535)],
        "icon": "message-square"
    },
    "zoom": {
        "name": "Zoom",
        "category": "communication",
        "domains": ["zoom.us", "zoom.com"],
        "ports": [8801, 8802],
        "icon": "video"
    },
    "google_meet": {
        "name": "Google Meet",
        "category": "communication",
        "domains": ["meet.google.com"],
        "ports": [],
        "icon": "video"
    },

    # Gaming
    "steam": {
        "name": "Steam",
        "category": "gaming",
        "domains": ["steampowered.com", "steamcommunity.com", "steamcontent.com", "steamstatic.com"],
        "ports": [range(27000, 27101)],
        "icon": "gamepad-2"
    },
    "epic_games": {
        "name": "Epic Games",
        "category": "gaming",
        "domains": ["epicgames.com", "unrealengine.com"],
        "ports": [],
        "icon": "gamepad"
    },
    "playstation": {
        "name": "PlayStation Network",
        "category": "gaming",
        "domains": ["playstation.com", "playstation.net", "sonyentertainmentnetwork.com"],
        "ports": [],
        "icon": "playstation"
    },
    "xbox": {
        "name": "Xbox Live",
        "category": "gaming",
        "domains": ["xboxlive.com", "xbox.com"],
        "ports": [3074],
        "icon": "xbox"
    },

    # P2P / Torrents
    "bittorrent": {
        "name": "BitTorrent / P2P",
        "category": "p2p",
        "domains": ["tracker", "torrent"],
        "ports": [6881, 6882, 6883, 6884, 6885, 6886, 6887, 6888, 6889, 51413],
        "icon": "download-cloud"
    },

    # VPN & Tunnels
    "wireguard": {
        "name": "WireGuard",
        "category": "vpn",
        "domains": [],
        "ports": [51820],
        "icon": "shield"
    },
    "openvpn": {
        "name": "OpenVPN",
        "category": "vpn",
        "domains": [],
        "ports": [1194],
        "icon": "shield"
    },
    "ipsec": {
        "name": "IPsec / IKEv2",
        "category": "vpn",
        "domains": [],
        "ports": [500, 4500],
        "icon": "shield"
    },

    # Cloud Storage
    "google_drive": {
        "name": "Google Drive",
        "category": "cloud",
        "domains": ["drive.google.com"],
        "ports": [],
        "icon": "cloud"
    },
    "icloud": {
        "name": "Apple iCloud",
        "category": "cloud",
        "domains": ["icloud.com"],
        "ports": [],
        "icon": "cloud"
    },
    "yandex_disk": {
        "name": "Яндекс Диск",
        "category": "cloud",
        "domains": ["disk.yandex.ru"],
        "ports": [],
        "icon": "cloud"
    },
    "dropbox": {
        "name": "Dropbox",
        "category": "cloud",
        "domains": ["dropbox.com", "dropboxstatic.com"],
        "ports": [],
        "icon": "cloud"
    },
}


class AppClassifier:
    """Zero-overhead L7 application classifier using SNI, DNS context, and transport signatures."""

    def __init__(self, max_dns_cache: int = 5000):
        # Maps dst_ip -> (domain, timestamp)
        self._dns_cache: Dict[str, tuple[str, float]] = {}
        self._max_dns_cache = max_dns_cache

    def cache_dns_resolution(self, ip: str, domain: str):
        """Records DNS resolution mapping to correlate future flows to this IP."""
        if not ip or not domain:
            return
        if len(self._dns_cache) >= self._max_dns_cache:
            # Evict oldest 20%
            sorted_items = sorted(self._dns_cache.items(), key=lambda x: x[1][1])
            for k, _ in sorted_items[:len(sorted_items) // 5]:
                self._dns_cache.pop(k, None)
        self._dns_cache[ip] = (domain.lower().strip().rstrip("."), time.time())

    def get_domain_for_ip(self, ip: str) -> Optional[str]:
        """Returns cached domain name for IP if resolved within last 1 hour."""
        item = self._dns_cache.get(ip)
        if item:
            domain, ts = item
            if time.time() - ts < 3600:
                return domain
            else:
                self._dns_cache.pop(ip, None)
        return None

    def classify_flow(
        self,
        src_ip: str,
        dst_ip: str,
        dst_port: int,
        proto: str = "tcp",
        sni: Optional[str] = None,
        domain_hint: Optional[str] = None,
    ) -> Dict[str, Any]:
        """
        Classifies network flow into an application category.
        Returns: {'app_id': str, 'name': str, 'category': str, 'icon': str}
        """
        target_domain = (sni or domain_hint or self.get_domain_for_ip(dst_ip) or "").lower()

        # 1. Domain / SNI Match
        if target_domain:
            for app_id, app_info in APP_CATALOG.items():
                for d in app_info["domains"]:
                    if target_domain == d or target_domain.endswith("." + d):
                        return {
                            "app_id": app_id,
                            "name": app_info["name"],
                            "category": app_info["category"],
                            "icon": app_info["icon"],
                            "matched_by": "sni_or_domain",
                            "domain": target_domain,
                        }

        # 2. Port & Protocol Match
        if dst_port:
            # First pass: exact port matches (e.g. WireGuard 51820, OpenVPN 1194)
            for app_id, app_info in APP_CATALOG.items():
                for p_rule in app_info["ports"]:
                    if isinstance(p_rule, int) and dst_port == p_rule:
                        return {
                            "app_id": app_id,
                            "name": app_info["name"],
                            "category": app_info["category"],
                            "icon": app_info["icon"],
                            "matched_by": "port",
                            "port": dst_port,
                        }

            # Second pass: port range matches (e.g. Steam 27000-27100, Discord 50000-65535)
            for app_id, app_info in APP_CATALOG.items():
                for p_rule in app_info["ports"]:
                    if isinstance(p_rule, range) and dst_port in p_rule:
                        return {
                            "app_id": app_id,
                            "name": app_info["name"],
                            "category": app_info["category"],
                            "icon": app_info["icon"],
                            "matched_by": "port_range",
                            "port": dst_port,
                        }

        # 3. Default generic classifications
        if dst_port in (80, 443, 8080, 8443):
            return {
                "app_id": "web",
                "name": "Веб-серфинг (HTTP/HTTPS)",
                "category": "web",
                "icon": "globe",
                "matched_by": "standard_web_port",
            }
        elif dst_port in (53, 853):
            return {
                "app_id": "dns",
                "name": "DNS-трафик",
                "category": "system",
                "icon": "server",
                "matched_by": "dns_port",
            }
        elif dst_port == 123:
            return {
                "app_id": "ntp",
                "name": "NTP (Сетевое время)",
                "category": "system",
                "icon": "clock",
                "matched_by": "ntp_port",
            }

        return {
            "app_id": "other",
            "name": f"Прочий трафик ({proto.upper()}:{dst_port})",
            "category": "other",
            "icon": "activity",
            "matched_by": "unclassified",
        }

    def aggregate_apps(self, flows_or_sessions: List[Dict[str, Any]]) -> Dict[str, Any]:
        """
        Aggregates a list of flows or session dicts into a summary with breakdown by app and category.
        Each item is expected to have 'bytes' (or 'rx_bytes'/'tx_bytes') and classification fields.
        """
        app_bytes: Dict[str, int] = {}
        app_counts: Dict[str, int] = {}
        app_meta: Dict[str, Dict[str, str]] = {}
        category_bytes: Dict[str, int] = {}
        total_bytes = 0

        for item in flows_or_sessions:
            b = (
                item.get("bytes", 0)
                or (item.get("bytes_up", 0) + item.get("bytes_down", 0))
                or (item.get("rx_bytes", 0) + item.get("tx_bytes", 0))
                or item.get("packet_count", 1)
            )
            app_id = item.get("app_id", "other")
            app_name = item.get("app_name") or item.get("name", "Other")
            cat = item.get("category") or item.get("app_category", "other")
            icon = item.get("icon") or item.get("app_icon", "activity")

            total_bytes += b
            app_bytes[app_id] = app_bytes.get(app_id, 0) + b
            app_counts[app_id] = app_counts.get(app_id, 0) + 1
            category_bytes[cat] = category_bytes.get(cat, 0) + b
            app_meta[app_id] = {"name": app_name, "category": cat, "icon": icon}

        breakdown = []
        for app_id, b in sorted(app_bytes.items(), key=lambda x: x[1], reverse=True):
            pct = round((b / total_bytes * 100), 1) if total_bytes > 0 else 0
            breakdown.append({
                "app_id": app_id,
                "name": app_meta[app_id]["name"],
                "category": app_meta[app_id]["category"],
                "icon": app_meta[app_id]["icon"],
                "bytes": b,
                "percentage": pct,
                "flow_count": app_counts[app_id],
            })

        categories = []
        for cat, b in sorted(category_bytes.items(), key=lambda x: x[1], reverse=True):
            pct = round((b / total_bytes * 100), 1) if total_bytes > 0 else 0
            categories.append({
                "category": cat,
                "bytes": b,
                "percentage": pct,
            })

        return {
            "total_bytes": total_bytes,
            "apps_breakdown": breakdown,
            "categories_breakdown": categories,
        }


app_classifier = AppClassifier()
