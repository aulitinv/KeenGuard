"""Catalog of known public DoH (DNS-over-HTTPS), DoT (DNS-over-TLS), and Anycast resolvers."""
from typing import Optional, Dict, Set


DOH_DOMAINS: Dict[str, str] = {
    # Google
    "dns.google": "Google Public DNS",
    "dns.google.com": "Google Public DNS",
    # Cloudflare
    "cloudflare-dns.com": "Cloudflare DNS",
    "1dot1dot1dot1.cloudflare-dns.com": "Cloudflare DNS",
    "one.one.one.one": "Cloudflare DNS",
    "security.cloudflare-dns.com": "Cloudflare Security DNS",
    "family.cloudflare-dns.com": "Cloudflare Family DNS",
    # Quad9
    "dns.quad9.net": "Quad9 Secure DNS",
    "dns9.quad9.net": "Quad9 Secure DNS",
    "dns10.quad9.net": "Quad9 Uncensored DNS",
    "dns11.quad9.net": "Quad9 ECS DNS",
    # OpenDNS / Cisco
    "doh.opendns.com": "Cisco OpenDNS",
    "doh.familyshield.opendns.com": "Cisco OpenDNS FamilyShield",
    # AdGuard
    "dns.adguard-dns.com": "AdGuard DNS",
    "unfiltered.adguard-dns.com": "AdGuard Non-filtering DNS",
    "family.adguard-dns.com": "AdGuard Family DNS",
    # NextDNS
    "dns.nextdns.io": "NextDNS",
    # Control D
    "dns.controld.com": "Control D",
    "freedns.controld.com": "Control D Free",
    # Mullvad
    "dns.mullvad.net": "Mullvad DNS",
    # CleanBrowsing
    "doh.cleanbrowsing.org": "CleanBrowsing",
    # AliDNS
    "dns.alidns.com": "AliDNS",
    # Firefox Canary domain (NXDOMAIN disables DoH)
    "use-application-dns.net": "Mozilla Firefox DoH Canary",
}


PUBLIC_RESOLVER_IPS: Dict[str, str] = {
    # Google
    "8.8.8.8": "Google DNS",
    "8.8.4.4": "Google DNS",
    "2001:4860:4860::8888": "Google DNS",
    "2001:4860:4860::8844": "Google DNS",
    # Cloudflare
    "1.1.1.1": "Cloudflare DNS",
    "1.0.0.1": "Cloudflare DNS",
    "1.1.1.2": "Cloudflare Security",
    "1.0.0.2": "Cloudflare Security",
    "1.1.1.3": "Cloudflare Family",
    "1.0.0.3": "Cloudflare Family",
    "2606:4700:4700::1111": "Cloudflare DNS",
    "2606:4700:4700::1001": "Cloudflare DNS",
    # Quad9
    "9.9.9.9": "Quad9",
    "149.112.112.112": "Quad9",
    "9.9.9.10": "Quad9 Uncensored",
    "149.112.112.10": "Quad9 Uncensored",
    "2620:fe::fe": "Quad9",
    "2620:fe::9": "Quad9",
    # OpenDNS
    "208.67.222.222": "OpenDNS",
    "208.67.220.220": "OpenDNS",
    "208.67.222.123": "OpenDNS FamilyShield",
    "208.67.220.123": "OpenDNS FamilyShield",
    # AdGuard
    "94.140.14.14": "AdGuard DNS",
    "94.140.15.15": "AdGuard DNS",
    "94.140.14.140": "AdGuard Default",
    "94.140.14.141": "AdGuard Default",
    # Control D
    "76.76.2.0": "Control D",
    "76.76.10.0": "Control D",
    # CleanBrowsing
    "185.228.168.9": "CleanBrowsing Security",
    "185.228.169.9": "CleanBrowsing Security",
    # Mullvad
    "194.242.2.2": "Mullvad DNS",
}


def is_doh_domain(domain: Optional[str]) -> bool:
    """Returns True if the given domain matches a known DoH provider or canary domain."""
    if not domain:
        return False
    d = domain.strip().lower().rstrip(".")
    if d in DOH_DOMAINS:
        return True
    for candidate in DOH_DOMAINS.keys():
        if d.endswith("." + candidate):
            return True
    return False


def get_provider_for_domain(domain: Optional[str]) -> Optional[str]:
    """Returns human-readable name of DoH provider if matched, else None."""
    if not domain:
        return None
    d = domain.strip().lower().rstrip(".")
    if d in DOH_DOMAINS:
        return DOH_DOMAINS[d]
    for candidate, name in DOH_DOMAINS.items():
        if d.endswith("." + candidate):
            return name
    return None


def is_public_resolver_ip(ip: Optional[str]) -> bool:
    """Returns True if IP is in the catalog of known public DNS resolvers."""
    if not ip:
        return False
    return ip.strip() in PUBLIC_RESOLVER_IPS


def get_provider_for_ip(ip: Optional[str]) -> Optional[str]:
    """Returns provider name for public resolver IP, or None."""
    if not ip:
        return None
    return PUBLIC_RESOLVER_IPS.get(ip.strip())
