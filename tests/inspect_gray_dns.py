# -*- coding: utf-8 -*-
"""Inspect all DNS queries in database and analyze unclassified or gray domains."""
import asyncio
import sys
from pathlib import Path

PROJECT_ROOT = Path(__file__).resolve().parent.parent
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))

from keenguard.db.database import db
from keenguard.core.domain_analyzer import domain_analyzer, CATEGORIES


async def main():
    await domain_analyzer.load_custom_rules_and_signatures(db)
    queries = await db.get_top_dns_queries(limit=1000)
    print(f"=== TOTAL DNS QUERIES IN DATABASE: {len(queries)} ===")

    all_devs = await db.get_all_devices()
    dev_map = {d.mac.upper(): d for d in all_devs if d.mac}

    category_counts = {}
    gray_list = []
    classified_list = []

    for q in queries:
        dom = q["domain"]
        ip = q.get("ip")
        mac = q.get("mac")
        cnt = q.get("count", 1)

        dev_name = "Unknown"
        if mac and mac.upper() in dev_map:
            d = dev_map[mac.upper()]
            dev_name = d.custom_name or d.hostname or d.vendor or d.mac

        analysis = domain_analyzer.analyze_domain(dom, ip=ip)
        cat = analysis["category"]
        risk = analysis["risk_level"]
        badge_color = analysis["badge_color"]
        badge_text = analysis["badge_text"]

        category_counts[cat] = category_counts.get(cat, 0) + 1

        is_gray = (cat == "unknown" or badge_color == "slate")
        entry = {
            "domain": dom,
            "ip": ip,
            "mac": mac,
            "device": dev_name,
            "count": cnt,
            "category": cat,
            "risk": risk,
            "badge_color": badge_color,
            "badge_text": badge_text,
            "vendor": analysis.get("vendor", ""),
            "description": analysis.get("description", ""),
        }

        if is_gray:
            gray_list.append(entry)
        else:
            classified_list.append(entry)

    print("\n--- CATEGORY BREAKDOWN ---")
    for cat, count in sorted(category_counts.items(), key=lambda x: -x[1]):
        cat_info = CATEGORIES.get(cat, {})
        print(f"  {cat:<15}: {count:3d} ({cat_info.get('name', 'Unknown')})")

    print(f"\n--- TOTAL GRAY / SLATE ROWS: {len(gray_list)} ---")
    # Group by category and root domain
    from collections import defaultdict
    unknowns = [x for x in gray_list if x['category'] == 'unknown']
    cdn_medias = [x for x in gray_list if x['category'] == 'cdn_media']

    print(f"\n=== 1. UNKNOWN DOMAINS GROUPED ({len(unknowns)} domains) ===")
    grouped_unk = defaultdict(list)
    for item in unknowns:
        dom = item['domain']
        parts = dom.split('.')
        # identify root / parent domain
        if len(parts) >= 2:
            if parts[-2] in ('co', 'com', 'org', 'net', 'edu', 'gov', 'spb', 'msk', 'ip') and len(parts) >= 3:
                parent = '.'.join(parts[-3:])
            else:
                parent = '.'.join(parts[-2:])
        else:
            parent = dom
        grouped_unk[parent].append(item)

    for parent, items in sorted(grouped_unk.items(), key=lambda x: -sum(i['count'] for i in x[1]))[:15]:
        total_reqs = sum(i['count'] for i in items)
        dev_names = list(set(i['device'] for i in items))
        print(f"  Parent: {parent:<32} ({len(items):2d} subdomains, total_cnt={total_reqs:4d}) | Devs: {', '.join(dev_names)[:40]}")
        for s in items[:3]:
            print(f"    - {s['domain']} (cnt={s['count']}, ip={s['ip']})")
        if len(items) > 3:
            print(f"    ... + {len(items)-3} more")

    print(f"\n=== 2. CDN / MEDIA DOMAINS THAT RENDER AS GRAY SLATE ({len(cdn_medias)}) ===")
    # Group by root domain
    grouped_cdn = defaultdict(list)
    for item in cdn_medias:
        parts = item['domain'].split('.')
        root = '.'.join(parts[-2:]) if len(parts) >= 2 else item['domain']
        grouped_cdn[root].append(item)

    for root, items in sorted(grouped_cdn.items(), key=lambda x: -len(x[1])):
        total_cnt = sum(x['count'] for x in items)
        print(f"  Root: {root:<25} ({len(items)} subdomains, total requests={total_cnt})")
        for sub in items[:3]:
            print(f"    - {sub['domain']}")
        if len(items) > 3:
            print(f"    ... and {len(items)-3} more")

    print(f"\n--- CLASSIFIED SAMPLE ({len(classified_list)} domains) ---")
    for item in classified_list[:15]:
        print(f"[{item['category']:<10}|{item['badge_text']:<10}] {item['domain']:<45} | {item['vendor']}")


if __name__ == "__main__":
    asyncio.run(main())
