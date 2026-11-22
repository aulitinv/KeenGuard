"""HTML Template Assembler and Builder for KeenGuard SPA Web UI.

Decomposes the monolithic 7,200+ line index.html into clean, modular templates:
- keenguard/web/templates/base.html (Shell, header, sidebar, navigation, script imports)
- keenguard/web/templates/tabs/*.html (14 independent tab views)
- keenguard/web/templates/modals/*.html (16 independent dialogs and inspectors)

Compiles them seamlessly into keenguard/web/static/index.html with zero runtime overhead.
"""
import logging
from pathlib import Path
from typing import List, Optional

logger = logging.getLogger("keenguard.web.builder")

TEMPLATES_DIR = Path(__file__).resolve().parent / "templates"
STATIC_INDEX_PATH = Path(__file__).resolve().parent / "static" / "index.html"

ORDERED_TABS: List[str] = [
    "dashboard",
    "security",
    "devices",
    "smarthome",
    "lan",
    "topology",
    "packets",
    "tv",
    "alerts",
    "rules",
    "dns",
    "audits",
    "investigator",
    "settings",
]

ORDERED_MODALS: List[str] = [
    "command_palette",
    "device_modal",
    "isolation_wizard",
    "digest_modal",
    "event_modal",
    "domain_modal",
    "audit_detail_modal",
    "network_audit_modal",
    "security_wizard_modal",
    "clear_events_modal",
    "device_setup_wizard_modal",
    "custom_preset_modal",
    "dns_preset_modal",
    "dns_active_rules_modal",
    "rule_builder_modals",
    "login_modal",
]


def assemble_index_html(templates_dir: Optional[Path] = None) -> str:
    """Assembles index.html from base.html, tabs, and modals."""
    tpl_dir = templates_dir or TEMPLATES_DIR
    base_file = tpl_dir / "base.html"
    if not base_file.exists():
        raise FileNotFoundError(f"Base template not found: {base_file}")

    base_content = base_file.read_text(encoding="utf-8")

    # Collect tabs
    tabs_dir = tpl_dir / "tabs"
    tabs_parts = []
    for tab_name in ORDERED_TABS:
        tab_path = tabs_dir / f"{tab_name}.html"
        if tab_path.exists():
            tabs_parts.append(tab_path.read_text(encoding="utf-8"))
        else:
            logger.warning("Tab template missing: %s", tab_path)

    all_tabs_html = "".join(tabs_parts)

    # Collect modals
    modals_dir = tpl_dir / "modals"
    modals_parts = []
    for modal_name in ORDERED_MODALS:
        modal_path = modals_dir / f"{modal_name}.html"
        if modal_path.exists():
            modals_parts.append(modal_path.read_text(encoding="utf-8"))
        else:
            logger.warning("Modal template missing: %s", modal_path)

    all_modals_html = "".join(modals_parts)

    assembled = base_content.replace(
        "<!-- {{ TABS_CONTENT }} -->\n",
        all_tabs_html
    ).replace(
        "<!-- {{ MODALS_CONTENT }} -->\n",
        all_modals_html
    )

    return assembled


def build_index_html(
    templates_dir: Optional[Path] = None,
    output_path: Optional[Path] = None
) -> Path:
    """Builds and writes keenguard/web/static/index.html from modular templates."""
    out_file = output_path or STATIC_INDEX_PATH
    assembled = assemble_index_html(templates_dir=templates_dir)

    # Check if already up-to-date to avoid touching mtime unnecessarily
    if out_file.exists():
        current = out_file.read_text(encoding="utf-8")
        if current == assembled:
            logger.debug("index.html is already up-to-date with templates.")
            return out_file

    out_file.parent.mkdir(parents=True, exist_ok=True)
    out_file.write_text(assembled, encoding="utf-8")
    logger.info("Successfully built index.html from modular templates -> %s", out_file)
    return out_file


if __name__ == "__main__":
    logging.basicConfig(level=logging.INFO)
    dest = build_index_html()
    print(f"Built: {dest} ({dest.stat().st_size} bytes)")
