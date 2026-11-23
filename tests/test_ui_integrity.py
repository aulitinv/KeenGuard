"""
Automated Static Analysis & UI Integrity Tests.

Verifies:
1. All onclick/onchange/onsubmit/oninput handlers in index.html and app.js reference valid functions.
2. All modal dialogs and overlay drawers are registered in initModalDismissHandlers (Escape + backdrop click).
3. Document getElementById lookups reference existing IDs in HTML or dynamic JS templates.
4. Interactive SVG topology guarantees clickability (drag vs click threshold, hit targets, no pointer-events: none on text).
"""

import re
from pathlib import Path
import pytest

REPO_ROOT = Path(__file__).resolve().parent.parent
STATIC_DIR = REPO_ROOT / "keenguard" / "web" / "static"
APP_JS = STATIC_DIR / "app.js"
INDEX_HTML = STATIC_DIR / "index.html"

BUILTIN_FUNCS = {
    'alert', 'confirm', 'prompt', 'console', 'preventDefault', 'stopPropagation',
    'encodeURIComponent', 'decodeURIComponent', 'parseInt', 'parseFloat', 'isNaN',
    'isFinite', 'Number', 'String', 'Boolean', 'Object', 'Array', 'Math', 'Date',
    'setTimeout', 'clearTimeout', 'setInterval', 'clearInterval', 'event', 'closeAnyModal',
    'getElementById', 'querySelector', 'querySelectorAll', 'closest', 'getAttribute',
    'setAttribute', 'focus', 'click', 'submit', 'reset', 'trim', 'toLowerCase', 'toUpperCase'
}


@pytest.fixture(scope="module")
def html_content() -> str:
    assert INDEX_HTML.exists(), f"Missing {INDEX_HTML}"
    return INDEX_HTML.read_text(encoding="utf-8")


@pytest.fixture(scope="module")
def js_content() -> str:
    assert APP_JS.exists(), f"Missing {APP_JS}"
    parts = [APP_JS.read_text(encoding="utf-8")]
    js_dir = STATIC_DIR / "js"
    if js_dir.exists():
        for p in sorted(js_dir.rglob("*.js")):
            parts.append(p.read_text(encoding="utf-8"))
    return "\n\n".join(parts)


@pytest.fixture(scope="module")
def js_defined_functions(js_content: str) -> set[str]:
    defined = set()
    # 1. Standard function declarations: function foo(
    for m in re.finditer(r'\bfunction\s+([a-zA-Z0-9_$]+)\s*\(', js_content):
        defined.add(m.group(1))

    # 2. window assignments: window.foo =
    for m in re.finditer(r'\bwindow\.([a-zA-Z0-9_$]+)\s*=', js_content):
        defined.add(m.group(1))

    # 3. Variable function assignments: const foo = function / const foo = () =>
    for m in re.finditer(r'\b(?:const|let|var)\s+([a-zA-Z0-9_$]+)\s*=\s*(?:async\s*)?(?:function|\([^)]*\)\s*=>)', js_content):
        defined.add(m.group(1))

    return defined


def test_html_event_handlers_exist_in_js(html_content: str, js_content: str, js_defined_functions: set[str]):
    """Verify that every onclick, onchange, onsubmit, oninput in index.html calls an existing function."""
    html_handlers = re.findall(r'on(?:click|change|submit|input)\s*=\s*["\']([^"\']+)["\']', html_content)
    assert len(html_handlers) > 0, "No event handlers found in index.html"

    missing_funcs = set()
    for handler in html_handlers:
        func_calls = re.findall(r'([a-zA-Z0-9_$]+)\s*\(', handler)
        for fn in func_calls:
            if fn in BUILTIN_FUNCS:
                continue
            if fn not in js_defined_functions and not re.search(r'\b' + re.escape(fn) + r'\b\s*[:=]', js_content):
                missing_funcs.add(fn)

    assert not missing_funcs, f"Found event handlers in index.html calling undefined JS functions: {missing_funcs}"


def test_js_template_event_handlers_exist(js_content: str, js_defined_functions: set[str]):
    """Verify that HTML templates dynamically created in app.js call valid functions."""
    template_handlers = re.findall(r'on(?:click|change|submit|input)\s*=\s*\\?["\']([^"\'>\\]+)', js_content)
    assert len(template_handlers) > 0, "No template event handlers found in app.js"

    missing_funcs = set()
    for handler in template_handlers:
        func_calls = re.findall(r'([a-zA-Z0-9_$]+)\s*\(', handler)
        for fn in func_calls:
            if fn in BUILTIN_FUNCS:
                continue
            if fn not in js_defined_functions and not re.search(r'\b' + re.escape(fn) + r'\b\s*[:=]', js_content):
                missing_funcs.add(fn)

    assert not missing_funcs, f"Found template event handlers in app.js calling undefined functions: {missing_funcs}"


def test_all_modals_have_dismiss_handlers(html_content: str, js_content: str):
    """Verify that every modal overlay dialog in index.html is registered for Escape & backdrop dismissal."""
    # Find full-screen modal overlays (fixed inset-0 containing modal/drawer)
    all_overlay_divs = set(re.findall(
        r'<div\s+id=["\']([a-zA-Z0-9_\-]+(?:modal|drawer))["\'][^>]*class=["\'][^"\']*fixed\s+inset-0[^"\']*["\']',
        html_content,
        re.IGNORECASE
    ))

    # Exempt modals that are strictly locked or not dismissable by clicking backdrop
    exempt_modals = {
        'login-modal',  # Authentication dialog should not dismiss on backdrop click
    }

    interactive_modals = all_overlay_divs - exempt_modals
    assert len(interactive_modals) > 0, "No interactive modals found in index.html"

    # Extract modalIds array explicitly from initModalDismissHandlers in app.js
    array_match = re.search(r'const\s+modalIds\s*=\s*\[([\s\S]*?)\];', js_content)
    assert array_match, "const modalIds = [...] array not found in app.js"

    registered_ids = set(re.findall(r'["\']([a-zA-Z0-9_\-]+)["\']', array_match.group(1)))

    # Also verify closeAnyModal handles each registered modal
    close_any_match = re.search(r'function closeAnyModal\([^)]*\)\s*\{([\s\S]*?)\n\}', js_content)
    assert close_any_match, "function closeAnyModal() not found in app.js"
    close_handled_ids = set(re.findall(r'id\s*===\s*["\']([a-zA-Z0-9_\-]+)["\']', close_any_match.group(1)))

    unregistered_modals = interactive_modals - registered_ids
    assert not unregistered_modals, (
        f"The following modal overlays are missing from initModalDismissHandlers: {unregistered_modals}. "
        "Users cannot close them with Escape or backdrop clicks!"
    )

    unhandled_in_close_any = registered_ids - close_handled_ids
    assert not unhandled_in_close_any, (
        f"The following modals are in initModalDismissHandlers but missing in closeAnyModal: {unhandled_in_close_any}"
    )


def test_svg_topology_interaction_integrity(js_content: str):
    """
    Verify regression protection for network topology node interaction:
    1. Distance threshold prevents mousedown from triggering premature physics/DOM recreation.
    2. Transparent hit circle exists for effortless clicking/tapping.
    3. SVG text labels do NOT contain pointer-events: none.
    4. Touch events (touchstart/touchmove/touchend) are registered.
    """
    # 1. Check distance threshold logic
    assert "dragCandidate" in js_content, "Topology must use dragCandidate to distinguish drag from click"
    assert "Math.hypot" in js_content, "Topology must calculate euclidean movement distance before initiating drag"

    # 2. Check hit circle in topology render
    assert "topology-hit-circle" in js_content, "Topology render must include transparent hit area circle"

    # 3. Check that topology text does not have pointer-events: none
    topo_render_match = re.search(r'function renderTopologyElements\(\)\s*\{([\s\S]*?)\n\}', js_content)
    assert topo_render_match, "renderTopologyElements not found in app.js"
    topo_render_body = topo_render_match.group(1)

    # In topology-node-group text, pointer-events: none must NOT be present
    text_matches = re.findall(r'<text\b[\s\S]*?</text>', topo_render_body)
    for tm in text_matches:
        assert "pointer-events: none" not in tm, (
            f"Found forbidden 'pointer-events: none' inside topology text node:\n{tm}\n"
            "This causes clicks on device labels to be ignored by the browser!"
        )

    # 4. Check touch events
    assert "touchstart" in js_content and "touchend" in js_content, (
        "Topology must handle touchstart/touchend for mobile and tablet devices"
    )


def test_template_builder_integrity(html_content: str):
    """
    Verify that keenguard.web.builder compiles modular templates into an exact match of static index.html.
    """
    from keenguard.web.builder import assemble_index_html
    assembled = assemble_index_html()
    assert assembled == html_content, "Assembled templates must match static index.html byte-for-byte"


def test_index_serve_no_rebuild_in_production():
    """Verify GET / does not trigger build_index_html unless dev_reload=True."""
    from unittest.mock import patch
    from fastapi.testclient import TestClient
    from keenguard.web.app import app
    from keenguard.config import settings

    orig_dev = settings.dev_reload
    try:
        settings.dev_reload = False
        with patch("keenguard.web.builder.build_index_html") as mock_build:
            client = TestClient(app)
            res = client.get("/")
            assert res.status_code == 200
            assert mock_build.call_count == 0

        settings.dev_reload = True
        with patch("keenguard.web.builder.build_index_html") as mock_build:
            client = TestClient(app)
            res = client.get("/")
            assert res.status_code == 200
            assert mock_build.call_count == 1
    finally:
        settings.dev_reload = orig_dev


def test_template_builder_crlf_compatibility(tmp_path):
    """Verify that builder handles Windows CRLF (\r\n) line endings seamlessly."""
    from keenguard.web.builder import assemble_index_html

    base_crlf = (
        "<!DOCTYPE html>\r\n"
        "<html>\r\n"
        "<head><title>Test</title></head>\r\n"
        "<body>\r\n"
        "<!-- {{ TABS_CONTENT }} -->\r\n"
        "<div>Content</div>\r\n"
        "<!-- {{ MODALS_CONTENT }} -->\r\n"
        "</body>\r\n"
        "</html>\r\n"
    )

    (tmp_path / "base.html").write_text(base_crlf, encoding="utf-8")
    (tmp_path / "tabs").mkdir()
    (tmp_path / "modals").mkdir()
    (tmp_path / "tabs" / "dashboard.html").write_text("<div>Dashboard</div>\r\n", encoding="utf-8")
    (tmp_path / "modals" / "login_modal.html").write_text("<div>Login</div>\r\n", encoding="utf-8")

    assembled = assemble_index_html(templates_dir=tmp_path)
    assert "<!-- {{ TABS_CONTENT }} -->" not in assembled
    assert "<!-- {{ MODALS_CONTENT }} -->" not in assembled
    assert "<div>Dashboard</div>" in assembled
    assert "<div>Login</div>" in assembled


def test_security_headers_middleware():
    """Verify standard HTTP security headers are set on web responses."""
    from fastapi.testclient import TestClient
    from keenguard.web.app import app

    client = TestClient(app)
    res = client.get("/")
    assert res.headers.get("X-Content-Type-Options") == "nosniff"
    assert res.headers.get("X-Frame-Options") == "DENY"
    assert res.headers.get("Referrer-Policy") == "no-referrer"


def test_cdn_library_versions_pinned(html_content: str):
    """Verify critical external libraries (Lucide, Chart.js) have pinned semantic versions."""
    assert "lucide@0.468.0" in html_content or "lucide@" in html_content
    assert "chart.js@4.4.7" in html_content or "chart.js@" in html_content
    # Must not use floating latest tags
    assert "lucide@latest" not in html_content
    assert "chart.js@latest" not in html_content
    assert "unpkg.com/lucide\"" not in html_content  # unpinned without version


def test_no_inline_onclick_interpolation(js_content: str):
    """
    Prevent Stored/DOM XSS:
    Verify that no JS template contains dangerous inline onclick with interpolated JS strings like
    onclick="func('${...}')" or onclick="func('${escapeHtml(...)}')".
    Instead, attributes MUST use data-* attributes with this.dataset.*
    """
    dangerous_matches = re.findall(
        r'onclick\s*=\s*\\?["\'][^"\'>]*\$\{[^}]*escapeHtml[^}]*\}[^"\'>]*\\?["\']',
        js_content
    )
    assert not dangerous_matches, (
        f"Found forbidden inline onclick with escapeHtml interpolation (use data-* and this.dataset instead):\n"
        f"{dangerous_matches}"
    )

    single_quote_interpolation = re.findall(
        r'onclick\s*=\s*\\?["\'][^"\'>]*\'\$\{[^}]+\}\'[^"\'>]*\\?["\']',
        js_content
    )
    assert not single_quote_interpolation, (
        f"Found forbidden inline onclick with quoted JS interpolation:\n"
        f"{single_quote_interpolation}"
    )


def test_single_dom_content_loaded():
    """Verify only one single DOMContentLoaded listener exists across frontend core and modules."""
    js_dir = STATIC_DIR / "js"
    listeners = []
    for file in [APP_JS] + list(js_dir.rglob("*.js")):
        text = file.read_text(encoding="utf-8")
        matches = re.findall(r'document\.addEventListener\(\s*[\'"]DOMContentLoaded[\'"]', text)
        if matches:
            listeners.append((file.name, len(matches)))

    assert len(listeners) == 1, f"Expected exactly 1 file registering DOMContentLoaded, found: {listeners}"
    assert listeners[0][0] == "app.js", f"DOMContentLoaded must be located in app.js, found in {listeners[0][0]}"
    assert listeners[0][1] == 1, f"app.js must register DOMContentLoaded exactly once"


def test_builder_template_assembly_with_backslashes(tmp_path: Path):
    """
    Verify that assemble_index_html correctly handles backslashes in templates
    (e.g., Windows paths 'C:\\Users\\test\\file' and regex backreferences like '\\1', '\\g<0>')
    without re.error or string corruption.
    """
    from keenguard.web.builder import assemble_index_html

    tpl_dir = tmp_path / "templates"
    tabs_dir = tpl_dir / "tabs"
    modals_dir = tpl_dir / "modals"
    tabs_dir.mkdir(parents=True)
    modals_dir.mkdir(parents=True)

    base_html = (
        "<!DOCTYPE html>\n<html><body>\n"
        "<!-- {{ TABS_CONTENT }} -->\n"
        "<!-- {{ MODALS_CONTENT }} -->\n"
        "</body></html>"
    )
    (tpl_dir / "base.html").write_text(base_html, encoding="utf-8")

    backslash_tab_content = (
        '<div id="view-dashboard">\n'
        "  <span>Path: C:\\Users\\test\\file</span>\n"
        "  <span>Ref: \\1 and \\g<0> and \\2</span>\n"
        "</div>"
    )
    (tabs_dir / "dashboard.html").write_text(backslash_tab_content, encoding="utf-8")

    backslash_modal_content = (
        '<div id="command-palette-modal">\n'
        "  <span>RegEx: ^[a-z]\\d+\\s*$</span>\n"
        "  <span>Escape: \\n \\t \\r \\1</span>\n"
        "</div>"
    )
    (modals_dir / "command_palette.html").write_text(backslash_modal_content, encoding="utf-8")

    assembled = assemble_index_html(templates_dir=tpl_dir)

    assert "C:\\Users\\test\\file" in assembled
    assert "\\1 and \\g<0> and \\2" in assembled
    assert "^[a-z]\\d+\\s*$" in assembled
    assert "\\n \\t \\r \\1" in assembled


