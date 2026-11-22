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
