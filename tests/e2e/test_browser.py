"""Smoke tests that drive the web app in Chromium: sign in, open an incident, investigate, follow a citation.

Deselected by default; run with ``uv run pytest -m e2e`` after ``uv run playwright install chromium``.
"""

import os
import shutil
import socket
import threading
import time
from collections.abc import Iterator
from pathlib import Path

import pytest

from conftest import INCIDENT, PASSWORD, add_account, write_web_config

pytestmark = pytest.mark.e2e


@pytest.fixture
def server(tmp_path: Path, monkeypatch) -> Iterator[str]:
    """The web app on a free local port with an admin account and the sample incident; yields its URL."""
    import uvicorn

    from blacksite.config import load_settings
    from blacksite.services import Services
    from blacksite.web.app import create_app

    from conftest import scripted_agent

    config = write_web_config(tmp_path)
    incidents = tmp_path / "incidents"
    shutil.copytree(INCIDENT, incidents / INCIDENT.name)
    scripted_agent(monkeypatch)
    services = Services.open(load_settings(config, environ={}))
    add_account(services, "admin", "admin", two_step=False)
    with socket.socket() as probe:
        probe.bind(("127.0.0.1", 0))
        port = probe.getsockname()[1]
    app = create_app(config, [], incidents, services=services)
    web = uvicorn.Server(uvicorn.Config(app, host="127.0.0.1", port=port, log_level="warning"))
    thread = threading.Thread(target=web.run, daemon=True)
    thread.start()
    deadline = time.time() + 10
    while not web.started and time.time() < deadline:
        time.sleep(0.02)
    assert web.started, "the web app did not start"
    yield f"http://127.0.0.1:{port}"
    web.should_exit = True
    thread.join(timeout=10)


@pytest.fixture
def page() -> Iterator:
    from playwright.sync_api import sync_playwright

    with sync_playwright() as playwright:
        executable = os.environ.get("BLACKSITE_E2E_BROWSER")
        browser = playwright.chromium.launch(executable_path=executable) if executable else playwright.chromium.launch()
        page = browser.new_page()
        failures: list[str] = []
        page.on("pageerror", lambda error: failures.append(str(error)))
        yield page
        browser.close()
        assert failures == [], failures


def test_sign_in_investigate_and_follow_a_citation(server: str, page) -> None:
    from playwright.sync_api import expect

    from blacksite.auth import totp

    page.goto(f"{server}/")
    expect(page).to_have_url(f"{server}/login")
    page.fill("input[name=username]", "admin")
    page.fill("input[name=password]", PASSWORD)
    page.click("button[type=submit]")
    # An admin's first sign-in sets up two-step sign-in: the key shown on the page yields the code.
    secret = page.locator("code.secret").text_content().replace(" ", "")
    page.fill("input[autocomplete=one-time-code]", totp.code_at(secret, totp.step_of(time.time())))
    page.click("button[type=submit]")
    expect(page.locator(".recovery-codes li")).to_have_count(10)
    page.check("#saved")
    page.click("button.login-submit")
    expect(page.locator("#user-name")).to_have_text("Admin")

    page.click("nav.nav a[data-view=incidents]")
    page.click("#incident-list .incident-item", timeout=10_000)
    expect(page.locator("#page h1")).to_contain_text("502")
    expect(page.locator("#send")).to_have_text("Investigate")

    page.click("#send")
    root_cause = page.locator(".root-cause")
    expect(root_cause).to_contain_text("unbounded report cache", timeout=30_000)
    expect(page.locator("#send")).to_have_text("Send")

    root_cause.locator("button.ref", has_text="app/app.log:3").click()
    expect(page.locator("#evidence")).to_be_visible()
    focused = page.locator("#evidence-body .line.focus")
    expect(focused).to_have_count(1)
    expect(focused).to_contain_text("max_entries=unbounded")
