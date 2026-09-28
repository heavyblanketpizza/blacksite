import shutil
import time
from pathlib import Path
from typing import Any

import anyio
import pytest
from mcp.client import Client
from mcp.server.mcpserver import MCPServer

from blacksite.config import Settings, load_settings

FIXTURES = Path(__file__).parent / "fixtures"
INCIDENT = FIXTURES / "incidents" / "nginx-502-oom"
KNOWLEDGE = FIXTURES / "knowledge"


@pytest.fixture(autouse=True)
def cheap_password_hashing(monkeypatch):
    """scrypt at full strength costs 128 MiB and a quarter second per hash; tests need neither."""
    from blacksite.auth import passwords

    monkeypatch.setattr(passwords, "N", 2**10)


class FakeClock:
    """Starts at the real time (files written during a test carry real timestamps) and moves only when told."""

    def __init__(self, start: float | None = None) -> None:
        self.now = float(int(time.time())) if start is None else start

    def __call__(self) -> float:
        return self.now

    def advance(self, seconds: float) -> None:
        self.now += seconds


@pytest.fixture
def clock() -> FakeClock:
    return FakeClock()


@pytest.fixture
def keys(tmp_path: Path):
    from blacksite.keys import Keys

    return Keys(tmp_path / "keys")


@pytest.fixture
def access(tmp_path: Path, keys, clock):
    from blacksite.auth.store import AccessStore
    from blacksite.config import AuthSettings

    return AccessStore(tmp_path / "access.sqlite", keys, AuthSettings(totp_enabled=True), clock=clock)


PASSWORD = "river-stone-lamp-42"
BASE_URL = "http://127.0.0.1:8765"


def add_account(services, username: str, role: str = "member", two_step: bool | None = None):
    """An account with PASSWORD; admins (or ``two_step=True``) get an authenticator already set up."""
    from blacksite.auth import totp

    user, _ = services.access.create_user(username, username.title(), role, "test", password=PASSWORD,
                                          must_change=False)
    secret = None
    if role == "admin" if two_step is None else two_step:
        secret = services.access.totp_setup(user.id)
        services.access.totp_enroll(user.id, totp.code_at(secret, totp.step_of(services.access.clock())))
    return user, secret


def sign_in(client, username: str, role: str = "member", two_step: bool | None = None):
    """Create an account and sign ``client`` in through the real endpoints; sends its CSRF token from then on."""
    from blacksite.auth import totp

    services = client.app.state.demo.services
    user, secret = add_account(services, username, role, two_step)
    response = client.post("/auth/login", json={"username": username, "password": PASSWORD})
    assert response.status_code == 200, response.text
    data = response.json()
    if data["stage"] == "totp":  # enrollment used this step's code, so use the next one
        code = totp.code_at(secret, totp.step_of(services.access.clock()) + 1)
        data = client.post("/auth/totp/verify", json={"code": code}, headers={"X-CSRF-Token": data["csrf"]}).json()
    assert data["stage"] == "full", data
    client.headers["X-CSRF-Token"] = data["csrf"]
    return user


def write_web_config(tmp_path: Path) -> Path:
    config = tmp_path / "blacksite.toml"
    config.write_text(
        '[model]\nprovider = "vllm"\nbase_url = "http://127.0.0.1:9/v1"\nname = "test"\n'
        f'[rag]\ndocs_dir = "{KNOWLEDGE.as_posix()}"\n'  # backslashes would be TOML escapes
        '[learning]\nstore_path = "learning.sqlite"\n'
        '[auth]\ntotp_enabled = true\n',
        encoding="utf-8",
    )
    return config


def scripted_agent(monkeypatch) -> None:
    """Every investigation streams the sample guide instead of calling a model."""
    from pydantic_ai.models.function import FunctionModel

    from blacksite.agent import investigator as investigator_module
    from test_agent import GUIDE

    async def stream(messages, info):
        for start in range(0, len(GUIDE), 300):
            yield GUIDE[start:start + 300]

    monkeypatch.setattr(investigator_module, "agent_model", lambda settings: FunctionModel(stream_function=stream))


class Web:
    """The web app with an admin signed in (``admin``); ``client(name)`` signs in more people."""

    def __init__(self, app, services, clock, config: Path, incidents: Path) -> None:
        self.app, self.services, self.clock, self.config, self.incidents = app, services, clock, config, incidents
        self.admin = None

    def anonymous(self):
        from starlette.testclient import TestClient

        return TestClient(self.app, base_url=BASE_URL)

    def client(self, username: str, role: str = "member", two_step: bool | None = None):
        client = self.anonymous()
        sign_in(client, username, role, two_step)
        return client


@pytest.fixture
def web(tmp_path: Path, monkeypatch, clock):
    from starlette.testclient import TestClient

    from blacksite.services import Services
    from blacksite.web.app import create_app

    config = write_web_config(tmp_path)
    incidents = tmp_path / "incidents"
    incidents.mkdir()
    shutil.copytree(INCIDENT, incidents / "nginx-502-oom")
    scripted_agent(monkeypatch)
    services = Services.open(load_settings(config, environ={}), clock=clock)
    app = create_app(config, [], incidents, services=services)
    harness = Web(app, services, clock, config, incidents)
    with TestClient(app, base_url=BASE_URL) as admin:
        sign_in(admin, "admin", "admin")
        harness.admin = admin
        yield harness


@pytest.fixture
def incident_dir(tmp_path: Path) -> Path:
    """A private copy of the sample incident, so indexes never land in the repository."""
    target = tmp_path / "incidents" / "nginx-502-oom"
    shutil.copytree(INCIDENT, target)
    return target


@pytest.fixture
def make_settings(tmp_path: Path):
    """Settings rooted in tmp_path, with the sample runbooks as the library."""

    def make(*overrides: str) -> Settings:
        docs = tmp_path / "knowledge"
        if not docs.exists():
            shutil.copytree(KNOWLEDGE, docs)
        return load_settings(overrides=overrides, environ={}, cwd=tmp_path)

    return make


def call_tool(server: MCPServer, name: str, arguments: dict[str, Any] | None = None) -> tuple[bool, str]:
    """Call a tool through a real MCP client session; returns (is_error, text)."""

    async def run() -> tuple[bool, str]:
        async with Client(server) as client:
            result = await client.call_tool(name, arguments or {})
            return result.is_error, "\n".join(block.text for block in result.content)

    return anyio.run(run)


def tool_names(server: MCPServer) -> set[str]:
    async def run() -> set[str]:
        async with Client(server) as client:
            return {tool.name for tool in (await client.list_tools()).tools}

    return anyio.run(run)
