# Contributing

## Set up

Install [uv](https://docs.astral.sh/uv/) and run `uv sync` in the checkout. That installs Blacksite with the agent and hybrid extras plus the development tools. The tests mock the model and need no GPU.

## Before you push

```bash
uv run ruff check && uv run mypy && uv run pytest
```

CI runs the same checks on Linux, macOS, and Windows, audits the locked dependencies, and builds the wheel. The browser tests in `tests/e2e/` run separately with `uv run pytest -m e2e` after `uv run playwright install chromium` (set `BLACKSITE_E2E_BROWSER` to the path of a Chromium you already have). A change to the agent's instructions, the answer template, or the guide checks also deserves a run of `blacksite eval` against a real local model (see the README's Evaluation section), because the unit tests cannot judge the quality of a guide.

## Changes

- One change per pull request, with a test that fails without it.
- Keep the README in step with the code, and add a line under **Unreleased** in `CHANGELOG.md` when behavior changes.
- Everything under `tests/fixtures/` is synthetic and published with the repository: private or documentation addresses, reserved host names, secrets marked `EXAMPLE`. `tests/test_fixtures.py` enforces this, and `tests/fixtures/README.md` has the details. A new sample incident needs an `expected` block so `blacksite eval` can score it.
- Real evidence, credentials, keys, and model weights never go into the repository. Runtime data belongs in `var/`, which Git ignores.
