## What changes



## Why



## Checks

- [ ] `uv run ruff check && uv run mypy && uv run pytest` pass
- [ ] A test fails without the change
- [ ] README and `CHANGELOG.md` are updated where behavior changed
- [ ] Any new fixture is synthetic (see `tests/fixtures/README.md`) and, for an incident, labeled with an `expected` block
