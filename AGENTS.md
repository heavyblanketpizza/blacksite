# Blacksite development

Blacksite explores how useful a local coding agent could be after the internet
disappears and the user retreats to an off-grid homestead. HolmesGPT is the
starting point for experiments with agent harnesses, hardening, MCP tools,
local knowledge, and limited resources. Read `docs/PROJECT.md` for the purpose
and `docs/EXPERIMENTS.md` for the questions we are trying to answer.

Keep implemented features, proposed experiments, and observed results distinct.
Mocked tool calls do not establish live inference or offline readiness. Record
meaningful experiment outcomes and decisions in the project docs, including
failures and unresolved questions, so the next session can pick up the work.

This outer repository publishes only Blacksite's changes to HolmesGPT.
`holmesgpt/` is an ignored, independent upstream checkout, not a submodule.

- Run `python3 scripts/upstream.py prepare` to reconstruct the working checkout.
- Read `holmesgpt/AGENTS.md` before changing files inside that checkout.
- Develop and test in `holmesgpt/`, then run `python3 scripts/upstream.py export`
  from this root to save the project files in `overlay/` and `patches/`.
- Add newly changed paths to the appropriate list in `upstream.json` after
  reviewing them for publication. Do not add secrets, generated files, or
  unchanged upstream files.
- Run `python3 scripts/upstream.py export --check` before committing.
- Commit and push from this root. Keep the nested checkout's HEAD at the
  pinned upstream commit; do not change its origin to the Blacksite repository.
- Never force-add `holmesgpt/`, vendor its canonical source, or copy its Git
  history into this repository.

Workflow tests: `python3 -m unittest discover -s tests -v`.
The README documents the focused HolmesGPT tests and live inference check.
