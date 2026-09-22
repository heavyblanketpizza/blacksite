# Blacksite

Playing with [HolmesGPT](https://github.com/HolmesGPT/holmesgpt), agent harnesses and hardening, MCPs, and whatever else helps answer one question:

![Blacksite — an isometric pixel-art homestead with solar power, a garden, and a local AI coding desk](assets/blacksite-homestead.png)

**How useful could a local coding agent be after the internet dies in an apocalypse and I retreat to my off-grid homestead?**

The apocalypse gives the experiments a concrete constraint: the agent has to work with the compute, power, code, tools, and knowledge already on hand. Can it fix a small program, diagnose a local service, write a useful script, or find the right passage in a saved manual when downloading the missing piece is no longer an option?

Blacksite is a personal experiment. HolmesGPT is the starting point; local inference, tool access through the Model Context Protocol (MCP), memory, retrieval, and the surrounding agent harness are things to try and measure. The model, hardware, and eventual architecture are open questions.

## Things to try

- Compare working alone, local model chat, and an agent on the same small coding tasks.
- Try local MCP tools for reading code, making reviewable changes, and running checks.
- Give the agent a local bookshelf of saved documentation and see whether it can find reliable answers.
- Disconnect the internet, restart the stack, and find out which dependencies we forgot to bring.
- Measure useful work completed, human intervention, memory, latency, and energy where available.

The first offline scenario allows a working LAN. Model weights, packages, container images, source code, and reference material need to be prepared before the cutoff. Working from a warm cache, restarting offline, and recovering from saved artifacts are separate experiments.

## What exists today

The current work provides a vLLM Docker Compose deployment, example model configuration, a tool-calling smoke check, and a fix that makes Holmes reserve the configured output-token budget for smaller context windows. The project also includes a reproducible way to apply those additions to a pinned HolmesGPT checkout.

The repository-setup baseline on 2026-09-22 recorded 49 passing tests with mocked inference calls, 11 repository workflow tests, and successful reconstruction from upstream. Live GPU inference, useful coding performance, project-specific MCP servers, and operation through an actual internet cutoff remain to be demonstrated. A working HTTP endpoint or a passing mock test is only one part of the experiment.

## Repository layout

This repository stores our additions and changes. The canonical HolmesGPT code, dependencies, generated files, credentials, and Git history stay in the ignored `holmesgpt/` checkout.

| Path | Contents |
| --- | --- |
| `overlay/` | Project files added to HolmesGPT, using their original relative paths |
| `patches/holmesgpt.patch` | Our edits to existing upstream code and tests |
| `upstream.json` | Exact upstream commit and explicit list of files to export |
| `scripts/upstream.py` | Rebuild or export the project changes |
| `holmesgpt/` | Local working checkout; excluded from this public repository |

Only this README is published as Markdown. Supporting notes and local documentation edits stay outside the published files.

## Set up a checkout

Requires Git and Python 3.9 or later. The first preparation downloads the pinned upstream source, so do this while connected to the internet.

```bash
git clone https://github.com/heavyblanketpizza/blacksite.git
cd blacksite
python3 scripts/upstream.py prepare
cd holmesgpt
```

The upstream base is [`96715d65480cefc26a03ee5ac8408aa793204e53`](https://github.com/HolmesGPT/holmesgpt/commit/96715d65480cefc26a03ee5ac8408aa793204e53). Preparation applies the patch and copies the overlay files into the checkout. Repeating it with the same project files is a no-op; conflicting local edits cause an error instead of being overwritten.

From inside `holmesgpt/`, start the included Linux/NVIDIA deployment:

```bash
cp examples/vllm/.env.example vllm.env
# Edit vllm.env for your GPU, model, and API key.
docker compose --env-file vllm.env \
  -f docker-compose.yaml -f docker-compose.vllm.yaml up --build -d
```

This CUDA deployment needs a compatible Linux NVIDIA host. A Mac can run Holmes as a client of a remote inference server. Offline use also requires downloading the container images, Python dependencies, model weights, and any data/tooling you need in advance.

After the model server finishes loading, verify a tool-calling round trip:

```bash
docker compose --env-file vllm.env \
  -f docker-compose.yaml -f docker-compose.vllm.yaml exec -T holmes \
  python - --base-url http://vllm:8000/v1 --model holmes-local < scripts/check_vllm.py
```

The reference model settings live in [the example environment file](overlay/examples/vllm/.env.example) and [the model list](overlay/examples/vllm/model_list.yaml). Keep the server's total context limit and the model list's `max_context_size` aligned, with `max_tokens` below that limit.

## Keep project changes in Git

Develop inside `holmesgpt/`, then export from the Blacksite root:

```bash
python3 scripts/upstream.py export
git diff
git add overlay patches upstream.json
git commit -m "Describe the project change"
git push
```

Only paths listed for publication in `upstream.json` are exported. For a new code or configuration file, add its path relative to `holmesgpt/` to `added_files`; for a new edit to an existing upstream file, add its path to `modified_files`. `local_only_files` records documentation changes that may remain in the working checkout but are never exported or required by a fresh checkout. Keep supporting Markdown in that local-only category. Review each path before exporting. Unlisted changes are reported so they cannot silently disappear from the public project or be published accidentally. Local `.env` files and credentials belong outside the export list; the committed `.env.example` contains reference placeholders only.

```bash
# Verify that everything intended for publication matches the working checkout.
python3 scripts/upstream.py export --check

# Rebuild into a separate, empty location without touching your working checkout.
python3 scripts/upstream.py prepare --checkout /tmp/blacksite-check
python3 scripts/upstream.py export --check --checkout /tmp/blacksite-check
```

The upstream commit is deliberately pinned. Updating it requires reconciling the patch and file list against the new base before exporting again. Do not commit local changes in the nested checkout: export them and commit in Blacksite so its upstream HEAD remains at the pinned commit.

## Tests

Run the repository workflow tests from the Blacksite root:

```bash
python3 -m unittest discover -s tests -v
```

For the application tests, the pinned HolmesGPT version requires Python 3.10–3.13. Install its development dependencies in the prepared checkout:

```bash
cd holmesgpt
poetry install --with dev
poetry run pytest tests/core/test_vllm_backend.py \
  tests/core/test_llm_completion_max_tokens.py tests/test_check_vllm.py --no-cov
```

These tests mock inference HTTP calls. The [smoke check](overlay/scripts/check_vllm.py) shown above separately verifies a running model server.

## Attribution

HolmesGPT is the upstream project. Its Apache 2.0 license is retained in [LICENSE](LICENSE); [NOTICE](NOTICE) identifies the project modifications. The public repository contains our new files and patch context, rather than a duplicate of the upstream source tree.
