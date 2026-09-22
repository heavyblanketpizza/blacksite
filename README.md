# Blacksite

Experiments with running [HolmesGPT](https://github.com/HolmesGPT/holmesgpt) against local inference, starting with vLLM. The current work includes a Docker Compose deployment, example model configuration, a tool-calling smoke check, and a fix that makes Holmes reserve the configured output-token budget for smaller context windows.

This repository stores our additions and changes. The canonical HolmesGPT code, dependencies, generated files, credentials, and Git history stay in the ignored `holmesgpt/` checkout.

| Path | Contents |
| --- | --- |
| `overlay/` | Project files added to HolmesGPT, using their original relative paths |
| `patches/holmesgpt.patch` | Our edits to existing upstream code, tests, and documentation |
| `upstream.json` | Exact upstream commit and explicit list of files to export |
| `scripts/upstream.py` | Rebuild or export the project changes |
| `holmesgpt/` | Local working checkout; excluded from this public repository |

## Set up a checkout

Requires Git and Python 3.9 or later. The first preparation downloads the pinned upstream source, so do this while connected to the internet.

```bash
git clone https://github.com/heavyblanketpizza/blacksite.git
cd blacksite
python3 scripts/upstream.py prepare
cd holmesgpt
```

The upstream base is [`96715d65480cefc26a03ee5ac8408aa793204e53`](https://github.com/HolmesGPT/holmesgpt/commit/96715d65480cefc26a03ee5ac8408aa793204e53). Preparation applies the patch and copies the overlay files into the checkout. Repeating it with the same project files is a no-op; conflicting local edits cause an error instead of being overwritten.

Follow the [vLLM guide](overlay/docs/ai-providers/vllm.md) from inside `holmesgpt/`. Its relative links to other HolmesGPT documentation resolve in the prepared checkout. For the included Linux/NVIDIA deployment:

```bash
cp examples/vllm/.env.example vllm.env
# Edit vllm.env for your GPU, model, and API key.
docker compose --env-file vllm.env \
  -f docker-compose.yaml -f docker-compose.vllm.yaml up --build -d
```

This CUDA deployment needs a compatible Linux NVIDIA host. A Mac can run Holmes as a client of a remote inference server. Offline use also requires downloading the container images, Python dependencies, model weights, and any data/tooling you need in advance.

## Keep project changes in Git

Develop inside `holmesgpt/`, then export from the Blacksite root:

```bash
python3 scripts/upstream.py export
git diff
git add overlay patches upstream.json
git commit -m "Describe the project change"
git push
```

Only paths listed in `upstream.json` are exported. For a new file, add its path relative to `holmesgpt/` to `added_files`; for a new edit to an existing upstream file, add its path to `modified_files`. Review each path before exporting. Unlisted changes are reported so they cannot silently disappear from the public project or be published accidentally. Local `.env` files and credentials belong outside the export list; the committed `.env.example` contains reference placeholders only.

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

These tests mock inference HTTP calls. The [smoke check](overlay/scripts/check_vllm.py) in the vLLM guide separately verifies a running model server.

## Attribution

HolmesGPT is the upstream project. Its Apache 2.0 license is retained in [LICENSE](LICENSE); [NOTICE](NOTICE) identifies the project modifications. The public repository contains our new files and patch context, rather than a duplicate of the upstream source tree.
