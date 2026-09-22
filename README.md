# Blacksite

Experiments with [HolmesGPT](https://github.com/HolmesGPT/holmesgpt), local inference, agent harnesses, and MCP tools for an off-grid development setup.

![Off-grid coding workstation](assets/blacksite-homestead.png)

Currently includes vLLM configuration, a tool-calling check, and an output-token budget fix. Local MCP integrations are planned. Live inference and offline operation remain unverified.

## Setup

Requires Git and Python 3.9+. The included vLLM deployment requires Docker and a compatible Linux NVIDIA host.

```bash
git clone https://github.com/heavyblanketpizza/blacksite.git
cd blacksite
python3 scripts/upstream.py prepare --checkout ../blacksite-runtime
cd ../blacksite-runtime

cp examples/vllm/.env.example vllm.env
# Edit vllm.env for your model, GPU, and API key.
docker compose --env-file vllm.env \
  -f docker-compose.yaml -f docker-compose.vllm.yaml up --build -d
```

Preparation downloads the pinned upstream source and applies this project's changes. Offline use requires downloading images, packages, model weights, and reference data in advance.

Once the model is ready, check tool calling:

```bash
docker compose --env-file vllm.env \
  -f docker-compose.yaml -f docker-compose.vllm.yaml exec -T holmes \
  python - --base-url http://vllm:8000/v1 --model holmes-local < scripts/check_vllm.py
```

Settings: [environment variables](overlay/examples/vllm/.env.example) and [model configuration](overlay/examples/vllm/model_list.yaml). Keep the server's context limit aligned with `max_context_size`, and `max_tokens` below that limit.

## Development

`overlay/` contains project additions; `patches/` contains changes to upstream files. [upstream.json](upstream.json) pins the upstream commit and lists the files to export. The runtime checkout stays separate.

After editing the runtime checkout, export from the Blacksite root:

```bash
python3 scripts/upstream.py export --checkout ../blacksite-runtime
python3 scripts/upstream.py export --check --checkout ../blacksite-runtime
git diff
```

Add new runtime files to `added_files` and edited upstream files to `modified_files`. Paths are relative to the runtime checkout. `local_only_files` are excluded from export. Commit in Blacksite; keep the runtime checkout at the pinned commit.

## Tests

Repository workflow tests, from the Blacksite root:

```bash
python3 -m unittest discover -s tests -v
```

Application tests require Python 3.10–3.13 and Poetry:

```bash
cd ../blacksite-runtime
poetry install --with dev
poetry run pytest tests/core/test_vllm_backend.py \
  tests/core/test_llm_completion_max_tokens.py tests/test_check_vllm.py --no-cov
```

These tests mock inference calls. Use the tool-calling check above against a running model.

## License

HolmesGPT's [Apache 2.0 license](LICENSE) and [attribution](NOTICE) are retained.
