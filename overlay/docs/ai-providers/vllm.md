# vLLM

HolmesGPT can use a vLLM server through its OpenAI-compatible API. Run inference on a Linux GPU host, then connect Holmes from the same host, another machine, or Kubernetes. No vLLM Python dependency is needed in Holmes.

The repository includes a Docker Compose overlay using `Qwen/Qwen3-8B` and vLLM `v0.30.0-cu129`. These are configurable reference defaults, not a benchmarked model or hardware recommendation. The model must support tool calling, and the GPU must have enough memory for its weights and the configured context and concurrency.

## Run with Docker Compose

Use a Linux host with a supported NVIDIA GPU, a compatible NVIDIA driver, Docker Compose, and the [NVIDIA Container Toolkit](https://docs.nvidia.com/datacenter/cloud-native/container-toolkit/latest/install-guide.html). This CUDA deployment does not run on Apple Silicon; Holmes on a Mac can connect to a remote server using the configuration below.

From the repository root:

```bash
# Copy and edit the reference settings (vllm.env is ignored by Git).
cp examples/vllm/.env.example vllm.env

# Build Holmes from this checkout and start both services.
docker compose --env-file vllm.env \
  -f docker-compose.yaml -f docker-compose.vllm.yaml up --build -d

# The first start downloads the model and compiles the inference engine.
docker compose --env-file vllm.env \
  -f docker-compose.yaml -f docker-compose.vllm.yaml logs -f vllm
```

The inference API is at `http://localhost:8000/v1`, and Holmes is at `http://localhost:5050`. Both ports bind to loopback. Holmes waits for vLLM's health check before starting. Model files persist in the `vllm-huggingface-cache` named volume.

The overlay mounts `examples/vllm/holmes.yaml` and `examples/vllm/model_list.yaml` read-only. It selects the `vllm` model alias without modifying your host's `~/.holmes` files. Add your toolsets to the example config, or set `VLLM_HOLMES_CONFIG_FILE` to another config file containing `model: vllm`. The base Compose file still provides Kubernetes and cloud credential mounts; see [Docker configuration](../installation/docker-compose-installation.md#configuration).

**Verify tool calling:**

```bash
curl --fail http://localhost:8000/health
curl --fail http://localhost:5050/healthz

# Run the smoke check with the Holmes container's Python dependencies and key.
docker compose --env-file vllm.env \
  -f docker-compose.yaml -f docker-compose.vllm.yaml exec -T holmes \
  python - --base-url http://vllm:8000/v1 --model holmes-local < scripts/check_vllm.py
```

The smoke check requests a tool call, returns a synthetic tool result, and checks the model's final answer in both ordinary and streaming responses. It does not execute infrastructure tools. A healthy HTTP endpoint alone does not establish working tool calling.

With the repository's Python dependencies installed locally, you can also run `poetry run python scripts/check_vllm.py --base-url http://localhost:8000/v1 --model holmes-local`. It reads `VLLM_API_KEY` from the environment and defaults to `local-vllm`; export your configured key if you changed it in `vllm.env`.

Stop the services while retaining the downloaded model:

```bash
docker compose --env-file vllm.env \
  -f docker-compose.yaml -f docker-compose.vllm.yaml down
```

## Connect to an existing vLLM server

The server must expose `/v1/chat/completions` and serve a model with automatic tool calling enabled. For the reference model, the relevant server settings are:

```bash
vllm serve Qwen/Qwen3-8B \
  --served-model-name holmes-local \
  --enable-auto-tool-choice \
  --tool-call-parser hermes \
  --default-chat-template-kwargs '{"enable_thinking":false}' \
  --enable-prefix-caching \
  --max-model-len 32768
```

This uses Qwen3's bundled chat template and disables thinking by default. Set `VLLM_API_KEY` in the server environment if authentication is required, and use the same value in Holmes. For an endpoint without authentication, Holmes still needs a nonempty placeholder key. See [Qwen's vLLM guide](https://qwen.readthedocs.io/en/latest/deployment/vllm.html#parsing-tool-calls) and the [vLLM serve options](https://docs.vllm.ai/en/v0.30.0/cli/serve/).

=== "Holmes CLI"

    From this checkout, point the provided model list at the server:

    ```bash
    export VLLM_API_BASE="http://localhost:8000/v1"
    export VLLM_API_KEY="local-vllm"
    export MODEL_LIST_FILE_LOCATION="$PWD/examples/vllm/model_list.yaml"
    holmes ask "what pods are failing?" --model vllm
    ```

    For a remote host, replace `localhost` with the reachable endpoint. The Compose deployment binds to loopback, so an SSH tunnel also works: `ssh -L 8000:127.0.0.1:8000 user@gpu-host`. If using an installed CLI elsewhere, merge the following entry into `~/.holmes/model_list.yaml` and select it with `--model vllm`:

    ```yaml
    vllm:
      model: openai/holmes-local
      api_base: "{{ env.VLLM_API_BASE }}"
      api_key: "{{ env.VLLM_API_KEY }}"
      temperature: 0.7
      top_p: 0.8
      max_tokens: 4096
      custom_args:
        max_context_size: 32768
    ```

=== "Holmes Helm Chart"

    Point Holmes at an existing vLLM service. This configures the client; it does not deploy the inference server.

    ```yaml
    additionalEnvVars:
      - name: VLLM_API_KEY
        valueFrom:
          secretKeyRef:
            name: vllm-credentials
            key: api-key

    modelList:
      vllm:
        model: openai/holmes-local
        api_base: http://vllm.inference.svc.cluster.local:8000/v1
        api_key: "{{ env.VLLM_API_KEY }}"
        temperature: 0.7
        top_p: 0.8
        max_tokens: 4096
        custom_args:
          max_context_size: 32768

    config:
      model: vllm
    ```

    Create `vllm-credentials` in the Holmes namespace with the server's key, and replace the example service URL with your endpoint. For the Robusta Helm chart, nest these values under `holmes:`.

## Change the model or GPU settings

Edit `vllm.env`, then rerun the Compose `up` command. `VLLM_MODEL` selects the Hugging Face model; the API name stays `holmes-local`, so the Holmes model list does not need to change when weights change.

| Setting | Default | Purpose |
| --- | --- | --- |
| `VLLM_IMAGE` | `vllm/vllm-openai:v0.30.0-cu129` | Pinned server and CUDA image |
| `VLLM_MODEL` | `Qwen/Qwen3-8B` | Model weights to download |
| `VLLM_TOOL_CALL_PARSER` | `hermes` | Parser matching the model's tool-call format |
| `VLLM_TENSOR_PARALLEL_SIZE` | `1` | GPUs reserved and used by tensor parallelism |
| `VLLM_GPU_MEMORY_UTILIZATION` | `0.9` | GPU memory fraction allocated to the engine |
| `VLLM_MAX_NUM_SEQS` | `4` | Maximum concurrent sequences |
| `VLLM_PORT` | `8000` | Host loopback port for inference |
| `VLLM_API_KEY` | `local-vllm` | Shared API key for this local reference deployment |
| `HF_TOKEN` | Unset | Hugging Face token for gated or private models |

When switching model families, check the [vLLM tool-calling configuration](https://docs.vllm.ai/en/v0.30.0/features/tool_calling/) and update the parser, chat template, and thinking settings together. Ollama model names and storage files are not interchangeable with Hugging Face model IDs.

**Keep token limits aligned.** The example sets a total context of **32,768 tokens** and a per-response output limit of **4,096 tokens**. If changing context length, update both `--max-model-len` in `docker-compose.vllm.yaml` and `custom_args.max_context_size` in the model list (or Helm values). Keep `max_tokens` below the total context limit. These values must remain YAML numbers; quoted environment templates produce strings. The per-model `max_tokens` setting is sufficient; no global output-token override is needed.

If startup reports insufficient KV-cache memory, lower context length in both places, reduce concurrency, use compatible smaller/quantized weights, or add GPUs. If requests return text resembling tool calls instead of structured `tool_calls`, verify the model's parser and template and rerun the smoke check. Evaluate representative Holmes investigations before switching an existing deployment.
