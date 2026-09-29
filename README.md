# Blacksite

[English](README.md) | [한국어](README.ko.md)

Offline incident analysis on local models. Prepping for the post-AGI apocalypse from a blacksite homestead I don't own. Tin foil hat sold separately.

Runs on **Ollama, llama.cpp, or vLLM**, through a local web app or the CLI.

## Demo

https://github.com/user-attachments/assets/07dc0837-7fa2-468e-a823-b9375bc70171

A 59-second walkthrough of sign-in, evidence search, a live investigation, the cited guide, signature check, download, sharing, and audit verification. Qwen 3.8 27B runs on llama.cpp from local GGUF weights with a 64k context, on synthetic logs and accounts. The video plays at 2×, and the 7-minute investigation at 15.5×, as the on-screen labels show.

## Quick start

Needs Python 3.11+, [uv](https://docs.astral.sh/uv/), and a running [Ollama](https://ollama.com) server. From the project directory:

```bash
uv sync --extra agent
ollama pull qwen3.8:27b-q4_K_M
ollama create blacksite-qwen3.8 -f demo/Modelfile
uv run blacksite --config demo/blacksite.toml users add admin --admin
uv run blacksite --config demo/blacksite.toml demo --incidents var/demo/incidents --samples --open
```

`users add` prints a temporary password once. Sign in at [localhost:8765](http://127.0.0.1:8765) and set your own. Open **Incidents**, pick one of the two samples, and click **Investigate**. Click any citation to see its source. The interface and guides are in English and Korean.

To run disconnected, fetch dependencies and model weights first, keep model endpoints local, and use `uv run --offline`.

## Investigate your own logs

Upload files in the web app, or use the CLI:

```bash
uv run blacksite new var/incidents/INC-1 path/to/app.log --title "API returns 502"
uv run blacksite --config demo/blacksite.toml investigate var/incidents/INC-1
```

If the agent asks for more evidence, run the suggested command yourself and pass back its output:

```bash
uv run blacksite --config demo/blacksite.toml investigate var/incidents/INC-1 --paste output.txt
```

`blacksite --help` lists every command.

## Configuration

Pass a TOML file with `--config`:

| Server | Example |
| --- | --- |
| Ollama | [demo/blacksite.toml](demo/blacksite.toml) |
| llama.cpp | [demo/llamacpp.toml](demo/llamacpp.toml) |
| vLLM | [demo/vllm.toml](demo/vllm.toml) |

[blacksite.example.toml](blacksite.example.toml) documents every setting. Override one with `--set section.key=value` or a `BLACKSITE__SECTION__KEY` environment variable; `blacksite config` prints the result.

Blacksite can find local models and start llama.cpp or vLLM with the flags it needs. Check the server before investigating:

```bash
uv run blacksite models
uv run blacksite --config demo/llamacpp.toml serve model --from-ollama qwen3.8:27b-q4_K_M
uv run blacksite --config demo/llamacpp.toml check
```

The web app's model picker lists the same models. Without a config file, Blacksite expects the model to be served as `blacksite`. Earlier versions expected `holmes-local`: if your server still uses that name, set `model.name = "holmes-local"` or restart it with `blacksite serve model`.

## Runbooks and learning

Three switches add team knowledge to an investigation. All start off, because extra context can also make an agent worse: turn one on after it beats the baseline on your own incidents. Admins set them for everyone in the web app's sidebar; the CLI reads the config file and `--set`.

| Switch | Setting | What the agent gets |
| --- | --- | --- |
| Runbook search | `rag.enabled` | Search over the Markdown and text runbooks in `rag.docs_dir` ([demo/knowledge](demo/knowledge/) in the demo) |
| Past incidents | `learning.cases.enabled` | Approved records of earlier incidents and what fixed them |
| Team playbook | `learning.playbook.enabled` | Approved lessons added to its instructions |

The agent calls runbook search and past incidents as tools when it wants them; set their `mode = "inject"` to add the top matches up front instead. Runbook search uses keyword ranking (BM25). `rag.retriever = "hybrid"` adds embeddings (install with `uv sync --extra hybrid`) and `rag.rerank = true` a reranker, each served from a local endpoint. The index rebuilds itself when runbooks change. Try it with `blacksite --config demo/blacksite.toml search "nginx 502"`.

Blacksite learns only from outcomes a person reports. After following a guide, answer **Did it work?** in the web app, or use the CLI:

```bash
uv run blacksite --config demo/blacksite.toml learn record var/incidents/INC-1 --outcome resolved --notes "rollback fixed it"
uv run blacksite --config demo/blacksite.toml learn reflect var/incidents/INC-1
uv run blacksite --config demo/blacksite.toml learn review
uv run blacksite --config demo/blacksite.toml learn approve ID...
```

The model drafts a case record and playbook lessons from the report. Nothing reaches the agent until an admin approves it in **Learning** or with `learn approve`.

## Use the tools from another agent

The agent sees evidence only through two MCP servers, and any MCP-capable harness can run them over stdio:

```bash
uv run blacksite serve evidence var/incidents/INC-1
uv run blacksite --config demo/blacksite.toml serve knowledge --incident var/incidents/INC-1
```

- **evidence** has five read-only tools over one incident: `list_artifacts`, `log_patterns`, `search_logs`, `read_lines`, and `timeline`.
- **knowledge** offers `search_docs` and `read_doc` when runbook search is on, and `recall_cases` when past incidents are on, in tool mode. With every switch off it has no tools, which is the baseline.

`blacksite context --incident DIR` prints what the switches add to the agent's instructions.

## USB workflow

The demo watches removable drives for this layout:

```text
<drive>/blacksite/
    api-502/
        incident.txt    # optional title and description
        app.log
        logs.tar.gz
```

Each incident is copied to a local sandbox and investigated. **Save to drive** writes an offline HTML guide, a Markdown guide, and a file manifest beside the evidence, then deletes the sandbox. Erasure on SSDs is best effort, so use full-disk encryption for sensitive evidence.

## Access and audit

The web app listens only on `127.0.0.1`, and only accounts an admin created can sign in. Run Blacksite under one OS account that alone can read `var/`, and have each person sign in from their own OS account.

- **Accounts.** Admins add members in **Admin → Members** or with `blacksite users add NAME`. New members replace their temporary password at first sign-in. `blacksite users --help` covers password resets, suspension, roles, and ending sessions.
- **Two-step sign-in** is off for everyone, and enrolled accounts keep their authenticator setups and recovery codes. To turn it on, set `auth.totp_enabled = true` and restart; existing sessions end. Admins must then use an authenticator app, and members may. Recovery codes cover a lost phone; `blacksite users reset-2fa NAME` resets enrollment.
- **Who sees what.** Members see incidents they created or that were shared with them. Admins see everything, and only admins change the model, the switches, and learning approvals.
- **Dashboard.** Open incidents, guides awaiting an outcome, resolved rate, median time to guide, model runs with verified citations, and team activity, limited to what the viewer may see.
- **Audit ledger.** `var/audit.sqlite` records sign-ins, uploads, investigations, outcomes, shares, exports, and admin changes. Records are hash-chained and keyed, so edits, deletions, and reordering are detected. They hold ids, counts, and hashes, never evidence, prompts, passwords, or codes. Verify the chain in **Admin → Audit log → Verify chain** or with `blacksite audit verify`, and note the anchor fingerprint from **Security health**.
- **Guide provenance.** Each guide carries a signed record of who ran it, the SHA-256 of every evidence file, and the model and settings. USB exports include it; check one on any computer with `blacksite verify <folder>`.

Keep `var/keys/` private and backed up. It holds the key that proves the ledger and guides came from this machine.

## Data and checks

- Indexing redacts recognized secrets and flags suspicious instructions in logs.
- Guide checks validate cited files and lines and flag risky commands. Review the guide and its warnings before acting.
- Inference requests go to the model endpoints you configure, including embedding and reranking servers when enabled.
- Runtime data lives in `var/`, which Git ignores. `tests/fixtures/` holds synthetic samples only; keep real evidence out.

## Development

```bash
uv run pytest
```

Tests mock the model and need no GPU. CI runs them on Linux, macOS, and Windows with Python 3.11 and 3.14.

| Path | Contents |
| --- | --- |
| [src/blacksite/agent](src/blacksite/agent/) | The investigation loop and the checks a guide passes before anyone sees it |
| [src/blacksite/evidence](src/blacksite/evidence/) | Log parsing, redaction, the evidence index, and its MCP server |
| [src/blacksite/knowledge](src/blacksite/knowledge/) | Runbook search and the knowledge MCP server |
| [src/blacksite/learning](src/blacksite/learning/) | Outcome reports, reflection, and the store of cases and lessons |
| [src/blacksite/auth](src/blacksite/auth/), [audit](src/blacksite/audit/) | Accounts and sign-in, the audit ledger, and guide provenance |
| [src/blacksite/web](src/blacksite/web/) | The web app: API, dashboard, admin console, and front end |
| [src/blacksite](src/blacksite/) | The CLI, settings, model servers and checks, USB mode, and exported reports |
| [tests](tests/) | The test suite, with synthetic sample incidents and runbooks in `tests/fixtures/` |
| [demo](demo/) | Example configs, the Ollama Modelfile, and sample runbooks |
| [scripts](scripts/) | Tools that record the demo videos and rebuild the banner |

## License

Apache 2.0. See [LICENSE](LICENSE).
