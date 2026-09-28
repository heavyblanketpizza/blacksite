# Blacksite

[English](README.md) | [한국어](README.ko.md)

Offline incident analysis on local LLMs. Prepping for the post-AGI apocalypse from a blacksite homestead I don't own. Tin foil hat sold separately.

![Off-grid coding workstation](assets/blacksite-homestead.png)

Give Blacksite a server's logs, configs, and command output. It investigates with read-only tools and writes a repair guide with cited log lines, expected results, and rollback steps. It cannot run commands on your servers.

Runs on **Ollama, llama.cpp, or vLLM**, through a local web app or the CLI.

## Demo

https://github.com/user-attachments/assets/5cdedde4-ccf4-4289-a6a2-121e20cc82ed

A 59-second walkthrough: sign-in, evidence search, a live investigation, the cited guide, signature check, download, sharing, and audit verification. Qwen 3.8 27B runs on llama.cpp from local GGUF weights with a 64k context; the logs and accounts are synthetic. The video plays at 2×, and the 7-minute investigation at 15.5×. On-screen labels show the speed.

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

## Configuration

Pass a TOML file with `--config`:

| Server | Example |
| --- | --- |
| Ollama | [demo/blacksite.toml](demo/blacksite.toml) |
| llama.cpp | [demo/llamacpp.toml](demo/llamacpp.toml) |
| vLLM | [demo/vllm.toml](demo/vllm.toml) |

The web app's model picker lists local models. `blacksite serve model --help` shows how to start llama.cpp or vLLM. Check the model server before investigating:

```bash
uv run blacksite --config demo/blacksite.toml check
```

[blacksite.example.toml](blacksite.example.toml) documents every setting. Runbook retrieval, past-incident recall, and playbook lessons are off by default, and new learning entries need human approval.

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

- **Accounts.** Admins add members in **Admin → Members** or with `blacksite users add NAME`. New members replace their temporary password at first sign-in.
- **Two-step sign-in** is off for everyone, including enrolled accounts, whose authenticator setups and recovery codes are kept. To turn it on, set `auth.totp_enabled = true` and restart; existing sessions end. Admins must then use an authenticator app, and members may. Recovery codes cover a lost phone; `blacksite users reset-2fa NAME` resets enrollment.
- **Who sees what.** Members see incidents they created or that were shared with them. Admins see everything, and only admins change the model, agent switches, and learning approvals.
- **Audit ledger.** `var/audit.sqlite` records sign-ins, uploads, investigations, outcomes, shares, exports, and admin changes. Records are hash-chained and keyed, so edits, deletions, and reordering are detected. It stores ids, counts, and hashes, never evidence, prompts, passwords, or codes. Verify it with **Admin → Audit log → Verify chain** or `blacksite audit verify`, and note the anchor fingerprint from **Security health**.
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

Tests mock the model and need no GPU. Code lives in [src/blacksite](src/blacksite/); sample configs and runbooks in [demo](demo/).

## License

Apache 2.0. See [LICENSE](LICENSE).
