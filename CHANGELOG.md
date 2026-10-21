# Changelog

Notable changes to Blacksite, in the format of [Keep a Changelog](https://keepachangelog.com/en/1.1.0/). The project follows [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Added

- Records that span several lines, such as stack traces and tracebacks, fold into the line that started them. Indexing also reads Apache, klog, journald JSON, `dmesg -T`, and Redis timestamps.
- Configuration files and command output (`df`, `free`, `ps`, `ss`, `netstat`, `systemctl status`, `uptime`) are kept verbatim and summarized as facts in `list_artifacts`.
- The `compare_windows` evidence tool reports the patterns that started, rose, or stopped in a time window.
- A large bundle is indexed one file per process, with progress shown in the web app and the CLI.
- A citation check that a cited line shows what the citation claims.
- Model profiles for Qwen3, Qwen3-Coder, gpt-oss, GLM, DeepSeek, Llama, Mistral, and Kimi set the thinking controls and server flags for each family; `model.family` overrides the detection.
- Guides and questions list hypotheses as confirmed, ruled out, or open.
- `blacksite eval` scores the agent on labeled incidents under presets that set the knowledge switches, and thirteen more sample incidents, all labeled.
- `blacksite bundle` writes an offline install bundle: wheels, lock, example config, model files, install notes, and a checksummed manifest with a standalone `verify.py`.
- ruff and mypy gate CI, a dependency audit runs on every push, browser tests drive the web app in Chromium, and tagged releases are built, attested, and published by a workflow.

## [0.1.0] - 2026-09-28

### Added

- Initial release: the investigation agent on Ollama, llama.cpp, or vLLM; the evidence index and its MCP server; runbook search, past incidents, and the playbook as switches; outcome reports and learning review; accounts, the audit ledger, and signed guide provenance; the USB workflow; the web app and CLI in English and Korean.

[Unreleased]: https://github.com/heavyblanketpizza/blacksite/compare/v0.1.0...HEAD
[0.1.0]: https://github.com/heavyblanketpizza/blacksite/releases/tag/v0.1.0
