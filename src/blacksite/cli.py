"""The ``blacksite`` command: incidents, MCP servers, retrieval, and learning review."""

from __future__ import annotations

import argparse
import json
import os
import shutil
import sys
from pathlib import Path
from typing import Sequence

from . import __version__
from .audit.ledger import LedgerError
from .audit.provenance import VerifyError
from .auth.store import ROLES, AuthError
from .config import ConfigError, Settings, as_dict, feature_summary, load_settings
from .evidence.store import ARTIFACTS_DIR, INCIDENT_FILE, Evidence, EvidenceError
from .knowledge.index import KnowledgeError
from .learning.store import OUTCOMES, LearningError
from .llm import LLMError

from .modelserver import ModelServerError  # noqa: E402  (after the imports it depends on)

_ERRORS = (ConfigError, EvidenceError, KnowledgeError, LearningError, LLMError, ModelServerError, AuthError, LedgerError,
           VerifyError)
# Sample incidents shipped with the repository, used by `blacksite demo --samples`.
SAMPLES = Path(__file__).resolve().parents[2] / "tests" / "fixtures" / "incidents"


def main(argv: Sequence[str] | None = None) -> int:
    _safe_console()
    parser = _parser()
    args = parser.parse_args(argv)
    try:
        settings = load_settings(args.config, args.set)
        return args.handler(args, settings)
    except _ERRORS as exc:
        print(f"blacksite: {exc}", file=sys.stderr)
        return 1


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(prog="blacksite", description=__doc__)
    parser.add_argument("--version", action="version", version=f"blacksite {__version__}")
    parser.add_argument("--config", type=Path, help="TOML settings file (default: ./blacksite.toml if present)")
    parser.add_argument("--set", action="append", default=[], metavar="KEY=VALUE",
                        help="Override a setting, e.g. --set rag.enabled=true (repeatable)")
    commands = parser.add_subparsers(dest="command", required=True, metavar="command")

    command = commands.add_parser("config", help="Show effective settings and which features are on")
    command.set_defaults(handler=_config)

    command = commands.add_parser("new", help="Create an incident directory from files")
    command.add_argument("incident", type=Path)
    command.add_argument("files", type=Path, nargs="*", help="Logs, configs, or command output to copy in")
    command.add_argument("--title", required=True)
    command.add_argument("--description", default="")
    command.add_argument("--year", type=int, help="Year for log timestamps that omit it (syslog)")
    command.set_defaults(handler=_new)

    command = commands.add_parser("ingest", help="Index an incident's files and print a summary")
    command.add_argument("incident", type=Path)
    command.set_defaults(handler=_ingest)

    serve = commands.add_parser("serve", help="Run an MCP server over stdio")
    servers = serve.add_subparsers(dest="server", required=True, metavar="server")
    command = servers.add_parser("evidence", help="Read-only tools over one incident's files")
    command.add_argument("incident", type=Path)
    command.set_defaults(handler=_serve_evidence)
    command = servers.add_parser("knowledge", help="Library search and past incidents, per the switches")
    command.add_argument("--incident", type=Path, help="Match past incidents against this incident")
    command.set_defaults(handler=_serve_knowledge)
    command = servers.add_parser("model", help="Start llama.cpp or vLLM with the flags Blacksite needs")
    command.add_argument("--model", help="GGUF file (llama.cpp) or Hugging Face id or path (vLLM)")
    command.add_argument("--from-ollama", metavar="NAME", help="llama.cpp: reuse a model Ollama downloaded")
    command.add_argument("--binary", help="Path to llama-server or vllm")
    command.add_argument("--offline", action="store_true", help="vLLM: never contact Hugging Face")
    command.add_argument("--dry-run", action="store_true", help="Print the command instead of running it")
    command.add_argument("server_args", nargs="*", metavar="-- ARGS",
                         help="More options for the server, e.g. -- --tensor-parallel-size 2")
    command.set_defaults(handler=_serve_model)

    command = commands.add_parser("check", help="Check that the model server can run Blacksite")
    command.set_defaults(handler=_check)

    command = commands.add_parser("models", help="List the models on this computer for each model server")
    command.set_defaults(handler=_models)

    command = commands.add_parser("index", help="Build the knowledge index from rag.docs_dir")
    command.set_defaults(handler=_index)

    command = commands.add_parser("search", help="Try library retrieval from the command line")
    command.add_argument("query")
    command.add_argument("--top-k", type=int)
    command.set_defaults(handler=_search)

    command = commands.add_parser("investigate", help="Run the agent on an incident and print its work")
    command.add_argument("incident", type=Path)
    command.add_argument("--message", default="", help="What to tell the agent (default: investigate)")
    command.add_argument("--paste", type=Path, help="File with command output the agent asked for")
    command.add_argument("--reset", action="store_true", help="Forget the previous conversation")
    command.set_defaults(handler=_investigate)

    command = commands.add_parser("demo", help="Run the local web demo")
    command.add_argument("--incidents", type=Path, default=Path("var/incidents"), help="Where incidents are stored")
    command.add_argument("--host", default="127.0.0.1")
    command.add_argument("--port", type=int, default=8765)
    command.add_argument("--samples", action="store_true", help="Copy the sample incidents in if missing")
    command.add_argument("--open", action="store_true", help="Open the demo in the default browser")
    command.set_defaults(handler=_demo)

    command = commands.add_parser("context", help="Print the context the switches add to the agent's instructions")
    command.add_argument("--incident", type=Path)
    command.set_defaults(handler=_context)

    learn = commands.add_parser("learn", help="Record outcomes and review what Blacksite learned")
    actions = learn.add_subparsers(dest="action", required=True, metavar="action")
    command = actions.add_parser("record", help="Record what happened after following the guide")
    command.add_argument("incident", type=Path)
    command.add_argument("--outcome", required=True, choices=OUTCOMES)
    command.add_argument("--notes", default="")
    command.add_argument("--root-cause", default="", help="The confirmed root cause, if the guide was wrong")
    command.add_argument("--guide", type=Path, help="The guide the developer followed")
    command.set_defaults(handler=_record)
    command = actions.add_parser("reflect", help="Ask the model to propose a case and playbook updates")
    command.add_argument("incident", type=Path)
    command.add_argument("--force", action="store_true", help="Reflect again even if a case exists")
    command.set_defaults(handler=_reflect)
    command = actions.add_parser("review", help="List entries waiting for approval")
    command.set_defaults(handler=_review)
    command = actions.add_parser("approve", help="Approve cases or bullets by id")
    command.add_argument("ids", nargs="+")
    command.set_defaults(handler=_approve)
    command = actions.add_parser("reject", help="Reject cases or bullets by id")
    command.add_argument("ids", nargs="+")
    command.set_defaults(handler=_reject)
    command = actions.add_parser("list", help="List cases and playbook bullets")
    command.add_argument("--status")
    command.set_defaults(handler=_list)

    users = commands.add_parser("users", help="Create and manage the accounts that may use the web app")
    actions = users.add_subparsers(dest="action", required=True, metavar="action")
    command = actions.add_parser("add", help="Create an account and print its temporary password")
    command.add_argument("username")
    command.add_argument("--admin", action="store_true", help="Can manage accounts, settings, and the audit log")
    command.add_argument("--display-name", default="", help="Name shown in the app (default: the username)")
    command.set_defaults(handler=_users_add)
    command = actions.add_parser("list", help="List accounts")
    command.set_defaults(handler=_users_list)
    for name, text in (("reset-password", "Give the account a new temporary password"),
                       ("suspend", "Block the account and end its sessions"),
                       ("activate", "Unblock a suspended or locked account"),
                       ("reset-2fa", "Turn off two-step sign-in so it can be set up again"),
                       ("revoke-sessions", "Sign the account out everywhere")):
        command = actions.add_parser(name, help=text)
        command.add_argument("username")
        command.set_defaults(handler=_users_change, change=name)
    command = actions.add_parser("set-role", help="Make the account an admin or a member")
    command.add_argument("username")
    command.add_argument("role", choices=ROLES)
    command.set_defaults(handler=_users_change, change="set-role")

    audit = commands.add_parser("audit", help="Check or export the audit ledger")
    actions = audit.add_subparsers(dest="action", required=True, metavar="action")
    command = actions.add_parser("verify", help="Check every record and signed checkpoint")
    command.add_argument("--anchor", type=Path, action="append", default=[],
                         help="A signed anchor saved earlier (ledger-anchor.json); repeatable")
    command.add_argument("--export", type=Path, help="Check an exported ledger instead of this machine's")
    command.set_defaults(handler=_audit_verify)
    command = actions.add_parser("export", help="Write the ledger, checkpoints, and public key as JSON lines")
    command.add_argument("file", type=Path)
    command.set_defaults(handler=_audit_export)
    command = actions.add_parser("anchor", help="Sign the ledger head and print it, to keep a copy elsewhere")
    command.set_defaults(handler=_audit_anchor)

    command = commands.add_parser("verify", help="Check a guide's signed provenance (export folder or manifest)")
    command.add_argument("path", type=Path, help="A SOLUTION-* folder, or an incident's provenance/turn-N.json")
    command.add_argument("--key", type=Path, help="Public key file (default: the export's, or this machine's)")
    command.set_defaults(handler=_verify)
    return parser


def _config(args: argparse.Namespace, settings: Settings) -> int:
    for name, state in feature_summary(settings).items():
        print(f"{name:<9} {state}")
    print()
    print(json.dumps(as_dict(settings), indent=2))
    return 0


def _new(args: argparse.Namespace, settings: Settings) -> int:
    target = args.incident
    if target.exists() and any(target.iterdir()):
        raise EvidenceError(f"{target} already exists and is not empty")
    artifacts = target / ARTIFACTS_DIR
    artifacts.mkdir(parents=True, exist_ok=True)
    for source in args.files:
        if source.is_dir():
            shutil.copytree(source, artifacts / source.name, symlinks=True)
        elif source.is_file():
            shutil.copy2(source, artifacts / source.name)
        else:
            raise EvidenceError(f"No such file: {source}")
    meta = {"id": target.name, "title": args.title, "description": args.description}
    if args.year:
        meta["year"] = args.year
    (target / INCIDENT_FILE).write_text(json.dumps(meta, indent=2) + "\n", encoding="utf-8")
    print(f"Created {target} with {len(args.files)} item{'' if len(args.files) == 1 else 's'} in {ARTIFACTS_DIR}/")
    return 0


def _ingest(args: argparse.Namespace, settings: Settings) -> int:
    from .evidence.server import format_artifacts

    with Evidence(args.incident, settings.evidence) as evidence:
        evidence.refresh()
        print(format_artifacts(evidence))
    return 0


def _serve_evidence(args: argparse.Namespace, settings: Settings) -> int:
    from .evidence.server import build_evidence_server

    with Evidence(args.incident, settings.evidence) as evidence:
        evidence.refresh()
        build_evidence_server(evidence, settings.evidence).run("stdio")
    return 0


def _serve_knowledge(args: argparse.Namespace, settings: Settings) -> int:
    from .knowledge.server import build_knowledge_server

    evidence = Evidence(args.incident, settings.evidence) if args.incident else None
    try:
        print(f"blacksite-knowledge: {_features(settings)}", file=sys.stderr)
        build_knowledge_server(settings, evidence).run("stdio")
    finally:
        if evidence is not None:
            evidence.close()
    return 0


def _serve_model(args: argparse.Namespace, settings: Settings) -> int:
    import shlex

    from .modelserver import plan, run

    launch = plan(settings, args.model, args.from_ollama, args.binary, args.offline, args.server_args)
    added = [f"{name}={shlex.quote(value)}" for name, value in launch.env.items() if os.environ.get(name) != value]
    printable = " ".join([*added, *(shlex.quote(part) for part in launch.command)])
    if args.dry_run:
        print(printable)
        return 0
    print(f"Starting: {printable}", file=sys.stderr)
    return run(launch)


def _check(args: argparse.Namespace, settings: Settings) -> int:
    from .backends import DISPLAY
    from .check import run_checks

    model = settings.model
    print(f"Checking {DISPLAY[model.provider]} at {model.base_url} (model {model.name}, "
          f"thinking {settings.agent.thinking})")
    failed = 0
    for result in run_checks(settings):
        mark = "ok  " if result.ok else "FAIL"
        print(f"  {mark} {result.name:<16} {result.detail}  ({result.seconds:.1f} s)")
        if not result.ok:
            failed += 1
            if result.hint:
                print(f"       fix: {result.hint}")
    print("Ready for Blacksite." if not failed else f"{failed} check{'' if failed == 1 else 's'} failed.")
    return 1 if failed else 0


def _models(args: argparse.Namespace, settings: Settings) -> int:
    from dataclasses import replace

    import anyio
    import httpx

    from . import catalog
    from .backends import DEFAULT_URLS, DISPLAY, PROVIDERS, server_root

    for provider in PROVIDERS:
        url = settings.model.base_url if settings.model.provider == provider else DEFAULT_URLS[provider]
        if provider == "ollama":
            try:
                models = anyio.run(catalog.ollama_models, server_root(replace(settings.model, base_url=url)))
            except (httpx.HTTPError, ValueError):
                print(f"{DISPLAY[provider]}: not running at {url}\n")
                continue
        else:
            models = catalog.gguf_models() if provider == "llamacpp" else catalog.hf_models()
        print(f"{DISPLAY[provider]} ({len(models)} model{'s' if len(models) != 1 else ''})")
        for model in models:
            reasons = {"no-tools": "no tool calling", "no-template": "no chat template in the file"}
            notes = [model.source] + ([reasons.get(model.note, model.note)] if not model.usable else [])
            if provider == "ollama":
                notes.append(f"context {model.context}" if model.context else "Ollama's context length")
            print(f"  {model.label:<36} {model.size / 1e9:5.1f} GB  {', '.join(notes)}")
            if provider != "ollama" and model.usable:
                print(f"      --set model.provider={provider} serve model --model {model.id}")
        print()
    return 0


def _index(args: argparse.Namespace, settings: Settings) -> int:
    from .context import open_index

    count = open_index(settings).build()
    print(f"Indexed {count} passages from {settings.rag.docs_dir} into {settings.rag.index_path}")
    return 0


def _search(args: argparse.Namespace, settings: Settings) -> int:
    from .context import format_hits, open_index

    hits = open_index(settings).search(args.query, args.top_k)
    print(format_hits(hits, settings.evidence.max_output_chars) if hits else "No passages match.")
    return 0


def _context(args: argparse.Namespace, settings: Settings) -> int:
    from .context import build_context

    print(f"# {_features(settings)}", file=sys.stderr)
    if args.incident:
        with Evidence(args.incident, settings.evidence) as evidence:
            text = build_context(settings, evidence)
    else:
        text = build_context(settings)
    if text:
        print(text)
    return 0


def _investigate(args: argparse.Namespace, settings: Settings) -> int:
    import anyio

    from .agent.investigator import CONVERSATION_FILE, Investigator

    if args.reset:
        (args.incident / CONVERSATION_FILE).unlink(missing_ok=True)
    pasted = args.paste.read_text(encoding="utf-8") if args.paste else ""
    investigator = Investigator(settings, args.incident, args.config, args.set)
    dim, bold, reset = ("\033[2m", "\033[1m", "\033[0m") if _colors() else ("", "", "")

    async def run() -> int:
        status = 0
        thinking = False
        async for event in investigator.turn(args.message, pasted):
            kind = event["type"]
            if kind == "thinking":
                if not thinking:
                    print(f"{dim}thinking: ", end="")
                    thinking = True
                print(event["delta"], end="", flush=True)
                continue
            if thinking:
                print(reset)
                thinking = False
            if kind == "start":
                print(f"{bold}{event['model']}{reset} ({_features(settings)}; thinking {event['thinking']})")
            elif kind == "text":
                print(event["delta"], end="", flush=True)
            elif kind == "tool_call":
                print(f"\n{dim}[{event['t']:>5}s]{reset} {bold}\u2192 {event['name']}{reset} {json.dumps(event['args'])}")
            elif kind == "tool_result":
                lines = event["content"].splitlines()
                shown = "\n".join(f"  {line[:160]}" for line in lines[:8])
                more = f"\n  \u2026 {len(lines) - 8} more lines" if len(lines) > 8 else ""
                print(f"{dim}{shown}{more}{reset} ({event['ms']} ms)")
            elif kind == "retry":
                print(f"\n{dim}[{event['t']:>5}s]{reset} {bold}checks sent the answer back:{reset} {event['reason'][:400]}")
            elif kind == "guide":
                print(f"\n{dim}[{event['t']:>5}s] guide ready{reset}\n" + event["markdown"])
            elif kind == "question":
                request = event["request"]
                print(f"\n{bold}The agent needs more information:{reset} {request['reason']}")
                for question in request["questions"]:
                    print(f"  ? {question}")
                for command in request["commands"]:
                    print(f"  $ {command}")
                print(f"Reply with: blacksite investigate {args.incident} --paste output.txt")
            elif kind == "done":
                print(f"\n{dim}{event['seconds']} s, {event['requests']} model calls, {event['tool_calls']} tool calls, "
                      f"{event['input_tokens']} in / {event['output_tokens']} out tokens{reset}")
            elif kind == "error":
                print(f"\nblacksite: {event['message']}", file=sys.stderr)
                status = 1
        return status

    return anyio.run(run)


def _demo(args: argparse.Namespace, settings: Settings) -> int:
    from .web.app import serve

    if args.samples:
        if not SAMPLES.is_dir():
            print(f"blacksite: no sample incidents at {SAMPLES}; run from a source checkout", file=sys.stderr)
        else:
            args.incidents.mkdir(parents=True, exist_ok=True)
            for sample in sorted(SAMPLES.iterdir()):
                if sample.is_dir() and not (args.incidents / sample.name).exists():
                    shutil.copytree(sample, args.incidents / sample.name)
                    print(f"Added sample incident {sample.name}")
    if args.open:
        import threading
        import webbrowser

        threading.Timer(1.5, webbrowser.open, [f"http://{args.host}:{args.port}"]).start()
    serve(args.config, args.set, args.incidents, args.host, args.port)
    return 0


def _record(args: argparse.Namespace, settings: Settings) -> int:
    from .learning.reflect import record_outcome

    if not (args.incident / ARTIFACTS_DIR).is_dir():
        raise EvidenceError(f"{args.incident} is not an incident directory")
    path = record_outcome(args.incident, args.outcome, args.notes, args.root_cause, args.guide)
    print(f"Recorded {args.outcome} in {path}. Next: blacksite learn reflect {args.incident}")
    return 0


def _reflect(args: argparse.Namespace, settings: Settings) -> int:
    from .context import open_store
    from .learning.reflect import reflect
    from .llm import ChatClient

    chat = ChatClient(settings.model, thinking=settings.agent.thinking)
    try:
        with Evidence(args.incident, settings.evidence) as evidence:
            report = reflect(evidence, open_store(settings), chat, settings, force=args.force)
    finally:
        chat.close()
    state = "approved" if report.approved else "waiting for review"
    print(f"Case {report.case_id} {state}.")
    playbook = report.playbook
    for label, items in (("Added", playbook.added), ("Merged into", playbook.merged),
                         ("Tagged", playbook.tagged), ("Retired", playbook.retired),
                         ("Ignored", playbook.ignored)):
        if items:
            print(f"{label}: {', '.join(items)}")
    if not report.approved:
        print("Review with: blacksite learn review")
    return 0


def _review(args: argparse.Namespace, settings: Settings) -> int:
    from .context import open_store

    store = open_store(settings)
    cases, bullets = store.cases("pending"), store.bullets("pending")
    if not cases and not bullets:
        print("Nothing waiting for review.")
        return 0
    for case in cases:
        print(f"{case.id}  {case.outcome}  incident {case.incident}: {case.title}")
        print(f"    symptoms: {case.symptoms}\n    root cause: {case.root_cause}\n    resolution: {case.resolution}")
        for lesson in case.lessons:
            print(f"    lesson: {lesson}")
    for bullet in bullets:
        print(f"{bullet.id}  {bullet.section}: {bullet.text}  (from {bullet.source})")
    print("\nApprove with: blacksite learn approve ID...   Reject with: blacksite learn reject ID...")
    return 0


def _approve(args: argparse.Namespace, settings: Settings) -> int:
    from .context import open_store

    return _report_change("Approved", args.ids, open_store(settings).approve(args.ids))


def _reject(args: argparse.Namespace, settings: Settings) -> int:
    from .context import open_store

    return _report_change("Rejected", args.ids, open_store(settings).reject(args.ids))


def _list(args: argparse.Namespace, settings: Settings) -> int:
    from .context import open_store

    store = open_store(settings)
    for case in store.cases(args.status):
        print(f"{case.id}  {case.status:<8}  {case.outcome:<12}  {case.title}")
    for bullet in store.bullets(args.status):
        print(f"{bullet.id}  {bullet.status:<8}  +{bullet.helpful}/-{bullet.harmful}  {bullet.section}: {bullet.text}")
    return 0


def _services(settings: Settings):
    from .services import Services

    return Services.open(settings)


def _users_add(args: argparse.Namespace, settings: Settings) -> int:
    from .services import cli_actor

    services = _services(settings)
    role = "admin" if args.admin else "member"
    user, temporary = services.access.create_user(args.username, args.display_name, role, cli_actor())
    services.ledger.append("admin.user_created", actor=cli_actor(), target=user.actor(), detail={"role": role})
    print(f"Created {role} {user.username} ({user.display_name}).")
    print(f"Temporary password (shown once): {temporary}")
    print("They must choose a new password at first sign-in" +
          (", then set up two-step sign-in with an authenticator app."
           if args.admin and settings.auth.totp_enabled else "."))
    return 0


def _users_list(args: argparse.Namespace, settings: Settings) -> int:
    users = _services(settings).access.users()
    if not users:
        print("No accounts yet. Create the first admin with: blacksite users add NAME --admin")
        return 0
    print(f"{'USERNAME':<20} {'NAME':<20} {'ROLE':<7} {'STATUS':<10} {'2FA':<4} LAST SIGN-IN")
    for user in users:
        print(f"{user.username:<20} {user.display_name:<20} {user.role:<7} {user.status:<10} "
              f"{'on' if user.totp_enabled else 'off':<4} {user.last_login_at or 'never'}")
    return 0


def _users_change(args: argparse.Namespace, settings: Settings) -> int:
    from .services import cli_actor

    services = _services(settings)
    access = services.access
    user = access.find(args.username)
    if user is None:
        raise AuthError(f"No account named {args.username!r}.")
    actor = cli_actor()
    if args.change == "reset-password":
        temporary, ended = access.reset_password(user.id)
        services.ledger.append("admin.password_reset", actor=actor, target=user.actor(), detail={"sessions": len(ended)})
        print(f"Reset the password for {user.username} and signed them out.")
        print(f"Temporary password (shown once): {temporary}")
        return 0
    if args.change == "suspend":
        ended = access.set_status(user.id, "suspended")
        action, detail, message = "admin.user_suspended", {"sessions": len(ended)}, f"Suspended {user.username}."
    elif args.change == "activate":
        access.set_status(user.id, "active")
        action, detail, message = "admin.user_activated", {}, f"Activated {user.username}."
    elif args.change == "reset-2fa":
        ended = access.reset_totp(user.id)
        action, detail = "admin.totp_reset", {"sessions": len(ended)}
        message = f"Two-step sign-in for {user.username} is off; they set it up again at next sign-in."
    elif args.change == "revoke-sessions":
        ended = access.end_user_sessions(user.id, "revoked")
        action, detail, message = "admin.session_revoked", {"sessions": len(ended)}, f"Ended {len(ended)} session(s)."
    else:
        ended = access.set_role(user.id, args.role)
        action, detail, message = "admin.role_changed", {"role": args.role}, f"{user.username} is now {args.role}."
    services.ledger.append(action, actor=actor, target=user.actor(), detail=detail)
    print(message)
    return 0


def _audit_verify(args: argparse.Namespace, settings: Settings) -> int:
    from .audit.ledger import verify_export
    from .services import cli_actor

    anchors = [json.loads(path.read_text(encoding="utf-8")) for path in args.anchor]
    if args.export:
        result = verify_export(args.export, anchors)
    else:
        services = _services(settings)
        result = services.ledger.verify(anchors=anchors)
        services.ledger.append("audit.verified", actor=cli_actor(), detail={
            "ok": result.ok, "records": result.records, "first_bad": result.first_bad})
    print(result.reason)
    if result.last_checkpoint:
        checkpoint = result.last_checkpoint
        print(f"Last signed checkpoint: record {checkpoint['seq']} at {checkpoint['at']}")
    if result.key_fingerprint:
        print(f"Signing key: {result.key_fingerprint}")
    return 0 if result.ok else 1


def _audit_export(args: argparse.Namespace, settings: Settings) -> int:
    from .services import cli_actor

    services = _services(settings)
    count = services.ledger.export(args.file)
    services.ledger.append("audit.exported", actor=cli_actor(), detail={"records": count})
    print(f"Wrote {count} records to {args.file}. Check it anywhere with: blacksite audit verify --export {args.file}")
    return 0


def _audit_anchor(args: argparse.Namespace, settings: Settings) -> int:
    ledger = _services(settings).ledger
    anchor = ledger.checkpoint() or ledger.anchor()
    print(f"Anchor: record {anchor['seq']}, fingerprint {anchor['fingerprint']}")
    print(json.dumps(anchor, indent=2))
    return 0


def _verify(args: argparse.Namespace, settings: Settings) -> int:
    from .audit import provenance
    from .agent.investigator import CONVERSATION_FILE

    path = args.path
    guide = None
    incident_dir = None
    anchor = None
    try:
        if path.is_dir():
            manifest_path = path / "provenance.json"
            key_path = args.key or path / "blacksite-signing-key.pub"
            exported = path / "manifest.json"
            if exported.is_file():
                guide = json.loads(exported.read_text(encoding="utf-8")).get("guide")
            if (path / "ledger-anchor.json").is_file():
                anchor = json.loads((path / "ledger-anchor.json").read_text(encoding="utf-8"))
        else:
            manifest_path = path
            key_path = args.key or settings.auth.keys_dir / "signing.pub"
            if path.parent.name == provenance.MANIFEST_DIR:
                incident_dir = path.parent.parent
        manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
        pem = key_path.read_bytes()
        if incident_dir is not None and (incident_dir / CONVERSATION_FILE).is_file():
            turns = json.loads((incident_dir / CONVERSATION_FILE).read_text(encoding="utf-8")).get("turns", [])
            index = int(manifest.get("turn", 0)) - 1
            if 0 <= index < len(turns):
                found = provenance._guide_event(turns[index].get("events", []))
                guide = found.get("guide") if found else None
        result = provenance.check(manifest, pem, incident_dir, guide)
    except (OSError, ValueError, KeyError) as exc:
        raise VerifyError(f"Cannot check {path}: {exc}") from None
    print(f"Signature: {'valid' if result['signature'] else 'INVALID'} (key {result['key_fingerprint']})")
    print("Guide: " + {True: "matches", False: "does not match", None: "not checked"}[result["guide"]])
    if result["evidence"] == "unknown":
        print("Evidence: not checked (the evidence files are not here)")
    elif result["evidence"] == "unchanged":
        print(f"Evidence: unchanged ({len(result['files'])} files)")
    else:
        changed = [f"{item['file']} ({item['status']})" for item in result["files"] if item["status"] != "unchanged"]
        print(f"Evidence: changed: {', '.join(changed)}")
    print(f"Run: {manifest.get('actor')}, turn {manifest.get('turn')}, finished {manifest.get('finished_at')}, "
          f"model {manifest.get('model', {}).get('name')}")
    ledger_anchor = manifest.get("ledger_anchor") or {}
    print(f"Ledger at signing: record {ledger_anchor.get('seq')}")
    if anchor:
        print(f"Ledger checkpoint in this folder: record {anchor.get('seq')}, fingerprint {anchor.get('fingerprint')}")
    print("Compare the key fingerprint with Admin > Security health on the Blacksite machine.")
    ok = result["signature"] and result["guide"] is not False and result["evidence"] != "changed"
    return 0 if ok else 1


def _report_change(verb: str, requested: list[str], changed: list[str]) -> int:
    if changed:
        print(f"{verb}: {', '.join(changed)}")
    skipped = [item for item in requested if item not in changed]
    if skipped:
        print(f"Unchanged (not found or already in that state): {', '.join(skipped)}", file=sys.stderr)
    return 0 if changed else 1


def _safe_console() -> None:
    """Never crash printing symbols such as \u26a0 to a console that cannot show them.

    Windows consoles and pipes may use a legacy code page (cp1252, cp949); Python's UTF-8
    mode is not the default there before Python 3.15.
    """
    for stream in (sys.stdout, sys.stderr):
        encoding = (getattr(stream, "encoding", None) or "").lower().replace("-", "").replace("_", "")
        if encoding != "utf8" and hasattr(stream, "reconfigure"):
            stream.reconfigure(errors="replace")


def _colors() -> bool:
    """ANSI styling only for terminals known to support it, and never with NO_COLOR set."""
    if os.environ.get("NO_COLOR") or not sys.stdout.isatty():
        return False
    if os.name != "nt":
        return True
    return any(os.environ.get(name) for name in ("WT_SESSION", "TERM_PROGRAM", "ANSICON", "ConEmuANSI"))


def _features(settings: Settings) -> str:
    return ", ".join(f"{name} {state}" for name, state in feature_summary(settings).items())


if __name__ == "__main__":
    sys.exit(main())
