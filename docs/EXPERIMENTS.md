# Experiments: is this useful when the internet is gone?

The question is practical: **at an off-grid homestead, with only the hardware,
power, software, and information already on hand, does a local coding agent help
me finish useful work?** The apocalypse is the premise; working code, time saved,
and recoverable failures are the evidence.

This is a proposed experiment backlog. It is not a claim that Blacksite already
provides an autonomous coding agent or an offline-ready homestead system.

## Starting point

The published work currently provides HolmesGPT configuration for local vLLM
inference, a Docker Compose overlay, a synthetic tool-calling probe, and a fix
for reserving the configured output-token budget in smaller context windows.

The repository-setup baseline on 2026-09-22 (Blacksite revision `54647ad`)
recorded 49 focused application tests with mocked inference and 11 repository
workflow tests passing, plus successful reconstruction from upstream. Those checks establish
neither live model quality nor disconnected operation. No live GPU run or
disconnected trial is recorded here yet. See the [README](../README.md) for the
commands; record new results against the exact revision tested.

MCP integrations, coding task fixtures, local knowledge retrieval, and the
failure drills below are experiments to build and evaluate.

## 1. Establish a useful baseline

Use the same self-contained task fixtures in three modes:

| Mode | What it measures |
| --- | --- |
| Human with local editor, tests, and saved references | What I can finish unaided by a model |
| Human plus local model chat | Whether suggestions help without agent tool access |
| Human plus HolmesGPT and an experimental tool harness | Whether tool use adds value beyond chat |

Start with small repository tasks: fix a seeded bug, extend a script, explain a
failure from saved logs, and repair a broken configuration. Define the expected
behavior and acceptance checks before running them. Keep each starting commit,
input, dependency set, and task prompt. Use matched variants or vary run order
so learning the answer in the first mode does not decide the comparison.

Record completed acceptance checks, regressions, elapsed time, human
interventions, and time spent reviewing or undoing changes. A plausible answer
is not a completed task. Include attempts where the model gets stuck or admits
it cannot finish.

## 2. Try a small local tool surface

First establish what HolmesGPT and the selected model actually support. Then
try local MCP servers or other adapters for a narrow set of operations: read a
fixture repository, search files, propose or apply a patch, and run its checks.
These are candidate capabilities, not existing Blacksite implementations.

Begin with read-only tools, then allow writes in disposable fixture copies.
Restrict commands, filesystem paths, output size, run time, and tool-call count.
Record the configuration and any human approvals alongside each run. Test
permission denials, unavailable tools, malformed arguments, and misleading
instructions in tool output. Check whether the agent explains the failure and
stays within its allowed scope.

Compare a minimal tool set with a larger one. More tools might improve task
completion, or might consume context and create more ways to fail.

## 3. Give it a local bookshelf

Prepare a small, versioned collection of project documentation, manuals, and
worked examples relevant to the fixtures. Compare no retrieval, ordinary file
search, and an experimental local retrieval service using the same questions.

Require answers to identify the local source used. Include missing information,
outdated instructions, and conflicting documents. Measure answer correctness,
retrieval/setup overhead, and whether the agent distinguishes a source-backed
answer from a guess. Keep private homestead details out of public fixtures.

## 4. Pull the internet plug, then restart

Stage the pinned source, model weights and tokenizer/config files, container
images, Python packages, tool binaries, and reference data while connected.
Record exact versions or hashes and the steps needed to start each service.
Preparation itself currently downloads upstream source on a fresh checkout.

First block external network access while retaining the intended local network.
Run the inference probe and selected tasks; capture unexpected external access
attempts and missing dependencies. Then stop and restart the stack, and finally
restart the host under the same restriction. A warm cached session and a cold
restart are separate results. Keep recovery copies before changing caches.

Success means the documented local startup procedure and task checks work after
restart without fetching anything. A failed download, authentication dependency,
or unavailable local service is a useful finding to fix and retest.

## 5. Find the limits that matter off-grid

Vary one constraint at a time: model/context size, memory, concurrency, response
budget, tool-call budget, or time limit. Record hardware and settings actually
used. Measure peak memory, startup latency, task latency, storage, and energy
where measurement is available; label estimates and unknowns explicitly.

Try a stopped inference server, interrupted task, and full fixture output
directory. Check whether work remains inspectable and whether recovery costs
less effort than starting over. Use disposable data for failure drills. Rank
configurations by useful tasks completed per time and energy spent, not just
response speed.

## Keep an experiment log

Change one major variable per comparison and repeat promising results. Save
sanitized prompts, tool traces, diffs, and test output so a future me can explain
what happened. Keep credentials and private machine data out of published logs.

```text
Run ID / date:
Question and expected success criteria:
Blacksite revision / upstream revision / fixture revision:
Hardware / OS / model revision / runtime and tool versions:
Mode / configuration / permissions / network restriction:
Staged artifacts and startup steps:
Prompt / inputs / local reference versions:
Acceptance results / regressions / human interventions:
Startup and task time / memory / energy (measured, estimated, or unknown):
Evidence paths (sanitized traces, diff, test output):
Failure, recovery, and next change:
```
