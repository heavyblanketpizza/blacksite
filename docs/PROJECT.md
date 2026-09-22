# What Blacksite is about

## The premise

Play with HolmesGPT and experiment with agent harnesses, hardening, MCPs, and whatever else seems useful. Find out how much help a local coding agent could provide after the internet dies in an apocalypse and we retreat to an off-grid homestead.

That is the reason for the project. Keep it visible when a model integration, tool server, or configuration rabbit hole starts looking like the whole objective.

The useful question is practical: **with only what we have already brought along, can this agent help us get real work done?**

## What “useful” might mean

- Understand a small local codebase, make a reviewable fix, and run the available tests.
- Write or adapt a script for a local task using installed dependencies.
- Diagnose a broken local service using its configuration, logs, and available tools.
- Find relevant information in saved documentation and show where it came from.
- Preserve enough notes to resume work after a restart or a long gap.
- Recognize missing tools, missing information, and failed attempts without pretending the task succeeded.

Possible homestead-flavored fixtures include a local inventory app, a sensor-log parser, or a small service running on the LAN. These are candidate coding tasks; no homestead hardware or automation is implemented here yet.

## Working assumptions

The first scenario is **no internet, with a local machine and possibly a working LAN**. A local model server on another machine is allowed in that scenario. Complete isolation on one machine is a separate scenario to test.

Preparation happens while the internet still works. Model weights, container images, packages, repositories, documentation, and any required tools have to be obtained beforehand. Once disconnected, a task cannot quietly depend on a cloud model, package registry, account login, or remote MCP service.

Compute, memory, storage, and power are constraints to measure. We have not selected a final hardware budget or established acceptable latency, energy use, or task success rates. Write those limits down for each experiment.

The person remains part of the workflow: they choose the task, inspect changes, and decide whether a result is useful. Record how much intervention the agent needs; that is part of its performance.

## Things we are willing to explore

| Area | Question |
| --- | --- |
| Local inference | Which available model and serving setup can complete our tasks within the resources on hand? |
| Agent harness | What prompts, context selection, tool access, feedback loops, and memory make the model useful? |
| Hardening | What happens with small context windows, tool failures, interrupted work, and unavailable services? |
| MCP tools | Which locally hosted tools add useful capabilities, and what do they cost to run and maintain? |
| Local knowledge | Can the agent use saved code and manuals accurately, with sources we can check? |
| Offline operation | Can the prepared system start and finish a task after the WAN is disconnected? |

The stack can change when an experiment gives us a reason. HolmesGPT is our current starting point, and the current vLLM integration is the first piece of groundwork. Broader coding-agent capabilities are still an evaluation target.

## Decisions to preserve

| Decision | Reason | Revisit when |
| --- | --- | --- |
| Keep Blacksite's additions and patches separate from canonical HolmesGPT. | Make our work visible and avoid duplicating upstream code and history. | An experiment requires a different integration boundary. |
| Pin the upstream commit in `upstream.json`. | Reconstruct the same starting point and understand which changes are ours. | Deliberately testing or adopting an upstream update. |
| Start with the existing vLLM configuration and tool-call probe. | Establish a concrete local inference path to test. | Hardware constraints or measured task results justify another backend. |
| Treat mocked tests, live model tests, and disconnected trials as separate evidence. | Each answers a different question. | Keep this distinction as the project grows. |
| Leave the hardware choice and final agent architecture open. | We do not yet have results that justify settling them. | Comparable experiments reveal a useful tradeoff. |

The repository structure and token-budget fix are implemented. Local MCP integrations, durable agent memory, offline installation bundles, and demonstrated autonomous coding are still experiment ideas.

## How to keep the project from drifting

For each substantial change, state which task or experiment it helps. Record what ran, what failed, what the person had to do, and whether the result changed our next step. A smaller setup that completes a useful task is a valid result; so is learning that a tool or model does not help.

Use [EXPERIMENTS.md](EXPERIMENTS.md) for the backlog and run notes, and [OFFLINE.md](OFFLINE.md) for the disconnected rehearsal. Keep the [README](../README.md) current enough that a future session can recover the purpose, present capability, and next test without reconstructing the conversation.
