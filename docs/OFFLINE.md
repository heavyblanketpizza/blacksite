# Rehearsing life without the internet

The target scenario is a local coding agent that remains useful with the WAN disconnected. The initial rehearsal may use a LAN and a separate local inference host. Record the network boundary for every run so “local” and “offline” have a precise meaning.

**Status:** the repository has been reconstructed from its pinned upstream source while connected. A live disconnected rehearsal and a cold restart have not yet been recorded. This page describes the rehearsal we want to perform.

## Bring the dependencies before the cutoff

| What to prepare | What to check during the rehearsal |
| --- | --- |
| Blacksite and its pinned HolmesGPT checkout | The code is present locally; rebuilding does not require GitHub. |
| Inference server and model weights | The exact model, tokenizer, configuration, and server dependencies are present. Startup does not fetch missing files. |
| Container images and Python packages | The chosen installation path can start from local artifacts. A running container alone does not prove it can be rebuilt. |
| Project repositories and test dependencies | The test task can be built and checked without reaching a registry. |
| MCP servers, if an experiment uses them | Their launchers, dependencies, and backing services are local too. An MCP connection does not by itself make a tool offline. |
| Saved documentation and data | Required documents are readable locally, with versions and source information attached. |
| Configuration and credentials | Required local configuration is available after restart; no cloud login or token refresh is needed for the chosen task. |
| Experiment notes | Hardware, versions, prompts, expected results, and prior failures remain available locally. |

`python3 scripts/upstream.py prepare` fetches upstream when the checkout is absent. Run it before the cutoff and preserve the prepared checkout. The public Blacksite repository intentionally excludes upstream source and model weights, so cloning Blacksite alone is not an offline installation kit.

The current Compose setup may download images and model files on first use. A download cache is useful preparation, but its completeness still needs a disconnected startup test. A portable recovery bundle is future work.

## Run a disconnected trial

1. Choose one small task from [EXPERIMENTS.md](EXPERIMENTS.md) with a known way to check success. Record the machine, model, context limit, tool configuration, and exact code revisions.
2. Stage the required artifacts and run the task while connected. Record any downloads or external services it uses.
3. Disconnect the WAN while keeping only the local connections allowed by the scenario. Record how the boundary is enforced and how external connection attempts will be observed.
4. Start a fresh agent session and run the same task. Inspect whether inference, tools, retrieval, and test commands stay within that boundary. Record attempted external calls, including failed background calls.
5. Stop and restart the services with the WAN still disconnected, then repeat. Use an isolated test setup so the rehearsal does not interrupt unrelated work.
6. In a separate recovery experiment, rebuild the environment from the staged artifacts. Record any missing package, image, model file, authentication step, or instruction.
7. Save the result, the agent's changes, test output, elapsed time, resource measurements, and human interventions. State exactly which part passed or failed.

Keep these outcomes separate: running offline from a warm environment, restarting offline, and recovering offline from saved artifacts. Passing one leaves the others open.

## Evidence to collect

- Did the task meet its stated acceptance test, and was the resulting code or answer useful?
- Which external requests were attempted? Which unavailable services affected the result?
- What did the person have to fix, explain, restart, or supply?
- What were the latency, peak memory use, disk footprint, and available power or energy measurements?
- Did a smaller context limit or interrupted tool call change the outcome?
- Were the instructions and saved notes enough to repeat the run later?

Record unavailable measurements as unknown. Keep real credentials and private logs out of the public notes; publish the reproducible fixture and a redacted account of the result.

An offline result is specific to the tested task, network boundary, and artifacts. Broaden the task set before treating it as evidence that the agent can handle an arbitrary problem at the homestead.
