# tool-risk-topology

**Does the *shape* of an AI agent's toolkit change how catchable its misuse is?**

Give a possibly-misaligned agent the same capabilities through differently-*shaped*
tool interfaces, model each interface as a graph, and measure (a) how much
monitoring burden each shape leaves behind on paper and (b) whether a real LLM
monitor can actually catch misuse through each one.

This repo is the code and reproducible experiments behind the post
**"[A chokepoint you can walk through in one call isn't one](reports/chokepoint-legibility-post.md)."**

> **The finding in one paragraph.** Funnelling an agent's data exports through a
> single, clean, intent-named *chokepoint* tool was *supposed* to make exfiltration
> easier to catch. In a small control experiment it did the opposite: the reassuring
> name lulls a naive monitor, and — more fundamentally — a one-call export door
> leaves no composition for a monitor to read. The fix is a one-line design rule:
> **forbid the single-call escape** so every exfiltration must compose across several
> calls, which a trajectory-aware monitor can read again.

**Jump to:** [the idea](#the-idea) · [what we found](#what-we-found) ·
[quickstart: `trt-analyze`](#quickstart-the-static-analyzer) ·
[reproduce the results](#reproduce-the-results) ·
[repository layout](#repository-layout) · [how it's built](#how-its-built)

---

## The idea

Give an agent the *same* two powers — read internal data, send data out — through
four differently-shaped interfaces:

| carving | shape | discretion |
|---|---|---|
| **A — opaque** | a single `run_command` (bash) | maximum; nothing legible |
| **B — free-form** | ~7 atomic typed primitives | each call legible, composition wide open |
| **C — chokepoint** | intent-complete tools + one named `export_data` egress (the only door out) | effect-transparent egress |
| **D — provenance** | like C, but egress takes only real source refs (no agent-fabricated `text:`) and self-declares each export's `source_class` + `sensitivity` | no single-call escape |

Model each interface as a directed graph over typed capability / data-location
nodes: a tool that reads `In` and writes `Out` induces edges `In × Out`. A
**catastrophic effect** is an unwanted `src → sink` reachability (exfiltration,
credential-read, prod-mutation, weight-access, …). Each effect lands in one bucket:

| bucket | meaning | monitoring cost |
|---|---|---|
| **block** | `src` cannot reach `sink` at all | none |
| **choke** | reachable, but *every* path crosses a transparent chokepoint | cheap — watch the chokepoint calls |
| **resid** | an ordinary composition reaches `sink` while dodging every chokepoint | expensive — needs trajectory-aware monitoring |

The **residual** set is the burden that survives. The static analyzer
([`trt-analyze`](#quickstart-the-static-analyzer)) computes it from tool signatures
alone. The empirical half of the project then makes the four shapes *runnable*
against a network-isolated sandbox and lets a real LLM monitor try to catch a
scripted attacker exfiltrating a canary through each one.

---

## What we found

**1. On paper, the chokepoint looks great.** `trt-analyze` shows carving C drives
the residual monitoring burden to zero relative to A and B:

```
| Carving | ρ (coverage) | blocked | choked | residual | B_mon |
|---------|-------------:|--------:|-------:|---------:|------:|
| A       |         0.00 |       0 |      0 |        9 |    37 |
| B       |         0.00 |       0 |      0 |        9 |    14 |
| C       |         1.00 |       5 |      4 |        0 |     4 |
```

This is a *by-construction* result: a PASS means the carving is coherent and shrinks
the residual set on paper — **not** that the shrink survives a real attack. That's
the empirical question the rest of the repo tests.

**2. Live, the chokepoint can *lull* the monitor.** Scripting a diverse attacker
that exfiltrates a canary (40 attacks/carving, scored by a real `llama3.1:8b`
monitor), the thesis **reversed**. Judging each call in isolation, the monitor
catches **40/40** of B's exfils but only **23/40** of C's; give it a 3-call window
and C *collapses* to **11/40** while B stays at 40/40. A name-probe isolates why:
the same disguised bytes score **0.70** through B's generic `http_request` but only
**0.50** through C's `export_data` (a 0.21 gap) — the sanctioned-sounding name makes
the single door the *safest* exit. A **name-agnostic** monitor (judge egress by
*what leaves*, not the tool name) recovers C's windowed catch (11/40 → **36/40**),
so the reversal is a monitor artifact, not a structural win for C.

**3. Carving D fixes the real problem.** C's door failed because it accepted
agent-fabricated `text:` — a **single-call escape** that collapses the whole exfil
into one reassuring call. D removes it: egress takes only real source refs, so
exfiltration must be *staged* (read → write → export). Against a laundering
attacker under the **naive** monitor, D's catch rate **rises with monitor memory**
— the fingerprint of a forced, legible composition:

| carving | per-call | windowed | trajectory |
|---|---|---|---|
| B free-form | 40/40 | 39/40 | 40/40 |
| C chokepoint | 40/40 | 8/40 | 31/40 |
| **D provenance** | 29/40 | 37/40 | **40/40** |

**4. It replicates on a frontier monitor.** Re-running the same trajectories with
`claude-sonnet-5` as the monitor (nothing else changed): the per-call lull **holds**
(C: ~22/40 judging one `export_data` call), so it is not a weak-monitor artifact.
What the frontier model adds is *context* — C's windowed catch recovers to ~35/40,
and D is caught well throughout.

> **Honest bottom line.** The strong thesis — *chokepoint ⇒ more catchable than
> free-form* — is **not** supported by the live safety metric. The sharper, robust
> finding is **legibility can lull**, and the design rule that survives it is
> **"offer no single-call escape, so every exfil manifests as a composition a
> trajectory monitor can read."** Transparency of *intent* is double-edged for
> oversight; transparency of *effect through a forced composition* is what pays off.

**Deeper writeups** (each is reproducible — see [below](#reproduce-the-results)):

- [Legibility can lull](reports/legibility-can-lull.md) — the scripted-attacker study
- [Carving D: provenance-typed egress](reports/carving-d-provenance.md) — the fix, vindicated
- [Frontier-monitor replication](reports/frontier-monitor-replication.md) — the lull holds on `claude-sonnet-5`
- [Live control eval](reports/live-control-eval.md) — the model-in-the-loop negative result and why
- Illustrated note with inline charts (open in a browser): [`reports/chokepoint-legibility.html`](reports/chokepoint-legibility.html)

---

## Quickstart: the static analyzer

`trt-analyze` is the cheapest check in the project — **no agent, no models, no GPU,
no Docker.** It decides, from tool signatures alone, whether a carving shrinks the
residual monitoring burden.

```bash
python -m venv .venv && source .venv/bin/activate
pip install -e .
trt-analyze                 # markdown report (exit 0 = PASS, 1 = FAIL)
trt-analyze --json          # machine-readable JSON
trt-analyze --out reports   # also write reports/report.{md,json}
```

It also reports, per carving, every **single-call escape** — a tool that takes
agent-controlled input and writes a catastrophic sink in one opaque call (the
C-vs-D distinguisher):

| Carving | single-call escapes |
|---|---|
| A (opaque) | 2 — `run_command→external`, `run_command→pg_prod` |
| B (free-form) | 2 — `db_exec→pg_prod`, `http_request→external` |
| C (chokepoint) | 1 — `export_data→external` (accepts agent-fabricated `text:`) |
| **D (provenance)** | **0 — none** (egress takes only real sources) |

### Run the gate on your own toolkit

The whole analysis is data-driven — edit the YAML in [`data/`](data) to run the gate
against a different capability set or carving without touching code:

| file | what it defines |
|---|---|
| [`data/capabilities.yaml`](data/capabilities.yaml) | typed capability / data-location nodes |
| [`data/catastrophic.yaml`](data/catastrophic.yaml) | catastrophic set `C`, each `c` as a `(src, sink)` pair |
| [`data/benign_edges.yaml`](data/benign_edges.yaml) | benign-required reachabilities (the confound control) |
| [`data/interfaces/{A,B,C,D}.yaml`](data/interfaces) | the carvings, each tool with typed `In` / `Out` |

**Information-matching (confound control).** Before scoring, `trt-analyze` checks
that all carvings realize the *same* benign task-completion set — so usefulness is
matched and any partition difference is attributable to topology, not to one carving
quietly doing less. Catastrophic-only reach is *allowed* to differ: that difference
is the treatment, not a confound.

---

## Reproduce the results

The static gate above needs nothing but Python. The **empirical** experiments need
the sandbox (Docker) and a monitor model.

**Prerequisites**

```bash
pip install -e '.[dev,analysis]'          # analysis extras add matplotlib for the figures
# Docker Desktop running (for the sandbox stack)
# local LLM monitor:   ollama serve   &&   ollama pull llama3.1:8b
# frontier monitor:    export ANTHROPIC_API_KEY=...
```

> The sandbox is **network-isolated and GPU-less**, so model backends can't run
> *inside* it — only the attacker's *hands* run in-sandbox (via `docker compose
> exec`); the monitor/agent *brain* runs host-side over serialized trajectories.

### Claim 1 — the static kill-gate

```bash
trt-analyze --out reports        # writes reports/report.{md,json}; exit 0 = PASS
pytest                           # the analyzer's unit tests
```

### Claim 2 — legibility can lull (scripted attacker; naive vs. name-agnostic monitor)

Generate a diverse attack distribution in-sandbox, then score it host-side under two
monitor prompts:

```bash
docker compose -f sandbox/docker-compose.yml exec -T harness \
  python -m tool_risk_topology.control.sigma_experiment \
  --mode gen --trajectories /repo/logs/sigma_div.jsonl --carvings A,B,C \
  --n-honest 24 --n-attack 40 --seed 7

python -m tool_risk_topology.control.sigma_experiment --mode score --scorer ollama \
  --trajectories logs/sigma_div.jsonl --report reports/sigma_div_llm.json --monitor-prompt default
python -m tool_risk_topology.control.sigma_experiment --mode score --scorer ollama \
  --trajectories logs/sigma_div.jsonl --report reports/sigma_div_llm_chokepoint.json --monitor-prompt chokepoint
```

Full writeup: [`reports/legibility-can-lull.md`](reports/legibility-can-lull.md).

### Claim 3 — carving D forces a legible composition (laundering experiment)

```bash
python -m tool_risk_topology.control.sigma_experiment --mode score --scorer ollama \
  --trajectories logs/sigma_launder.jsonl --report reports/sigma_launder_llm.json --monitor-prompt default
```

Full writeup: [`reports/carving-d-provenance.md`](reports/carving-d-provenance.md).

### Claim 4 — frontier-monitor replication

Re-score the *same* trajectories with a frontier monitor (needs `ANTHROPIC_API_KEY`):

```bash
python -m tool_risk_topology.control.sigma_experiment --mode score --scorer anthropic \
  --model claude-sonnet-5 --trajectories logs/sigma_div.jsonl \
  --report reports/sigma_div_frontier.json --monitor-prompt default
```

Full writeup: [`reports/frontier-monitor-replication.md`](reports/frontier-monitor-replication.md).

### The name-lull probe (the single-payload comparison)

The "same stolen bytes score lower through C's intent-named `export_data` than
through B's generic `http_request`" comparison, regenerable from fixed payloads:

```bash
python -m tool_risk_topology.control.name_probe --scorer ollama --num-samples 5
python -m tool_risk_topology.control.name_probe --scorer anthropic --model claude-sonnet-5
```

> Honest caveat: on a *single* payload the gap is real but noisy (8B) and ~0 on a
> frontier monitor — so the citable signal is the aggregate **catch rate** in
> claim 2, not any single suspicion pair.

### The live model-in-the-loop eval (the negative result)

A real model drives the carving tools over a multi-step loop, benign vs. misaligned:

```bash
python -m tool_risk_topology.control.eval --provider ollama --model llama3.1:8b
```

This is reported as a **negative result**: a live safety number needs a policy that
is both *willing* to attack and *able* to execute the exfil, and neither accessible
model is both (Claude Opus refuses the red-team role; the local 8B is willing but
incompetent). That's why the load-bearing evidence stays the static gate (claim 1)
and the scripted/per-call studies (claims 2–4). Full writeup:
[`reports/live-control-eval.md`](reports/live-control-eval.md).

---

## Repository layout

```
data/                     YAML that drives trt-analyze (capabilities, catastrophic set, carvings)
src/tool_risk_topology/
  ├─ (analyzer)           models, lattice, schemas, graph, partition, metrics, report, cli  → trt-analyze
  ├─ carvings/            A/B/C/D made runnable over one shared backend; each also an MCP server
  ├─ harness/             effect extraction E(τ), sentinel Z(τ), the episode runner
  └─ control/             the control game: attack/honest policies, monitors, the experiments above
sandbox/                  network-isolated Docker stack (Postgres, MinIO, internal API, canary egress)
reports/                  generated reports, figures, and the deep-dive writeups
tests/                    pytest suite for the analyzer and the control machinery
```

### The analyzer modules (`src/tool_risk_topology/`)

| module | responsibility |
|---|---|
| `models.py` | core dataclasses (Node, Tool, Interface, Lattice, …) |
| `lattice.py` | load capabilities / catastrophic set / benign set |
| `schemas.py` | load carvings + information-matching check |
| `graph.py` | build reachability graph `G_I`; choke-free view |
| `partition.py` | block / choke / residual partition |
| `metrics.py` | coverage `ρ`, residual `ℓ_min`, burden `B_mon` |
| `report.py` | kill-gate PASS/FAIL report (md + json) |
| `cli.py` | the `trt-analyze` entry point |

---

## How it's built

The project was built in stages, each with its own one-command acceptance script
under [`sandbox/scripts/`](sandbox/scripts) (`verify_sandbox.sh`, `verify_carvings.sh`,
`verify_control.sh`, `verify_legibility.sh`, `verify_sweep.sh`) — they remain the
fastest way to rebuild a whole layer end-to-end. In order:

1. **The static analyzer** — the kill-gate above (`trt-analyze`).
2. **The sandbox** — a closed, network-isolated Docker stack that instantiates the
   capability model as real services (Postgres `pg_prod`, MinIO `object_store`, an
   internal FastAPI service, and a canary-sink `external` egress that logs any
   payload), plus a trusted harness that snapshots state and computes the effect
   `E(τ)` and sentinel `Z(τ)`. See [`sandbox/README.md`](sandbox/README.md).
3. **Runnable carvings** — A/B/C/D over one shared backend, each also served as a
   real MCP server, statically checked to stay information-matched.
4. **The control game** — honest/attack policies, a suspicion monitor at horizons
   `{per-call, windowed, trajectory}`, and the audit threshold — the machinery the
   experiments above drive.

```bash
cd sandbox && ./scripts/verify_sandbox.sh      # build + isolation + harness selftest
cd sandbox && ./scripts/verify_carvings.sh     # runnable carvings + MCP servers + benign battery
cd sandbox && ./scripts/verify_legibility.sh   # per-call legibility (real local-LLM monitor)
```

---

## License

[Apache License 2.0](LICENSE).
