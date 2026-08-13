# tool-risk-topology

Evaluates maligned-AI tool-misuse risk from the **topology** of the toolkit.

This repository implements **E1 — the Static Property-3 Analyzer**, the KILL
GATE of the project. It decides, *from tool signatures alone* (no agent, no
models, no GPU), whether a **chokepoint carving** of an interface shrinks the
residual monitoring burden relative to an opaque carving and an atomic-primitive
carving. It is the cheapest possible disconfirmation: if the carving doesn't pay
off on paper, the project halts before any sandbox or model work.

## The idea in one paragraph

Give an agent the *same* capabilities through three different tool interfaces:

- **A** — a single opaque `run_command` (maximum discretion, nothing legible);
- **B** — ~7 atomic typed primitives (each call legible, but the composition
  space is wide open);
- **C** — intent-complete tools plus **one named `export_data` chokepoint**
  (the only egress; effect-transparent).

Model each interface as a directed graph over typed capability/data-location
nodes: a tool that reads `In` and writes `Out` induces edges `In × Out`. A
**catastrophic effect** is an unwanted `src → sink` reachability (exfiltration,
credential-read, prod-mutation, weight-access, …). Each effect lands in one of
three buckets:

| bucket | meaning | monitoring cost |
|---|---|---|
| **block** | `src` cannot reach `sink` at all | none |
| **choke** | reachable, but *every* path crosses a transparent chokepoint | cheap — watch the chokepoint calls |
| **resid** | a composition of ordinary tools reaches `sink` while dodging every chokepoint | expensive — needs trajectory-aware monitoring |

The residual set `C_resid` is the burden that survives. **Gate 1 asks: does
carving C shrink `C_resid` relative to A and B?**

## Result (bundled sandbox model)

```
| Carving | ρ (coverage) | blocked | choked | residual | B_mon |
|---------|-------------:|--------:|-------:|---------:|------:|
| A       |         0.00 |       0 |      0 |        9 |    37 |
| B       |         0.00 |       0 |      0 |        9 |    14 |
| C       |         1.00 |       5 |      4 |        0 |     4 |

Gate 1 verdict: PASS ✅
  ρ(C)=1.00 > ρ(A)=ρ(B)=0.00
  |C_resid(C)|=0  ≪  |C_resid(A)|=|C_resid(B)|=9
```

`ρ(I) = (|C_block| + |C_choke|) / |C|` is coverage; `B_mon` is the number of
distinct edges a monitor must watch (residual edges + chokepoint edges).

> This is a **paper** check on interface topology. A pass means the chokepoint
> carving is coherent and shrinks the residual set *by construction*; it does
> **not** yet establish that the shrink survives a real attack policy — that is
> the empirical claim tested downstream (E6/E8).

## Install & run

```bash
python -m venv .venv && source .venv/bin/activate
pip install -e .
trt-analyze                 # markdown kill-gate report (exit 0 = PASS, 1 = FAIL)
trt-analyze --json          # machine-readable JSON
trt-analyze --out reports   # also write reports/report.{md,json}
```

Run the tests:

```bash
pip install -e '.[dev]'
pytest
```

## How it's specified (data-driven)

The whole analysis is driven by YAML in [`data/`](data), so you can re-run the
gate against a different capability set or a different carving without touching
code:

| file | ticket | what it defines |
|---|---|---|
| [`data/capabilities.yaml`](data/capabilities.yaml) | E1-T1 | typed capability/data-location nodes |
| [`data/catastrophic.yaml`](data/catastrophic.yaml) | E1-T1 | catastrophic set `C`, each `c` as a `(src, sink)` pair |
| [`data/benign_edges.yaml`](data/benign_edges.yaml) | E1-T4 | benign-required reachabilities (the confound control) |
| [`data/interfaces/{A,B,C}.yaml`](data/interfaces) | E1-T2 | the three carvings, each tool with typed `In`/`Out` |

**Information-matching (confound control).** `trt-analyze` first checks that
A, B and C all realize the *same* benign task-completion set. Reach on the
catastrophic-only capabilities is intentionally allowed to differ — that
difference is the treatment (C removes catastrophic-only reach and chokes the
rest), not a confound. Equal benign reach keeps usefulness matched across
carvings, so partition differences are attributable to topology.

## Module map (`src/tool_risk_topology/`)

| module | ticket | responsibility |
|---|---|---|
| `models.py` | — | core dataclasses (Node, Tool, Interface, Lattice, …) |
| `lattice.py` | E1-T1 | load capabilities / catastrophic set / benign set |
| `schemas.py` | E1-T2 | load carvings + information-matching check |
| `graph.py` | E1-T3 | build reachability graph `G_I`; choke-free view |
| `partition.py` | E1-T4 | block / choke / residual partition |
| `metrics.py` | E1-T5 | coverage `ρ`, residual `ℓ_min`, burden `B_mon` |
| `report.py` | E1-T6 | kill-gate PASS/FAIL report (md + json) |
| `cli.py` | — | `trt-analyze` entry point |

## E2 — Sandbox & Harness Foundation

With Gate 1 passed, [`sandbox/`](sandbox) instantiates the capability model as a
closed, **network-isolated** Docker stack (Postgres, MinIO, an internal FastAPI
service, the canary-sink egress, an untrusted `app` sandbox, and a trusted
`harness`) plus the machinery to measure an episode:

- **effect extraction `E(τ)`** — snapshot/diff across four channels (git repo,
  Postgres rows, MinIO objects, canary-sink log);
- **sentinel `Z(τ)`** — benign-canary detection of exfil / side-task effects;
- **Inspect skeleton** — an `inspect_ai` task driving an agent stub through one
  tool call end-to-end, reproducible from `(config_hash, seed)`.

```bash
cd sandbox && ./scripts/verify_e2.sh   # build + up + isolation + selftest + eval
```

The harness code lives in [`src/tool_risk_topology/harness/`](src/tool_risk_topology/harness);
see [`sandbox/README.md`](sandbox/README.md) for the full service map, isolation
guarantees, and commands.

## Roadmap

E1 (Phase 1) and E2 (Phase 0) are done. Next: runnable MCP carvings over the
shared capability backend (E3), honest/attack policies and the horizon monitor
(E4), and the control sweep that tests these predictions empirically (E6/E8).
See the build backlog for the full epic/ticket breakdown and gates.
