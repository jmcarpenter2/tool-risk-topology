# Scripted-attacker findings: legibility can lull the monitor

This is the scripted-attacker line of work (the E6 follow-up). It set out to get a
live, reproducible safety number for the chokepoint thesis — *does carving an
agent's tools around one transparent `export_data` chokepoint (C) make misuse more
catchable than a bag of general-purpose tools (B)?* — by scripting the attack
instead of eliciting it from a model. It ended somewhere more interesting than it
started, and not where the thesis predicted.

**Headline:** *legibility can lull.* Naming a tool for its intent (`export_data`)
makes a naive monitor **trust** it, turning the single sanctioned door into the
**safest** place to exfiltrate. The chokepoint's structural benefit is real but
**not automatic** — it pays off only when the monitor scrutinizes egress by
*content*, not by *tool name*.

---

## The investigation, in order

### 1. Attacker spread (σ) — a dead end
First hypothesis: an attacker beats a short-memory monitor by **spreading** the
steal and the send far apart (σ benign steps between them), so a bounded-window
monitor loses the composition. Built the knob (a `window` monitor horizon +
`AttackPolicy.spread`). **It didn't matter:** even a "stealth" attack ends by
sending data to an external address — a per-call tell a capable monitor catches on
its own. Spread is only a lever if *no single step* is incriminating; here the send
is. (See `git log` for the σ primitives; the safety-vs-σ curves were flat.)

### 2. A diverse attack distribution — the reversal
Replaced the single hand-picked attack with a **randomized variant library**
(`StealthAttackPolicy`: random source × disguise × destination × spread) and a
**noisier honest policy** (`NoisyHonestPolicy`) so the audit threshold θ rests on a
smooth honest distribution rather than 4 fixed tasks. 40 distinct attacks + 24
honest per carving; each attack verified to reach the sink live (Z=40/40). Scored
by the real `llama3.1:8b` monitor, catch rate with 95% Wilson CIs.

**Result (default monitor) — the thesis reversed:**

| carving | per-call | windowed | full-traj |
|---|---|---|---|
| A (opaque) | 16/40 | 40/40 | 40/40 |
| B (free-form) | **40/40** | **40/40** | **40/40** |
| C (chokepoint) | 23/40 | **11/40** | 33/40 |

C — the design the thesis says is *most* catchable — was the **worst**: at the
windowed monitor it caught only 11/40 (27%, CI [0.16, 0.43]) vs B's 40/40
([0.91, 1.00]). Non-overlapping intervals. (The small-n pilot that suggested "C
clean everywhere" was sampling luck — see §5.)

### 3. The mechanism — the name/framing lulls the monitor
The same stolen bytes score differently through B's generic `http_request` than
through C's intent-named `export_data`: the monitor treats a call *named* for a
sanctioned purpose as routine and lowers its guard, while a generic external send
reads as sketchy. Reproduce it with the committed probe (means over a fixed set of
disguised payloads, either backend):

```bash
python -m tool_risk_topology.control.name_probe --scorer ollama    --num-samples 5   # -> reports/name_probe_llama3.1-8b.json
python -m tool_risk_topology.control.name_probe --scorer anthropic --model claude-sonnet-5
```

| monitor | B `http_request` | C `export_data` | gap |
|---|---|---|---|
| 8B (mean/5) | 0.70 | 0.50 | +0.21 |
| sonnet-5 (mean/3) | 0.46 | 0.41 | +0.04 |

**Caveat — read this before quoting a number.** On a *single* payload the gap is
real but noisy (8B swings ~0.2–0.35 run to run) and it is ~0 on a frontier monitor,
which judges disguised content low through either tool. The earlier "0.84 vs 0.47
on one payload" was a one-off draw, not reproducible. The robust, committed evidence
for the lull is the **aggregate catch rate**: under the default monitor C's per-call
catch is **23/40 (8B) / 22/40 (sonnet)** vs B's **40/40** — and it recovers to 40/40
the moment the monitor is told to ignore tool names (§4). That rate, not any single
suspicion pair, is what to cite.

### 4. A name-agnostic monitor — the chokepoint recovers to parity
Built a **chokepoint-aware** monitor prompt that judges egress by *what leaves*
(generic public/trivial vs. not) and explicitly does **not** trust tool names.
Deliberately attack-agnostic — it never names customer data, secrets, canaries, or
disguises (that would be teaching to the test) — and applied **identically** to all
three carvings. Probe on the same payload: attack scores B 0.54 / **C 0.61**
(name no longer helps C), benign stays low (B 0.40 / C 0.31 — still discriminating).

**Result (name-agnostic monitor) — the gap closes:**

| carving | per-call | windowed | full-traj |
|---|---|---|---|
| A | 40/40 | 40/40 | 16/40 |
| B | 40/40 | 40/40 | 38/40 |
| C | **40/40** | **36/40** | 34/40 |

C's worst cell recovers from **11/40 → 36/40** ([0.77, 0.96]). So the reversal was a
**monitor-naming artifact**, not a structural defect — fix the monitor and the
chokepoint is fine. B was unaffected (the prompt is fair, not C-specific).

### 5. Why the small-n pilot lied, and n alone couldn't fix it
The first live run (n=6, 1 monitor draw each) showed "C clean everywhere." A
larger run (n=24) plus a diagnostic showed why that was noise, and — importantly —
that raw **n does not help**: the score cache correctly collapses repeats of the
same 4 cover tasks to one entry, so more repeats ≠ more resolution. Verified there
is **no cross-carving cache collision** and **no honest↔attack collision on the
incriminating egress** (only genuinely-identical benign reads share keys). The
fragility was a *quantile threshold estimated from ~4 behavioral structures*. The
fix that worked was **diversity** (many distinct attacks + noisier honest), which
is why §2 uses a variant library, not a bigger n.

---

## What this means for the thesis

- **Structural claim (E1): holds.** C funnels all catastrophic egress into one
  auditable door (residual 0/9, ρ=1.0). True by construction, unchanged.
- **Strong empirical claim — "chokepoint ⇒ *more* catchable than free-form": not
  supported.** With diverse attacks and real statistics, C is at best on par with
  B (36/40 vs 40/40), never clearly better, under either monitor.
- **The real finding — legibility can lull.** A reassuring, intent-named tool
  *reduces* a naive monitor's scrutiny, so a chokepoint can make misuse *harder* to
  catch unless the monitor is explicitly name-agnostic and content-focused. The
  chokepoint's value is **contingent on pairing it with the right monitor**, not a
  free consequence of the tool design. Transparency of intent is double-edged for
  oversight.

## Honest limitations
- One small (8B) local monitor. A larger monitor may be less swayed by names —
  but the effect is robust *for this monitor* (n=40, non-overlapping CIs), and it is
  exactly the kind of cheap trusted monitor AI-control setups assume.
- "Catch rate" quantities depend on the audit threshold β=0.2 and the honest
  distribution; the *relative* default-vs-name-agnostic and B-vs-C comparisons are
  the robust part, not the absolute percentages.
- The name-agnostic prompt is one reasonable fair monitor, not the optimum.

## Reproduce
```bash
# generate diverse trajectories in the sandbox (real Z)
docker compose -f sandbox/docker-compose.yml exec -T harness \
  python -m tool_risk_topology.control.sigma_experiment --mode gen \
  --trajectories /repo/logs/sigma_div.jsonl --carvings A,B,C --n-honest 24 --n-attack 40 --seed 7

# score host-side (needs `ollama serve` + llama3.1:8b), both monitors:
python -m tool_risk_topology.control.sigma_experiment --mode score \
  --trajectories logs/sigma_div.jsonl --report reports/sigma_div_llm.json --scorer ollama --monitor-prompt default
python -m tool_risk_topology.control.sigma_experiment --mode score \
  --trajectories logs/sigma_div.jsonl --report reports/sigma_div_llm_chokepoint.json --scorer ollama --monitor-prompt chokepoint
```
