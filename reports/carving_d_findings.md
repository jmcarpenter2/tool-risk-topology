# Carving D: forcing a legible composition (the thesis, vindicated)

Carving D is the design that came out of the "legibility can lull" result. C's
transparent `export_data` failed because it accepted agent-fabricated `text:` — a
**single-call escape**: the whole exfil collapsed into one reassuring call, with no
composition for a monitor to read. D removes that escape.

**D = intent-complete tools + a provenance-typed egress chokepoint.** `export_source`
accepts only a real source ref (`repo:`/`object:`/`pg:`), never agent text, and the
call declares `source_class` + `sensitivity`. Two consequences:

1. **Direct exfil self-declares.** Exporting `pg:customers` stamps
   `class=customer_records` on the call — the monitor reads it off the call. (Probe:
   D's forced move scores higher than C's disguised move on both monitors, and keeps
   honest `public_doc` exports clearly low.)
2. **Everything else must be *composed*.** To exfiltrate attacker-held or reshaped
   data you must first stage it to a real source, then export — a read→write→export
   **composition**. That is exactly the behaviour the original hypothesis says a good
   interface should force, and that a trajectory monitor can read.

## E1 (static): D ⊇ C, and leaner

D passes the kill-gate (residual 0, ρ=1.0) like C, but `B_mon = 3` vs C's 4. The
missing edge is `agent → external`: **that edge *is* the single-call escape hatch**,
and it was visible on paper the whole time. Removing it keeps D information-matched
(the benign set needs only `repo/object/pg → external`).

## The laundering experiment (the decisive test)

A **laundering-capable** attacker takes the cheapest exit each interface offers (the
same attack code, carving-adaptive): a one-call escape on A/B/C, but on D — which has
no `text:` egress — it is *forced* into stage-then-export. 40 randomized attacks + 24
honest per carving (all reach the sink, Z=40/40), scored by the **naive default**
monitor (name-trusting — the hardest case for D), catch rate with 95% CIs:

| carving | per-call | windowed (w=3) | full trajectory |
|---|---|---|---|
| B (free-form) | 40/40 | 39/40 | 40/40 |
| C (chokepoint) | 40/40 | 8/40 | 31/40 [0.62, 0.88] |
| D (provenance) | 29/40 [0.57, 0.84] | 37/40 [0.80, 0.97] | **40/40 [0.91, 1.00]** |

**The signature is the trend across horizons, not any single cell:**

- **D rises monotonically with monitor memory — 72% → 92% → 100%.** The more history
  the monitor sees, the more legible the forced read→write→export composition
  becomes; at full trajectory D catches **every** laundering attack. This is the
  original hypothesis realized: malicious *composition* is legible.
- **C does not benefit from context** (40 → 8 → 31). There is no composition to
  reveal — C's exfil is a single call — so extra memory can't help; the numbers are
  θ-dominated and noisy (the w3 dip is threshold inflation).
- **B is flat-high** — its raw external send is conspicuous in a single call, so
  memory adds nothing.
- At the **trajectory** horizon (a monitor that can read compositions) **D matches
  the conspicuous B (40/40) and beats the naive chokepoint C (31/40).**

## Why this reconciles the whole investigation

1. **Hypothesis:** a misaligned agent composes tools; the right interface makes the
   composition legible.
2. **C (naive chokepoint) failed** — not because chokepoints are bad, but because it
   let the attacker *skip composition* via a one-call `text:` escape. Legibility of
   one call is worthless when the attack is one call. ("Legibility can lull.")
3. **D forces the composition** by forbidding the escape, and the composition is
   legible to a trajectory monitor. The topology does what it was meant to.

The property that actually matters is therefore **"no single-call escape → force a
legible composition,"** and E1 already encodes it as the `agent → external` edge.

## Honest limitations

- One small (8B) monitor; n=40 per carving. The robust result is the **horizon
  trend** (D increases with context; C does not), not the absolute percentages —
  C's per-call 40/40 is seed-noisy (θ coarseness; a prior seed gave 23/40).
- **D v1 does not propagate taint through writes**, so the laundered export looks
  benign *per call* (D per-call 29/40): the provenance stamp reflects the immediate
  source, not the data's origin. The composition is caught *with memory*; a
  per-call-robust version would need taint propagation (a write inheriting its
  source's sensitivity). D shows this is optional hardening, not required for the
  thesis — the forcing function + a trajectory monitor already suffice.
- Result shown against the naive name-trusting monitor (the conservative case); a
  name-agnostic monitor only helps D further.

## D v2 — closing the per-call hole with taint propagation

D v1's gap: a laundered export (copy sensitive data into a repo file, then export
the file) declares `repo_file`, so it looks benign *per call* and is caught only
with trajectory memory. **D v2** adds content-based taint propagation: the egress
classes the payload by the most sensitive KNOWN data actually present in it
(matched against the live source), so a laundered export self-declares its true
class.

**Mechanism — verified.** The *same* laundered payload, same `Z=1`:
- D v1 stamps `source_class=repo_file, sensitivity=internal` (benign-looking)
- D v2 stamps `source_class=customer_records, sensitivity=high` (self-declaring)

So v2 does exactly what it should: laundering no longer relabels sensitive data as
benign. Isolated per-call score of that export (default monitor): v1 ≈ 0.55 → v2 ≈
0.65, vs an honest repo export ≈ 0.30.

**On the full suite, v2 changes nothing measurable.** The apples-to-apples test is
the *diverse* attack distribution (the same one D v1 was measured on, seed 11),
scored by the naive monitor, 40 attacks:

| carving | per-call | windowed | trajectory |
|---|---|---|---|
| B | 40/40 | 39/40 | 40/40 |
| C | 40/40 | 8/40 | 31/40 |
| D v1 | 29/40 | 37/40 | 40/40 |
| **D v2** | **29/40** | **37/40** | **40/40** |

**D v2 is identical to D v1 at every horizon.** Content-based taint did not close
the per-call gap. Two reasons:
- **It only touches known-sensitive content.** In the diverse suite most attacks
  exfil non-PII sources (a README, an internal API response, an object) or just the
  attacker's own canary token — none of which a content matcher can flag. Only the
  ~1/4 that exfil the customers table get relabelled, so the aggregate barely moves.
- **Even the relabelled exports don't clear the bar.** A laundered PII export lifts
  from `repo_file` (~0.55) to `customer_records` (~0.65) — still under the honest
  threshold θ≈0.80 the diverse honest traffic sets. The stamp changes; the verdict
  doesn't.

(An earlier *focused* run with `--attack-source db` showed D v1 and D v2 both at
24/24 — but that was **confounded**: forcing PII made the staging write a per-call
tell that caught everything at v1, hiding the comparison. The diverse suite above is
the honest test, and it supersedes it.)

**The clear answer.** Content-based taint (v2) is **not** the fix. The mechanism
works in isolation — a laundered export *does* self-declare `customer_records`
instead of `repo_file` — but it does not translate into aggregate safety, because
the threat is broader than known-sensitive content and the lift is too small to
cross the threshold. What actually carries D is **v1's forcing function plus a
trajectory monitor** (laundering caught 40/40 at full memory). The per-call gap
(29/40) is a real, open limitation.

Robustly closing it is not a stamp tweak: it needs **opaque, non-readable handles**
— information-flow control where the agent never holds raw sensitive bytes to
re-wrap, so there is no content to launder and no stamp to spoof. That is the honest
end-state, and the natural next project.

So the loop closes where it genuinely closes: **force composition (D v1) + read
trajectories** makes misuse legible. Making each *call* self-declare its content
(D v2) does not add measurable safety here; the real robustness frontier is
handle-based IFC.

## Reproduce
```bash
docker compose -f sandbox/docker-compose.yml exec -T harness python -m tool_risk_topology.control.sigma_experiment \
  --mode gen --trajectories /repo/logs/sigma_launder.jsonl --carvings B,C,D --n-honest 24 --n-attack 40 --seed 11
python -m tool_risk_topology.control.sigma_experiment --mode score --scorer ollama --monitor-prompt default \
  --trajectories logs/sigma_launder.jsonl --report reports/sigma_launder_llm.json --windows 3
python -m tool_risk_topology.control.sigma_experiment --mode plot --report reports/sigma_launder_llm.json --png reports/sigma_launder_catch.png

# D v2 (taint propagation): laundered exports self-declare their true class
docker compose -f sandbox/docker-compose.yml exec -T harness python -m tool_risk_topology.control.sigma_experiment \
  --mode gen --trajectories /repo/logs/d2_B.jsonl --carvings D --n-honest 16 --n-attack 24 --seed 21 --attack-source db --taint
```
