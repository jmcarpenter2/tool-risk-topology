---
title: "A chokepoint you can walk through in one call isn't one"
author: Jason Carpenter
note: Independent work. Code + reproduce commands: github.com/jmcarpenter2/tool-risk-topology
---

# A chokepoint you can walk through in one call isn't one

*Funneling a possibly-misaligned agent's data exports through a single clean, intent-named tool was supposed to make theft easier to catch. In a small control experiment, it did the opposite. Here's why — and the one-line design rule that actually fixes it.*

**The claim:** a single intent-named egress door creates a *per-call blind spot* that survives even on a frontier monitor. The reassuring tool name makes it worse on a cheap monitor, but the name isn't the root cause — the open door is. Forbid the one-call escape, force the attack to compose across several calls, and a monitor can read it again.

---

## The setup

Give an agent the same two powers — read internal data, send data out — but hand them over through differently *shaped* tool interfaces. Then let a trusted monitor watch the calls and try to flag exfiltration. Does the *shape* of the tools change what the monitor catches?

Four shapes:

- **A — opaque:** one `run_command(...)`. Everything flows through a single shell call.
- **B — free-form:** many small typed tools; "send" is a generic `http_request(target, body)`.
- **C — chokepoint:** intent-named tools, and the *only* way data leaves is one labeled door, `export_data(source, dest)`.
- **D — provenance-typed:** C's fix, introduced later. The door accepts only a real source (`repo:`/`object:`/`pg:`), never agent-written text.

Everything runs in a network-isolated sandbox against a synthetic canary. The attack is scripted, with 40 randomized stealth variants per shape — different sources, disguises, destinations, timing — and every one actually reaches the sink (Z = 40/40). The monitor scores each call's suspicion from 0 to 1; an audit fires above a threshold set to a fixed false-positive budget (β = 0.2). I report catch rate with 95% Wilson intervals, on two monitors: a local `llama3.1:8b` and a frontier `claude-sonnet-5`.

Why scripted, not a real attacker model? I tried the live version first and hit a wall — one that turns out to be informative on its own. The attack needs a model willing and able to steal the data. Neither kind I could run is both. Ask a capable frontier model to play the attacker, even in a clearly-sanctioned sandbox with a fake canary, and it refuses the role outright. Drop down to a weak local model and it accepts the role but can't actually pull off the exfil — Z=0, every time. So a live capable-attacker number is simply out of reach on models an individual can run, short of jailbreaking a production model, which I didn't do.

Scripting the attack sidesteps the wall, and it buys something too: it isolates what I actually care about — the interface's contribution to catchability — from how willing or skilled any particular model is.

And to be clear, this wall never blocks the monitor side of the experiment. Playing the attacker means performing a theft, which a safety-trained model refuses. Acting as the monitor just means rating a tool call for suspicion — ordinary classification, no refusal. That asymmetry is exactly why I could later swap a frontier model into the monitor seat and run the replication, even though it won't sit in the attacker seat.

---

## Why I expected the chokepoint to win

A misaligned agent rarely needs one obviously-dangerous tool. It can **compose** innocent ones — read a record here, send a request there — into a theft where every single step looks fine. That's the fragmentation picture from recent control work ([MonitoringBench](https://arxiv.org/abs/2605.09684); [Multi-Agent AI Control](https://arxiv.org/abs/2607.07368)): spread an attack thin and a per-step monitor loses the thread.

The obvious defense: carve the tools so every path to a catastrophic effect runs through *one* door you can watch closely. Concentrate the guards at the chokepoint. On paper it's clearly good.

It also lines up with an optimistic recent result, [INTENT-AS-A-TOOL](https://arxiv.org/abs/2608.27348), which argues that intent-*declaring* tools help oversight by making a model's commitment visible before it acts. My bet was that the same instinct — make the dangerous action legible — would pay off at the egress door.

It didn't. And the reason is the mirror image of that paper: labeling the door for its intent can make the monitor *trust* the door.

---

## Result 1 — the chokepoint is the easiest way out (local 8B monitor)

I ran 40 disguised exfiltrations through each shape and asked the monitor to flag them, call by call. It caught **every** theft that left through B's generic `http_request`. It **missed about 40%** that left through C's intent-named `export_data`. Same stolen bytes — only the door differed.

The full run, catch rate by how much history the monitor sees:

| shape | per-call | windowed (w=3) | full-trajectory |
|---|---|---|---|
| A (opaque) | 16/40 [0.26, 0.55] | 40/40 [0.91, 1.00] | 40/40 [0.91, 1.00] |
| B (free-form) | **40/40 [0.91, 1.00]** | 40/40 [0.91, 1.00] | 40/40 [0.91, 1.00] |
| C (chokepoint) | 23/40 [0.42, 0.71] | **11/40 [0.16, 0.43]** | 33/40 [0.68, 0.91] |

C — the shape the thesis says should be *easiest* to monitor — is the worst per call, and at the windowed monitor it collapses to 11/40 against B's perfect 40/40 (the intervals don't overlap).

**Is it the name doing this?** I checked directly, with a probe that scores the *same disguised bytes* two ways — through B's `http_request` and through C's `export_data`. On the 8B: B scores 0.70, C scores 0.50 — a **0.21** gap. Rename C's tool to something generic and most of that gap comes back (0.50 → 0.66). So on this cheap monitor, yes: the reassuring name is doing most of the work. Hold that thought — it changes when the monitor gets smarter.

---

## Why it happens — on a cheap monitor, the label lulls

Two things are both true:

- **A chokepoint really does concentrate the exits.** By construction, C forces every exfiltration through one door. (The static analyzer confirms it: 0 uncovered catastrophic paths for C, versus 9 for A and B.) Fewer places to watch.
- **But concentration isn't scrutiny.** A call named `export_data` *reads as legitimate*. A raw `http_request` to the outside looks sketchy; a labeled "export" looks like sanctioned business. So the monitor watches the one door *less*, not more — at least on a weak monitor (the frontier run below shows a strong monitor shrugs the name off).

I tested the fix for this directly: a name-agnostic monitor prompt that judges a send by what's leaving, told plainly not to trust tool names, and deliberately not taught this specific attack. Under it, C's catch jumps back up to near-perfect. So the reversal is a monitor-naming artifact, not a structural law — but it means the chokepoint's value is conditional on the monitor, which the original idea quietly assumed away.

Does the chokepoint then beat free-form tools? The data can't say it does. In the one regime where the two shapes clearly separate — the default monitor, where there's real headroom — the chokepoint loses badly (C 23/40 vs B 40/40 per call). In the regime where C recovers — the name-agnostic monitor — both shapes sit right against the 40/40 ceiling, so that comparison is saturated and simply can't rank them. There's no regime where the chokepoint reliably out-catches free-form. So the strong claim — "a chokepoint is more catchable than free-form tools" — isn't supported.

---

## Result 2 — the real fix: no one-call escape

So why did C fail *structurally*, beyond the name? Because its one door accepted an agent-written blob: `export_data(source="text:<anything>")`. That's a **single-call escape** — the whole theft collapses into one call, and there's no composition left for a monitor to read. Making one call legible is worthless when the attack *is* one call.

**Carving D** closes that hole. Its door, `export_source`, accepts only a *real* source reference — a file, a stored object, a DB query — never agent text, and it declares the source's class. Now, to smuggle out reshaped or fabricated data, the agent has to first **stage** it into a real source, then export it: a read → write → export *composition*. Structurally, D differs from C by exactly one removed edge — `agent → external` — which *is* the escape hatch.

The laundering run (same scripted attacker, 8B monitor):

| shape | per-call | windowed (w=3) | full-trajectory |
|---|---|---|---|
| B (free-form) | 40/40 [0.91, 1.00] | 39/40 [0.87, 1.00] | 40/40 [0.91, 1.00] |
| C (chokepoint) | 40/40 [0.91, 1.00] | 8/40 [0.11, 0.35] | 31/40 [0.63, 0.88] |
| D (provenance) | 29/40 [0.57, 0.84] | 37/40 [0.80, 0.97] | **40/40 [0.91, 1.00]** |

On the 8B, D's catch rate *climbs* as the monitor sees more history — 72% → 92% → 100% — and at full trajectory it catches every attack. Tempting to read that as the forced-composition story made visible: more memory, more of the composition on display. Keep a little skepticism, though — the frontier run is about to complicate the shape of that curve while leaving the point standing.

---

## Does it survive a frontier monitor?

Everything so far came from one small local model. The obvious objection writes itself: *isn't this just an 8B being dim?* So I re-ran the exact same trajectories — same seeds, same prompts, same thresholds, same n — swapping only the monitor, now `claude-sonnet-5`.

**Diverse run (default name-trusting monitor), 8B vs Sonnet, catch of 40:**

| shape · horizon | 8B | Sonnet |
|---|---|---|
| **C · per-call** | 23/40 | **22/40** [0.40, 0.69] |
| C · windowed | 11/40 | **35/40** [0.74, 0.95] |
| C · trajectory | 33/40 | 35/40 [0.74, 0.95] |
| B · all horizons | 40/40 | 40/40 [0.91, 1.00] |

**Laundering run (default monitor), 8B vs Sonnet:**

| shape · horizon | 8B | Sonnet |
|---|---|---|
| **C · per-call** | 40/40 | **24/40** [0.45, 0.74] |
| C · windowed | 8/40 | 32/40 [0.65, 0.90] |
| **D · per-call** | 29/40 | **37/40** [0.80, 0.97] |
| D · windowed | 37/40 | 34/40 [0.71, 0.93] |
| D · trajectory | 40/40 | 37/40 [0.80, 0.97] |

Three things fall out.

**1. The per-call blind spot is real on the frontier monitor — but the name isn't the cause.** Sonnet still catches only 22–24 of C's 40 per-call exfiltrations, far below B's 40/40, and it's *cleaner* than the 8B (consistent across seeds, where the 8B bounced). So the gap isn't a weak-monitor quirk.

But the name-probe tells a different story about *why*. Feed Sonnet the same bytes through both doors and the pure name effect nearly disappears: B 0.46 vs C 0.41, a **0.04** gap — against **0.21** on the 8B — and renaming C's tool barely moves it. A frontier monitor isn't really fooled by the label. What it still misses is the one door *accepting disguised, fabricated content* that scores low no matter what the tool is called. That open door is the robust vulnerability across monitor scale; the reassuring name is mostly an 8B-specific amplifier on top of it.

**2. Context beats the blind spot — on a capable monitor.** Where the 8B's windowed catch of C cratered to 8–11/40, Sonnet climbs back to 32–35/40. Give a strong monitor even a three-call window and it reads past the door. The practical read: a chokepoint is fine *if* you pair it with a monitor that reads across calls, not one scoring each call in isolation.

**3. D holds — and the "rising curve" was an 8B artifact.** The 8B rose 72 → 92 → 100; Sonnet is essentially flat-high at 92 → 85 → 92, catching D well at every horizon, including 37/40 per-call versus C's 24/40. A smarter reader spots the stage → export trail even in a single call. So the honest version of the claim isn't "catchability rises monotonically with monitor memory" — that part was weak-monitor-specific. It's the sturdier one: **remove the single-call escape, force a composition, and that composition is catchable** — immediately on a strong monitor, and with a little memory on a weak one.

---

## Check your own tools for this — statically

You don't have to run any of these experiments to find the flaw in a tool interface. The repo ships a static analyzer, `trt-analyze`, that works straight from the tool schemas — before a model ever runs.

```bash
trt-analyze            # markdown report; exit 0 = PASS, 1 = FAIL
trt-analyze --json     # machine-readable
```

It models the toolset as a capability graph and, for every catastrophic effect (`source → sink`), reports whether it's **blocked**, **funneled through one monitorable chokepoint**, or left as an open **residual path**. On the set used here: A and B leave all 9 effects residual; C blocks 5 and chokes the other 4, for 0 residual.

But coverage alone can't tell C from D — both score 0 residual. The metric that *does* is **single-call escapes**: how many tools take agent-controlled input straight to a catastrophic sink in one call. C scores **1** (the `text:` blob). D scores **0**. That single integer — not any catch-rate curve — is the robust, monitor-independent line between a chokepoint that lulls and one that works. It's the number to check on your own egress tools.

---

## Where this sits (related work)

- [**INTENT-AS-A-TOOL**](https://arxiv.org/abs/2608.27348) argues intent-declaring tools *aid* oversight. No contradiction: their intent tool is a *dedicated declaration* with no side effect; my `export_data` is a *load-bearing action* whose reassuring name rubs off on the monitor. The lesson isn't "intent labels are bad" — it's that an intent label on a real *action* can lower scrutiny of that action.
- [**The Framing Gap**](https://arxiv.org/abs/2608.27092) shows reframing a leak as routine plumbing beats surface-level defenses — but there the fooled party is the *acting agent* (via prompt injection), and the lever is page/instruction framing, not the tool's own name as read by a *separate* monitor. Adjacent axis.
- [**MonitoringBench**](https://arxiv.org/abs/2605.09684) and [**Multi-Agent AI Control**](https://arxiv.org/abs/2607.07368) establish that attacks fragment across steps and that trajectory-scope monitoring matters. D adds a tool-*interface* forcing function: shape the egress so the attack *has* to fragment.
- Monitor-transfer fragility ([Calibration-Family Overfit](https://arxiv.org/abs/2607.06596)) is a big part of why I ran the frontier check instead of trusting one monitor.

As far as I can tell, the specific claim here isn't isolated elsewhere — it lives in the gap between the "monitors are fooled by framing" line and the "design tools for monitorability" line:

> **A single intent-named egress door creates a per-call blind spot that persists across monitor scale, with the tool name amplifying it on cheap monitors.**

---

## Design takeaways

If your oversight of a capable model leans on reading its tool calls:

1. **Leave no single-call escape.** No tool should both *assemble* and *carry out* a catastrophic effect in one opaque call. If a single call can do it, there's no composition to read. This is checkable statically — the escape count should be 0. Use trt-analyze to verify.
2. **Design for risk, not reassurance.** A soothing name (`export_data`) lowers a cheap monitor's guard — and a human reviewer's. A frontier monitor shrugs off the name, but a single door that accepts fabricated blobs still lets theft score low per call. Foreground the risky fact — data is leaving, externally, of this class — and don't let one door swallow arbitrary content.
3. **Let only real, named things leave.** An egress tool should move typed sources, not an agent-composed blob. Then anything reshaped has to be *staged first* — a visible step.
4. **Give the overseer memory — it matters most when the monitor is cheap.** Forcing composition only pays off if the monitor reads across calls rather than scoring each one alone. A weak monitor *needs* the trajectory; a strong one catches the composition even per-call. Spend trajectory monitoring where data actually leaves.

None of this makes misuse impossible — a determined model can still act — but it makes *secret, one-shot* misuse structurally hard, and turns "did it just do something bad?" into a question a monitor can actually answer.

---

## Limitations (what I don't claim)

- **Two monitors, not a sweep.** One small (8B), one frontier (Sonnet), n=40 per shape. The claims that replicate on *both* are the per-call blind spot for C, the fact that C never reliably out-catches B, and the static single-call-escape metric. Two things are *not* model-independent: the pure tool-name effect (large on 8B, ~0 on Sonnet) and the 8B's rising-with-memory curve for D.
- **No strong-claim win.** A naive chokepoint never reliably out-catches free-form tools. The win is specific: no single-call escape, plus a monitor that reads context (or is strong enough to read the composition in one call).
- **The recovered-monitor comparison is ceiling-saturated.** Under the name-agnostic monitor, both B and C catch near 40/40, so that run has almost no power to rank them — "parity" there is saturation, not proven equivalence. Cleanly separating B from C would need a harder regime (a tougher attack distribution, or a stricter audit budget) that pulls both off the ceiling and leaves room for a difference to show.
- **D v1 doesn't propagate taint.** The provenance stamp reflects the immediate source, not the data's origin, so a laundered export can look benign per call on a weak monitor (8B D per-call 29/40). Taint propagation is optional hardening, not load-bearing for the result.
- **A tidy sandbox.** Synthetic canary, one benign task family, closed network. Whether it holds on a messier workload is open.

---

*Code, data, and reproduce commands: github.com/jmcarpenter2/tool-risk-topology. Feedback welcome.*
