> **Superseded, 2026-11-28: the hot standby is removed from the design.**
>
> The question asked in the [Lido forum thread](https://research.lido.fi/t/12227/2), how a standby that takes over avoids signing against what the primary already signed, led us to drop the standby and the arbiter altogether. Every path to slashing in the scheme below needed a second signer of the same key while the first might still be alive; the arbiter, votes, leases and floors existed only to make that safe. The current design has **one key, one board**: a board failure means missed duties, and a stolen or doubtful board means a pre-signed exit, never a second copy of the key. See the README sections [One key, one board](../README.md#one-key-one-board) and [Theft: exit, and why it is safe](../README.md#theft-exit-and-why-it-is-safe).
>
> The note below is kept unchanged as the record of the earlier design and its simulation results.

---

# Hot standby without double signing: protocol note and simulation results

Status, 2026-11-25. This note covers the protocol **as designed and as it runs in our software model**: simulated devices, a simulated arbiter, a synthetic beacon chain, and real BLS12-381 signatures checked by an independent checker. The board firmware does not exist yet, and nothing here has run on a physical board. The simulator source is not in this repository yet.

It answers the question raised in the [Lido forum thread](https://research.lido.fi/t/12227/2): can a standby device that takes over produce a surround vote against what the primary already signed?

## 1. Parties

- **Two devices**, primary and standby. Both hold the same validator keys, and each has its own identity key. Each device keeps, per validator key, a minimal EIP-3076 watermark: highest block slot, highest attestation source, highest attestation target.
- **Two hosts.** Each runs the beacon/validator client for its device. A host is not trusted: it can ask for anything.
- **An arbiter.** A small rented server that acts as the third voter. It holds no validator keys.

## 2. Terms and leases

Time is divided into **terms**, which are fixed ranges of epochs. Term `n` covers epochs `[n·T, (n+1)·T)`; the model uses `T = 2`.

A device signs only under a **lease** for the term of the message, meaning 2 of 3 votes from {device A, device B, arbiter}. Each voter keeps a record of its last vote `(term, holder)`, writes it before the vote leaves, and never votes for a lower term or for a different holder in the same term. Two leases for the same term would need 2 + 2 votes from 3 voters, so one voter would have to vote twice. **One holder per term.**

A device signs an attestation only if:

- `data.target.epoch == epoch(data.slot)` and `source ≤ target`;
- it holds a lease for `term(data.slot)`;
- the watermark allows it: `target > max_target` and `source ≥ max_source` (blocks: `slot > max_slot`).

Because of the first two checks, everything a device signs lies inside a term it holds. The slot-to-target binding matters too: without it (ablation A2 below) the model produces slashable pairs.

## 3. The take-over floor

A device remembers in persistent storage the contiguous **run** of terms it holds. When it installs a lease that does **not** extend its current run (its first lease, a takeover, or any gap), it starts a new run:

1. for every key it raises the floor to `source ≥ start_epoch(term)`, `target ≥ start_epoch(term)`, `slot ≥ start_slot(term)`, and **persists** it;
2. it records the new run;
3. only then does it install the lease.

If power is lost between these writes, the floor is applied again on the next install.

**Why this excludes surround and double votes across devices.** Let device P sign `x` in term `Tp` and device Q sign `y` in a later term `Tq`. Q's run containing `Tq` started at some term `R ≤ Tq`, and Q held every term in `[R, Tq]`. One holder per term means `Tp < R`. The floor gives

    x.source ≤ x.target < start(R) ≤ y.source ≤ y.target

So the targets differ (no double vote), neither vote surrounds the other, and the block slots differ. **The standby needs none of the primary's history.** Waiting before a takeover affects availability only, not safety.

In the forum's example (primary signed source 100 / target 105; the standby's beacon node still reports justified epoch 99), the standby **refuses** source 99. The cost is a missed attestation, not a slashing.

Within one device, its own watermark rules out double proposals, double votes and surrounds. After an unclean power loss, everything up to a bound written ahead of signing is treated as already signed: 10 epochs ahead for attestations, 320 slots for blocks.

An earlier draft also passed a signed watermark export from the old holder to the new one at a planned handover. The model showed this was redundant given the floor, and we removed it.

## 4. What it costs

- **Non-finality.** If the chain stops justifying, a device that starts a new run can't attest until the justified checkpoint reaches the start of its run. In the model a forced takeover during a long non-finality episode means silence for the rest of the episode: about 38 / 150 / 750 epochs for episodes of 50 / 200 / 1000 epochs. No host policy helps here, because the floor is what keeps the successor safe. In the model a planned handover is postponed until the chain justifies again.
- **Failover delay.** A normal forced takeover, without non-finality, costs 5–8 epochs of silence in the model.

## 5. What it assumes

- Each voter votes once per term. The arbiter is the one voter that is not a locked device.
- **A slashable pair needs the arbiter compromised together with one host, or together with a cut link between the sites.** A compromised host alone or a compromised arbiter alone is not enough, outside board replacement (§6, open). The model reproduces this limit on purpose (scenario 09: compromised arbiter plus a cut link between the sites, both hosts honest → pairs on 30 of 30 seeds).
- An arbiter restored from an old backup could forget a vote it already gave. Fix: a restarted arbiter does not vote in the current term or the next one (scenario 14: 0 pairs).

## 6. Open finding: replacing a board

**Replacing a device, as currently specified, is not safe against one compromised host at that site.** The new device has no clock and an empty vote record, and every input it gets about "now" comes from its own host. The model finds pairs on 30 of 30 seeds (scenario 19d). A candidate fix: every voter votes only for the current or next term, judged by trusted time sources its host cannot forge; a new device cold-starts from those sources instead of host inputs. In the model, trusted time without this vote horizon still gives pairs (votes collected in advance by the replaced device); with it, 0 pairs, including with a host that lies about time and replays old statements. Each vote is signed with, and names, the voting device's own identity key, and a replaced device's key is retired, so the old board can't vote on behalf of its successor. The design decision is still open, and the specification has not changed yet.

## 7. Results (run of 2026-11-25)

186 scenarios × 30 seeds each. Every signature and signing root is re-checked by an independent checker, which also searches all signed messages for slashable pairs. Overall: **all expectations met**. "Expected pairs" rows are deliberate: known limits, findings and ablations, where the checker must find pairs.

| scenario | what it does | missed duties | slashable pairs (seeds) | expected |
|---|---|---|---|---|
| 01-normal | no faults | 0 | 0 | 0 |
| 02a-site-a-dies | primary site dies, standby takes over | 1004 | 0 | 0 |
| 06a-compromised-active | active host attempts double / surround / double-block, replay, forgery, then dies | 1740 | 0 | 0 |
| 06c-compromised-successor | site A dies; B takes over with a compromised host feeding stale sources | 1930 | 0 | 0 |
| 07-compromised-arbiter | arbiter compromised (votes for anyone, lies in status); honest hosts; A dies and returns | 964 | 0 | 0 |
| 09-arbiter+split | compromised arbiter + cut link between sites | 0 | 2662 (30) | pairs: known limit |
| 10a-dongle-power-loss | sudden power loss at random points, incl. mid-write; host replays conflicting duties | 2212 | 0 | 0 |
| 11-planned-handover | planned handover A → B | 288 | 0 | 0 |
| 11d-…-stale-source | planned handover, successor host compromised, asks for a stale (genesis) source | 128 | 0 | 0 |
| 14-arbiter-rollback | honest arbiter restored from an old backup + cut link between sites | 0 | 0 | 0 |
| 15-stress-params-chaos | extreme parameters (term = 1 epoch, minimal flash headroom) + random faults + a compromised host | 3068 | 0 | 0 |
| 19d-FINDING-replace-lying-host | board replacement with one compromised host (§6) | 0 | 367 (30) | pairs: open finding |
| 20a-…-N1000-planned-handover | 1000 epochs without justification, planned handover | 132 | 0 | 0 |
| 20c-…-N50 / N200 / N1000-forced-takeover | forced takeover during 50 / 200 / 1000 epochs without justification | 4637 / 18061 / 90064 | 0 | 0 |
| 20d-…-N200-forced-compromised-successor | same, successor host compromised | 20355 | 0 | 0 |
| A1-ablation-no-floor | the take-over floor removed | 814 | 25222 (30), all surround votes | pairs: ablation |
| A2-ablation-literal-slot-term | lease checked against the slot only; a compromised host escapes its term with a far target | 2190 | 3256 (30) | pairs: ablation |

The ablations show the checks are live: take the floor out and the model produces surround votes on every seed.

**Mutation testing.** 51 deliberate mutations of the safety code: 43 are caught by at least one scenario, and 8 survive with a written reason (for example, defence-in-depth that another check already covers). Nothing survived unexpectedly.

## 8. Not covered here

- Fork schedule. By design a wrong or missing schedule can't cause a slashing, because watermarks compare only epochs and slots. It can cause missed duties on every key of a board that missed the update. A schedule change through the admin path takes effect no sooner than 24 h after the board accepts it. Runbook: push the schedule as soon as the fork epoch is announced, and confirm every board reports it well before the fork. Forks that change a signed schema need new firmware.
- Anything about physical boards: timing, flash wear, power behaviour on real hardware. That is the M0 benchmark.
