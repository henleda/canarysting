# AWS Demo Session Plan — getting the 5-min CISO arc running live

Goal: stand up the founder-approved demo arc (`DEMO_ARC.md`) end-to-end on the live M7
two-box window, record the deterministic cassette, and dry-run the run-of-show. Split into
**Part A (in-repo prep, solo, before the session)** so the live session is just "deploy →
record → dry-run", not "debug config knobs on the box."

Boxes (see the M7-window memory for current IPs): **server** (canaries + engine +
adapter + dashboard, private 10.20.1.24) and **client** (the prober/generator + the M9
attacker, bind 10.20.1.111). SSH: `ssh -i ~/.ssh/canarysting-dev ubuntu@<public-ip>`.

---

## Part A — in-repo prep (solo, before the session)

The demo posture is THREE knobs (not `set-demo-posture`'s `-aggressive`, which the founder
declined — realistic 3–5-touch was chosen):

| knob | where | demo value | why |
|------|-------|-----------|-----|
| `-contain-inline` (engine) | staged-range unit | **already ON** | T2 runs the inline attrition pump → real imposed cost (the bleed beat). No change. |
| `-aggressive` (engine tier thresholds) | `AGGRESSIVE_FLAG` in m7.env | **stays empty** | realistic 3–5-touch escalation (founder choice). No change. |
| `-sting-floor` (adapter) | adapter unit, **hardcoded `1`** | **needs `2`** (FloorAggressive) | activates all 5 axes (FloorAggressive builds tarpit+fakeMaze+poisonField+tokenBait+exploitBait+opExposure — confirmed attrition.go:154). Today the window runs floor 1 (velocity+poison only). |

**A1. Make the sting floor flippable via m7.env** (mirror the `AGGRESSIVE_FLAG` pattern):
add `STING_FLOOR` to m7.env (default `1` = the window's normal posture), change the adapter
unit's `-sting-floor 1` → `-sting-floor ${STING_FLOOR}`, and extend `set-demo-posture.sh` to
set `STING_FLOOR=2` (+ restart the adapter) for `aggressive-floor` and back to `1` for
`default`. So the session flips the floor cleanly and reverts (don't leave the live window
at FloorAggressive — it changes live behavior + the headline mechanism).

**A2. Dashboard build + deploy step.** `run-window.sh` builds only the engine+adapter; the
new Journey ribbon (PR #21) lives in the dashboard-backend (Go) + the frontend (`next
build`). Add a `deploy-dashboard.sh` (or extend run-window): `go build -o
$BIN/dashboard-backend ./cmd/dashboard-backend`; `npm ci && npm run build` in
`dashboard/app`; `systemctl restart canarysting-dashboard-backend canarysting-dashboard-web`.
Without this, the live wall won't show the journey.

**A3. `run-attack.sh` record/replay pass-through.** Add `--record <file>` and `--cassette
<file>` flags that pass `-record`/`-cassette` to the llm-attacker (the binary supports them
since PR #20; the wrapper doesn't surface them yet). `--cassette` implies no key needed.

**A4. Go version pre-flight.** The llm-attacker (cassette code) needs Go ≥1.24. Confirm the
box's Go (`ssh … go version`); if older, cross-compile locally
(`GOOS=linux GOARCH=arm64 go build ./cmd/llm-attacker`) and `SKIP_BUILD=1` on the box.

(A1–A3 are small, in-repo, testable; A4 is a check. I can land these as a small PR before
the session.)

---

## Part B — the live session (with Daniel, on the box)

Ordered; the reboot + revert steps are load-bearing.

1. **Sync `main` → server box.** `rsync -az --exclude=.git --exclude=bin/
   --exclude='bpf/*/vmlinux.h' --exclude=dashboard/app/node_modules --exclude=dashboard/app/.next
   ./ ubuntu@<server>:/home/ubuntu/canarysting/`.
2. **Redeploy engine+adapter+dashboard.** `sudo deploy/m7-window/run-window.sh` (engine+adapter+mesh)
   then `sudo deploy/m7-window/deploy-dashboard.sh` (A2). Confirms the Journey + the merged moat code are live.
3. **Set the demo posture.** `sudo deploy/m7-window/set-demo-posture.sh aggressive-floor` (A1 →
   adapter `-sting-floor 2`, all 5 axes). Leave `-aggressive` OFF (realistic escalation).
4. **REBOOT the server box** (F11): an adapter/sockops restart alone breaks cross-host
   cookie resolution; units are `Restart=always` + docker-on-boot, so they return clean.
   `sudo reboot`; wait; reconnect.
5. **Verify.** `deploy/m7-window/healthcheck.sh` (units active, Envoy ready, baseline DB
   growing, the prober's CANARY TOUCHes seen). Check the dashboard at
   `ssh -L 3001:127.0.0.1:3001 …` → localhost:3001: the wall renders, tap reachable,
   **calibration pill** state (see the calibration note below).
6. **Record the cassette** (client box): one real paid Opus run at the demo posture that
   ends on a CLEAN attacker-disengage (the engagement payoff). `./run-attack.sh --record
   /tmp/m9-demo.cassette --budget 5 --max-turns 30` (realistic). Inspect the run ledger +
   the journey on the wall; if the arc isn't clean (no disengage, odd path), re-record.
   Copy the cassette off the box. **This is the demo's deterministic spine.**
7. **Dry-run the arc** (the `DEMO_ARC.md` run-of-show): replay the cassette
   `./run-attack.sh --cassette /tmp/m9-demo.cassette` ($0, deterministic) and walk the 7
   beats against the live wall. Tune narration/timing. Then the live-cap proof:
   `./run-attack.sh --budget 0.50 --max-turns 5` (~$0.50, real, ~30s) — the "here it is live"
   closer. Prep the **terminal-curl bystander** (a legit-IP curl returning 200 while the
   attacker is jailed) and the **cross-customer forward-look diagram** (the two non-code assets).
8. **Decide the post-demo posture** (see decisions): revert to `default` floor (don't leave
   the live window at FloorAggressive) — `sudo set-demo-posture.sh default` + (if needed)
   reboot — OR keep it for a demo period.

---

## Calibration note (D6j-adjacent)

The acceleration/credibility beat is stronger when the scope is **calibrated** (the baseline
multiplier M is live, the Credibility panel shows it). The window started ~2026-06-09; by
demo time check the calibration pill (`evidence_seen` vs `evidence_floor`). If calibrated →
the M-live beat is real. If not → the core arc (recon→escalate→attrit→bleed→jail) still
works on touch-only scoring; narrate the calibration honestly as "still accruing" rather
than overclaiming. Do NOT fake calibration.

## Decisions for Daniel
- **Cross-customer beat:** the labeled forward-look diagram (chosen in DEMO_ARC), or batch a
  live D6 3rd box (scope-2) into this session? The 3rd box is a separate EC2 + calibration
  lead time (k≥feedK won't be reachable same-session) — the diagram is the honest call for a
  first demo; the live 3rd box is a bigger, later effort.
- **Post-demo posture:** revert to floor 1 after (clean — the window keeps its learning role)
  vs hold FloorAggressive for a demo window.
- **Cassette content:** the attack sequence to record (the five canary paths + a maze walk +
  a clean disengage). Default = let Opus run the standard recon→exploit flow at the demo
  posture and pick the cleanest of 1–2 takes.
- **Cost:** the box is ~$60/mo already; the cassette recording is ~1 paid run (≤$5 cap), the
  live-cap proof ~$0.50. Negligible.

## Risks (folded into the runbook)
- Reboot is required (F11) or cross-host cookie resolution breaks — step 4.
- Setting FloorAggressive changes live behavior + the headline mechanism; revert after (A1/step 8).
- A redeploy resets in-memory calibration EVIDENCE to 0 (re-accrues over days); the bbolt
  baseline rehydrates. So redeploy is a real cost to the learning window — do it AT demo prep,
  not casually. (This is why the redeploy was held for exactly this session.)
- The dashboard frontend must be `next build`-deployed (A2) or the wall is stale (no journey).
