---
name: sdive-bench
description: Run a blind security-dive benchmark round — a fresh disposable ledger at a commit with known ground truth, sweeps and dives with the current lenses and agents, verification of every hypothesis, then a scored report. Invoke as /sdive-bench <project> <truth-set> --rev <commit> [--round NAME] [--areas a,b,...] [--dives N|all] [--sweeps all|none|<lens,...>] [--parallel P]. Use to calibrate lenses and agent prompts before analysing current code.
argument-hint: "<project> <truth-set> --rev <commit> [--round NAME] [--areas a,b] [--dives all] [--sweeps all] [--parallel P]"
allowed-tools: Bash, Read, Agent, SendMessage
---

A benchmark round measures the *current* lenses and agents against a commit
whose vulnerabilities are already known. It must be **blind**: neither you nor
any agent reads the ground truth until the analysis is finished. Only the final
`sdive bench report` touches it.

## Arguments

`<project>`, `<truth-set>` (e.g. `vanessa`, imported earlier with
`sdive bench import`), `--rev` (required, e.g. `511dc9e2`), `--round` (ledger
name; default `bench-<truth-set>-<YYYYMMDD>`; refuse to reuse an existing
ledger directory under `analysis/ledgers/` — rounds start clean), `--areas`
(comma-separated; default: the whole project), `--dives` (default `all`),
`--sweeps` (default `all`), `--parallel` (default 1, passed to each skill),
`--verify` (`all`, the default, or `sample`).

On a tree the size of Zephyr a whole-project round costs about as much as a
full analysis. Restrict it with `--areas`, and import the truth set with the
same `--areas` (`sdive bench import ... --at <rev> --areas ...`) so recall is
measured over code the round covers. Areas are chosen before the round from
the truth set's import summary (item counts per area), never by reading
items; nothing about them goes into briefs.

## Steps

1. **Fresh ledger:** `uv run sdive --ledger <round> units <project> <rev>` —
   snapshots and indexes the commit in the new ledger.
2. **Sweeps** (unless `none`): follow the /sdive-sweep procedure with
   `--ledger <round> --rev <rev>` for each requested lens (with `--areas`:
   once per area, `--area A`).
3. **Dives:** follow the /sdive-dive procedure with `--ledger <round> --rev <rev>`
   and the `holistic` lens, for the requested count (with `--areas`: once per
   area, `--area A`).
4. **Verify:** follow the /sdive-verify procedure with `--ledger <round>` and
   `all`. With `--verify sample` (when hypotheses repeat heavily and
   verifying all would cost more than the round), do step 5 first, then write
   a slug file with every candidate match from the report plus a random
   sample of about 40 other hypotheses (seeded, so it can be reproduced) and
   verify with `--findings <file>`. Verifiers stay blind: their briefs are
   unchanged. Report precision as estimated from the sample, and re-run step 5
   after verifying.
5. **Score:** `uv run sdive --ledger <round> bench report <project> <truth-set> --rev <rev>`.
6. **Judge (with the user):** the report's location matches are only
   *candidates* — a finding in the same function as a truth item may be a
   different bug. Only judged matches count as raised. For each item with
   candidates, compare the finding's claim (`sdive finding show <slug>`) with
   the item title, propose a judgement to the user, and record the ones they
   agree with:
   `uv run sdive --ledger <round> bench judge <project> <truth-set> <item> <slug>...`
   (or `--none`; `--note` for the reason). Then re-run the report. Judgements
   live in the round's `adjudication.json`.

Steps 2–4 can take many runs. Report progress briefly after each step; if the
user stops partway, the ledger keeps everything done so far and the round can be
resumed with the same `--round`.

## Report to the user

- Recall: validated bugs in scope raised / confirmed by the verifier (judged).
- Traps: refuted claims raised, wrongly confirmed, correctly rejected (judged).
- Items still awaiting judgement, if any.
- Findings not judged to raise any truth item — these need human review: they
  may be new bugs (still present on `main`?) or false positives.
- For each missed validated bug: whether its code was examined (the `examined`
  column) — "not examined" is a coverage gap, "examined but not raised" is a
  lens/prompt gap.
- The model(s) used (`uv run sdive --ledger <round> runs <project>`).

Do not edit lenses or agent prompts in response to the report within the same
round; propose changes to the user, and measure them in a new round.
