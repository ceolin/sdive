---
name: sdive-triage
description: Drive security-dive triage interactively — turn verified findings into clusters (one fix, one advisory, one CVE each) with a recorded track. Works through `sdive triage`'s steps (release scoping, overlap pairs to merge or separate, duplicates, clustering, track, writers' shared-fix flags), proposes each decision with its evidence, and records it only after the user approves. Invoke as /sdive-triage <project> [--ledger X]. Use after verification, before write-up and export.
argument-hint: "<project> [--ledger main]"
allowed-tools: Bash, Read, Grep, Glob, AskUserQuestion
---

You run **triage** with the user. Triage answers four questions about each
verified finding:

1. **Did the buggy code ship in a release?** (release scoping: deterministic)
2. **Is it the same bug as another finding?** (missed duplicates: judgement)
3. **Which fix closes it, and what else does that fix close?** (clusters: judgement)
4. **Advisory or plain fix?** (the cluster's track: the user's decision)

The ledger decides nothing by itself. You read the evidence and the code,
**propose** each decision with a short reason, and record it once the user
says yes. You never record a judgement the user hasn't approved.

## Arguments

`<project>`; `--ledger` (default `main`). Every command below takes
`--ledger <ledger>` before the subcommand; it is left out here for brevity.

## Loop

Run `uv run sdive triage <project> --json`. Its `next` names the first step
with work left. Do that step (below), then run `sdive triage` again. Stop when
`next` is null, or when the user wants to stop.

Present decisions in **batches of at most six**, as a numbered list: the
proposal (as the exact command you would run) and a one- or two-line reason
from the evidence. The user approves everything, approves some, or changes
some. Use AskUserQuestion for a single decision with clear alternatives (e.g.
"duplicate / same cluster / separate"); use plain text for a batch. Run the
approved commands, show their output, move on.

### scope: release-scope new findings

No decision involved: run `uv run sdive mirror <project>` (new tags), then
`uv run sdive scope <project>`. Show the table. `mixed` verdicts are read at
the track step, not now.

### overlaps: pairs of findings that share code

For each open pair (`overlaps` in the JSON: not in one cluster and not
recorded as separate; sides may already sit in two different clusters),
read both findings (`uv run sdive finding show <slug>`) and the shared code in
the finding's snapshot, `work/snapshots/<project>/<sha>/`. Decide which of
three it is:

- **Duplicate**: one defect, described twice. Same root cause at the same
  place; fixing it removes both failures. Propose
  `uv run sdive finding set <copy> --status duplicate --of <orig> --note "<why>"`.
  Keep as `<orig>` the clearer, better-located claim (if equal, the older one).
- **One fix**: different defects or symptoms, but one change necessarily
  closes both. Propose putting both in one cluster: `cluster new` / `cluster
  add` if a side is unclustered, or a merge if both are clustered
  (`cluster add <keep> <slug>... --move`, `cluster drop <emptied>`,
  `cluster edit <keep> --title/--rationale` to cover both, then its track).
  Prefer to keep the cluster with the broader title or an existing write-up.
- **Separate**: distinct defects that happen to share lines (common: several
  bugs on one parsing path). Each goes to its own cluster. Sharing code is only
  a lead; say which distinct root causes you see, and propose
  `uv run sdive cluster separate <project> <a> <b> --note "<root cause a; root cause b>"`.

A pair leaves the list only when it is in one cluster or recorded as separate.
When many pairs are open (e.g. the first run after everything was clustered),
group them by subsystem and present the merges first, then the separations as
batches.

### cluster: verified findings in no cluster

Each one joins an existing cluster (`uv run sdive cluster add <cluster> <slug>`)
or starts one:
`uv run sdive cluster new <project> <cluster-slug> <slug>... --title "<title>" --rationale "<why one fix>"`.

**The CVE counting rule decides the shape.** Zephyr is MCUboot's CNA and wants
one CVE per independently fixable flaw. Join findings only when one natural
change *necessarily* fixes them all. If the fixes could land as separate
commits, they are separate clusters, even when the findings sit in one
function or share a theme (e.g. "missing zeroisation" in three places is three
fixes unless one helper closes all three). Most clusters hold one finding.

Name the cluster after the flaw, not the finding: lowercase, `-`-separated,
short (`serial-upload-align-overflow`). The title is what an advisory title
would say; the rationale says what the one fix is.

Existing clusters can be reshaped: `cluster add <c> <slug> --move` (take a
finding from another cluster), `cluster remove`, `cluster new ... --move`
(split), `cluster edit <c> --title/--rationale`, `cluster drop <c>` (empty
clusters only). Any membership change clears both clusters' tracks.

### empty: clusters left with no members

After a merge or a duplicate marking. Propose `uv run sdive cluster drop <c>`.

### track: clusters with no track

Before proposing a track, **check the cluster's shape**: run
`uv run sdive cluster show <c>`. Should the cluster be split (fixes could land
independently)? Raise that as a reshaping proposal first. (Merges with other
clusters come from the overlaps and shared-fix steps.)

Then the track, following the disclosure policy in `PLAN.md`:

- scope `released` → **`advisory`**.
- scope `post-release` → **`plain-fix`** (merged since the last release, never
  shipped: an ordinary fix, no GHSA or CVE).
- scope `mixed` → read the post-release commits:
  `uv run sdive scope <project> <slug> --json` lists them per location
  (`post_release: true`); look at each with
  `git --git-dir work/mirrors/<project>.git show <sha>`. If they only change code
  around the defect (error handling, formatting, a constant) and the defect
  itself was in the release, it is `advisory`; if a post-release commit
  introduced the defect, `plain-fix`.
- scope `unknown` → nothing blamable (e.g. a submodule path); tell the user
  what you can see and let them decide.

The note records the evidence, e.g. `released: all flagged lines in v2.5.0,
as-is since v2.0.0` or `mixed: post-release 59d24dd8ee only raises
BOOT_MAX_ALIGN; overflow present in v2.5.0`. Propose
`uv run sdive cluster track <c> advisory|plain-fix --note "<evidence>"`.

### check: a track contradicting its scope

`advisory` with scope `post-release`, or `plain-fix` with `released`: usually
the scope was redone after the track was set. Show both and propose a new
track decision.

### shared-fix: a writer says one fix closes two clusters

The `sdive-writer` read the code for a write-up and named, in `shared_fix`,
other clusters its recommended fix necessarily closes (`open` in the JSON:
each with the writer's reason). Read the writer's reason, both clusters'
members (`cluster show`) and the code, and judge it by the CVE counting rule:

- **Merge** when the natural fix closes both. Fold the other cluster's members
  into the flagged one (as under one fix above) and set the track again.
- **Separate** when a narrower fix could land for each: propose
  `uv run sdive cluster separate <project> --clusters <c> <other> --note "<why two fixes>"`.

Either way the write-up becomes `stale`; the next `/sdive-writeup` brief
carries the outcome.

## Finish

`uv run sdive clusters <project>`, then one paragraph: how many clusters by
track, anything left undecided, and that the next step is write-up and export.

## Invariants

- Record nothing the user hasn't approved, except `sdive mirror` and
  `sdive scope` (evidence, not decisions).
- Don't change verification verdicts. If a verified finding looks wrong, say
  so and leave it for the user (`sdive finding set` at their request); triage
  only marks duplicates.
- Never read `analysis/truth/` or any zepsec analysis directory, and never
  look up known advisories to shape clusters: dedup against published
  advisories is zepsec's job, after export.
- Read code only in `work/snapshots/` and `work/mirrors/`, never in the
  user's source checkouts.
- Finding details stay in the ledger: never put them in committed files.
