---
name: sdive-writeup
description: Write up and export security-dive clusters — for each tracked cluster, have the sdive-writer subagent draft the advisory (zepsec's result.json shape for the project), record and show it, revise on the user's feedback, approve, and export it to analysis/exports/ for zepsec's client-side tools. Invoke as /sdive-writeup <project> [cluster...|N] [--parallel P] [--ledger X]. Use after /sdive-triage.
argument-hint: "<project> [cluster...|N] [--parallel P] [--ledger main]"
allowed-tools: Bash, Read, Agent, SendMessage, AskUserQuestion
---

You run **write-up and export** with the user. The drafting happens in the
`sdive-writer` subagent; you brief it, record its result, show it to the user,
and approve and export only what the user accepts. The export is a local
directory that zepsec's client-side skills read; nothing leaves this machine.

## Arguments

`<project>`; cluster slugs, or a count `N` (default: every cluster that needs
work); `--parallel P` (default 1, at most 4) drafts in flight; `--ledger`
(default `main`). Every command below takes `--ledger <ledger>` before the
subcommand; it is left out here for brevity.

## Where things stand

`uv run sdive writeups <project> --json` lists the tracked clusters in
priority order (CVSS score: the write-up's once there is one, else the highest
of the members' verifier vectors; ties to the weaker attacker class), each
with its `state`:

- `needs-writeup` / `stale` (its membership changed since the last draft, or
  triage settled its shared-fix flag) → draft it (below).
- `needs-triage` → the writer said its fix also closes another cluster:
  settle it first (Shared fix, below).
- `draft` → show it and ask for review (below).
- `approved` → export it.
- `exported` → done; re-export only after a new version is approved.

Work through the named clusters, or the first `N` that are not `exported`, in
that priority order (so `1` is the most severe cluster still to do). If none
are named and there is no count, tell the user how many are in each state and
propose a batch (about six) before starting.

If a named slug is not in the list, check `uv run sdive clusters <project>`:
it may be a finding in no cluster, or a cluster with no track. Either way
there is nothing to write up yet; say which, and point the user to
`/sdive-triage <project>` (don't create clusters for unclustered findings from here). If the
list is empty, say so the same way rather than reporting "nothing to do".

## Draft

1. `uv run sdive writeup brief <cluster>` (add `--feedback "<what to change>"`
   for a revision in a new session; the brief carries the previous version).
2. Dispatch `sdive-writer` with exactly the prompt `Brief: <brief_path>`.
3. Run `uv run sdive writeup record <cluster>`. On a validation error (a CVSS
   band mismatch, `reportable` against the track, a missing component, a local
   path in the text, an unknown `shared_fix` cluster), SendMessage the error
   to the same agent to fix `result_path`, then record again (at most two
   rounds); if it still fails, report it and move on. If the output says
   **needs triage**, go to Shared fix before reviewing.

With `--parallel P`, brief P clusters and dispatch their writers in one
message; record each as it returns.

## Review

For each recorded draft, show the user `uv run sdive writeup show <cluster>`
(the `cluster.md` text), then your own short review: anything that looks wrong
against the members' claims (property, attacker class, CVSS metrics, the
configuration, the affected versions), and the writer's open questions. Ask:
approve, revise (with what to change) or skip.

- **Revise** → SendMessage the feedback to the same writer if it is still
  running, else brief again with `--feedback`. Record, show, ask again.
- **Approve** → `uv run sdive writeup approve <cluster> [--note "<caveat>"]`.
- Review several clusters in one message when there are several drafts; use
  AskUserQuestion for a single cluster.

## Shared fix

A recorded draft with `shared_fix` (`record` prints `! fix also closes …`)
cannot be approved: the writer says its recommended fix necessarily closes
another cluster too, so the two may be one CVE. Settle it here rather than
sending the user to another skill, following `/sdive-triage`'s rules (its
"shared-fix" step: the CVE counting rule, read both clusters and the code):

- propose a **merge** (`cluster add <c> <member>... --move`, `cluster drop
  <emptied>`, `cluster edit <c> --title/--rationale`, `cluster track <c> …
  --note`), or
- propose **separate**
  (`uv run sdive cluster separate <project> --clusters <c> <other> --note "<why two fixes>"`).

Run what the user approves, then draft again (a new brief; the merge changes
the members, the separate decision appears under `related_clusters`). Show the
user the draft's other content in the same message so the review is not lost.

## Export

Once approved: `uv run sdive export <project> <cluster>...` (or with no
cluster, every approved one). It writes
`<ledger>/exports/<project>/<cluster>/cluster.json` and `cluster.md` and moves
the members to `exported`. Print the paths.

## Finish

`uv run sdive writeups <project>`, then one paragraph: exported this session,
drafts awaiting review, what's left, and that zepsec's client-side intake
picks the exports up from `analysis/exports/<project>/` (for Mbed TLS no
intake exists yet: say the exports wait there for its hand-off tooling).

## Invariants

- Approve and export only what the user approved, by cluster. Record a merge
  or separate decision only on the user's yes, as in triage.
- Never edit a write-up or an export by hand; changes go through a new
  version (feedback → writer → record).
- Never read `analysis/truth/` or any zepsec analysis directory, and never
  give the writer anything but the brief path.
- Exports, write-ups and finding details stay in `analysis/`: never in
  committed files, commit messages, PRs or issues.
