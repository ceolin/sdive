---
name: sdive-rank
description: Rank a large code base for security-dive before spending deep-analysis time — the cheap sdive-ranker subagent judges, file by file, how directly an attacker reaches each function (0-3), and the scores reorder the dive and sweep queues. Invoke as /sdive-rank <project> [N|all] [--parallel P] [--min-priority K] [--ledger X]. Use on Zephyr-sized trees after `sdive units`, before dives.
argument-hint: "<project> [N|all] [--parallel P] [--min-priority 4] [--ledger main]"
allowed-tools: Bash, Read, Agent, SendMessage
---

You orchestrate **rank batches**. Each batch is a brief of whole files (the
best-scored ones whose functions have no reach judgement yet), sized to an
estimated context budget so the Haiku ranker stays in its cheap tier; a file
too large for the budget comes in line-range pieces; the
`sdive-ranker` subagent judges each function and `sdive` stores the
judgements and rescores the queue. This orders work; it finds no bugs and
records no coverage.

For hundreds of briefs, suggest `uv run sdive rank run <project> all --parallel 4`
instead: the same loop with no orchestrating model (each brief is a headless
`claude -p --agent sdive-ranker` session), so the cost is the ranker's alone.
This skill suits a few briefs, or watching the ranker's judgements.

## Arguments

`<project>`; a batch count `N` (default 1) or `all`; `--parallel P` (default
1, at most 4); `--min-priority K` (default 4: rank only areas at priority K
or above, where the deep work will go); `--ledger` (default `main`).

## Before the loop

Leftover briefs from an interrupted session lease their functions until
recorded. List them: `ls <ledger staging>/rank-*.brief.json` (the staging
path is in any brief). For each, run its `record_command`; if it says there
is no result file, delete that brief file.

## Loop

1. `uv run sdive --ledger <ledger> rank brief <project> --min-priority K`
   - Exit status 3: everything at that priority is ranked; stop.
2. Dispatch the agent named in `agent` with exactly the prompt
   `Brief: <brief_path>`.
3. Run `record_command`. On a validation error, SendMessage the error to the
   same agent to fix `result_path`, then record again (at most two rounds); if
   it still fails, delete the brief file and report.
4. Print one line: files ranked, functions by reach level.

**Parallel:** start up to P briefs (each `rank brief` call leases its
functions, so they never overlap), dispatch their agents in one message, and
record each as it returns.

## Finish

`uv run sdive --ledger <ledger> rank status <project>` and
`uv run sdive --ledger <ledger> rank show <project> --top 20`.

## Invariants

- Never write result files yourself or edit judgements.
- Never read `analysis/truth/` or any zepsec analysis directory.
