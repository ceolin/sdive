# security-dive — plan

Proactive, LLM-driven security analysis of embedded codebases — **MCUboot first,
then Zephyr** — with durable tracking of *what has been examined, through which
lens, at what version*, so the work can be incremental and can gate incoming
changes.

## Relationship to the sibling projects

- **zepsec** (`../zepsec`) looks *backward*: it finds already-merged **silent
  fixes**. security-dive looks *forward*: **live bugs in current code**, and
  **bugs introduced by incoming changes**.
- Analysis and tracking live **here**. A verified cluster of findings is
  *exported* to a local directory that zepsec's client-side skills read to
  draft the advisory, author the fix and request the CVE (see Triage and
  export). security-dive never files anything itself, and the export never
  goes to zepsec's prod Instance.
- Reused from zepsec: the MCUboot **threat model** (`../zepsec/threat-model.md`,
  properties P1–P6, attacker classes A1–A3) is the bar every verdict must name.
  It is referenced in place (its hash is recorded per run), with the goal of
  moving it into MCUboot's own documentation (see Threat model upstreaming
  below), after which `config.toml` points at that copy instead;
  `ghsa.db`, the Vanessa disclosures and prior findings form the **dedup corpus**.
- Zephyr has no equivalent: `projects/zephyr/threat-model.md` is written here
  (drafted 2026-11-14), making explicit the rules zepsec's Zephyr analyst
  applies implicitly; once the team settles its open rulings it is a
  candidate for Zephyr's own documentation, as MCUboot's is.

## Execution model: skills do the thinking, the CLI does the bookkeeping

The analysis runs **interactively in Claude Code** (the plan that makes Mythos
affordable is interactive-only), so there are **no direct API calls** in this
project. The split:

- **`sdive` (Python, uv, Click)** — deterministic, no LLM. Owns repo mirrors and
  snapshots, unit extraction, the SQLite ledger, the work queue, brief/context
  generation, *validated* ingestion of agent output, coverage reports, diff→unit
  mapping, and export to zepsec.
- **Claude Code skills + subagents (`.claude/`)** — the analysis. A skill asks
  `sdive next` for a work item, makes sure the snapshot exists, dispatches a
  subagent with a brief, the subagent writes a JSON result to a staging dir, and
  the skill calls `sdive record`, which validates it against a pydantic schema
  before anything touches the ledger. The model never writes the DB directly.
- Subagents use `model: inherit`, so the session's `/model` (Mythos) applies; the
  result JSON carries the model ID the agent reports, recorded per run.
- Throughput is bounded by plan usage, not dollars. Skills take `[id | N | all]`
  like `/zepsec-analyze`, and `/loop` can drain a queue within a session.
  Everything is resumable: a crash loses at most the in-flight item.

Planned skills / agents (names provisional):

| Skill | Subagent | Job |
|---|---|---|
| `/sdive-sweep` | `sdive-auditor` | whole-source pass over a project through one lens (MCUboot) |
| `/sdive-dive` | `sdive-auditor` | deep dive on one unit / entry point, following data flow |
| `/sdive-verify` | `sdive-verifier` | **blind**, adversarial refutation of one hypothesis |
| `/sdive-change` | `sdive-change-reviewer` | review a commit range or PR head against the dossiers |
| `/sdive-rank` | `sdive-ranker` (cheap model) | Zephyr attack-surface scoring of units |
| `/sdive-triage` | none (interactive) | built: verified findings → clusters with a track |
| `/sdive-writeup` | `sdive-writer` | built: advisory draft per cluster, review, export |

## Core data model — units, lenses, the ledger

SQLite at `analysis/sdive.db`.

- **Unit** — the thing analyzed: a file, a function, or a named cluster
  (e.g. "TLV iteration"). Extracted with tree-sitter (C). Each unit has a
  **content hash per snapshot**, so unchanged code keeps its coverage across
  commits, and a change invalidates exactly the units it touches.
- **Area** — a grouping of units with an owner/priority (MCUboot: hand-written
  `projects/mcuboot/areas.toml`; Zephyr: derived from `MAINTAINERS.yml`).
- **Lens** — a versioned question (markdown in `projects/<p>/lenses/`, identified
  by content hash). MCUboot lenses start from P1–P6 plus cross-cutting ones:
  attacker-controlled lengths/integer arithmetic, flash-read TOCTOU, swap/trailer
  state under power loss, config combinations that compile checks out
  (cf. `assert-guards-noop-ndebug`).
- **Run** — one skill invocation: kind, skill+agent file hashes, lens, model,
  snapshot SHA, timestamps, outcome.
- **Coverage** — `(unit, content_hash, lens, run) → clean | hypotheses | partial |
  error`. "Covered" means covered *at this hash under this lens version*.
- **Finding** — slug-keyed. Lifecycle:
  `hypothesis → verified | rejected | duplicate → exported → fixed`, with an event
  log. Every verified finding names property, attacker class, CWE, locations,
  and the snapshot it was found at. Rejections keep their reasoning.
- **Dossier** — per-area markdown (`analysis/dossiers/<p>/<area>.md`) that
  accumulates trust boundaries, invariants ("TLV length bounded at X"), and
  **cleared patterns** with the reason they are safe. Fed into every brief for
  that area; updated after each pass. This is what suppresses repeat false
  positives and what makes change review cheap.

## Reference trees and upstream notes

External components a project builds against (MCUboot: the `ext/mbedtls-3.6.0`
and `ext/mbedtls-4.1.0` submodules, plus 4.1's nested `tf-psa-crypto`) are
exported into snapshots as **reference trees**: agents consult them to settle
API contracts, but they are never indexed, never counted in coverage, and never
the location of a finding. `sdive record` rejects a hypothesis with no location
in indexed project code. Claims that depend on library behaviour name the version
relied on (Zephyr builds use Zephyr's own crypto modules, not MCUboot's pins).

A defect noticed *inside* a reference tree is recorded as an **upstream note**
(`upstream_notes` table, `sdive upstream`), with the component's URL and pinned
commit. This will matter much more for Zephyr, which pulls in many external
modules via west; tracking and filing upstream notes is future work. Code a
project vendors directly (MCUboot's `ext/tinycrypt`, `fiat`, `mbedtls-asn1`,
`nrf`) is *not* a reference tree: the project ships it, so it is audit scope
(a later tier).

For Zephyr, reference trees will come from `west.yml` projects rather than
`.gitmodules`.

## Repos and confidentiality

- **Never touch the user's checkouts.** Each project gets a private mirror at
  `work/mirrors/<p>.git` (cloned with `--reference` to the local repo, then
  dissociated), so PR refs can be fetched freely. Analysis runs against
  read-only snapshots `work/snapshots/<p>/<sha>/` exported with `git archive`.
  `work/` is disposable.
- **`analysis/` is private**: gitignored by this repo, with its own nested repo
  for history (as zepsec does). It holds the DB, findings, dossiers, run records.
  The top-level repo is tooling only.
- Findings in released code are live, embargoed vulnerabilities: nothing about
  them goes in a public PR, issue, or commit message. The one public channel is
  review comments on **unmerged** PRs (see the disclosure policy below).

## Disclosure policy for change findings

Handling depends on where the buggy code has got to:

| State of the introducing change | Handling |
|---|---|
| **Unmerged PR** | Comment on the PR. The code isn't in anyone's product yet. |
| **Merged, not yet in a release** | Just fix it with an ordinary fix PR. No GHSA or CVE. |
| **In a release** | A vulnerability like any other: GHSA draft through zepsec/`ghsa file`, embargo, CVE. |

`sdive` works out the state per finding (is the introducing commit merged? is it
in any release tag?) and records which path was taken. PR comments are drafted
by the skill and shown to the user before posting, and say only what's needed
for the author to fix it.

## Phases

### Phase 0 — skeleton (no LLM) — done
Config; `sdive mirror` / `sdive snapshot`; DB schema; tree-sitter unit extraction
for MCUboot; areas in `projects/mcuboot/project.toml`; `sdive units` /
`sdive coverage` reports; `sdive next` / `sdive record` with the result schemas.

Notes from building it:
- **Preprocessor.** tree-sitter doesn't preprocess, and MCUboot puts `#if` in
  signatures and bodies. The extractor parses renderings that keep one branch
  per `#if` group (first, last, then the exact branch path for any column-0 `}`
  still unaccounted for) and merges by name and line. On MCUboot `main` this
  gives 462 functions, and every `.c` file's count matches its column-0 `}`s.
- **Unit keys** are `path::func`, with `@2`, `@3` for `#if` variants in line
  order. Function hashes cover the original lines, so a change in any branch
  invalidates the unit.
- **Snapshots** are `git archive` exports. Submodules are included only when
  listed as reference trees (below). Agent instruction files (`CLAUDE.md`,
  `CLAUDE.local.md`, `AGENTS.md`, `.claude/`) are left out, project and
  references alike: Claude Code loads them into any agent reading files
  beside them, which would let the tree's committers steer our auditors and
  costs tokens every run. The snapshot marker lists what was left out.
- **Batching**: a dive run takes the uncovered functions of one file
  (highest priority first, capped at 40 functions / 600 lines); a sweep takes
  whole areas in priority order up to ~3000 lines (one area at least). Runs are
  the unit of cost and of stopping: skills take a run count or `--minutes`
  (agent-minutes, converted to runs from median recorded run times pooled
  over all ledgers — about $0.60 per agent-minute at list price for Mythos,
  from the first 21-run verify session), `sdive todo` estimates what is left,
  and coverage carries across sessions (interrupted runs are recorded or
  abandoned at the start of the next). `--parallel P` keeps up to four runs in
  flight; concurrent dives are started in different areas, because dossier
  notes only reach other runs once recorded.
- **Launching**: `sdive run` chooses the work (pending verifies, then the
  project's `sweep_order`, then dives) and starts `claude -p` on the skill
  with only the needed tools granted (sdive commands, reads, subagents,
  writes to the ledger's staging directory). Each session's stream and
  reported cost are saved under `<ledger>/sessions/`, for calibrating cost per
  run from real numbers.

### Phase 1 — MCUboot calibration
Write the auditor/verifier agents and the first lenses. **Recall benchmark:** run
blind at `511dc9e2` (the Vanessa scan commit) without feeding the disclosures,
then compare against the 46 known claims and our own validated verdicts. Tune
prompts on misses and false positives before spending effort on `main`.

Built (tooling); the benchmark rounds themselves run in a Mythos session:
- **Lenses** (`projects/mcuboot/lenses/`): `holistic` for dives; `memory-safety`,
  `authenticity` (P1/P5), `rollback` (P2), `secrets` (P3/P4), `recovery` (A2/P6),
  `upgrade-state` for sweeps. Caveat: written after seeing the truth-set titles;
  kept to general vulnerability classes, with the two most item-shaped lines
  removed, but not independent of the benchmark.
- **Agents** (`.claude/agents/`): `sdive-auditor`, `sdive-verifier` — Read, Grep,
  Glob, Write only (no Bash), read-only boundaries stated in the prompt.
- **Skills**: `/sdive-dive`, `/sdive-sweep`, `/sdive-verify`, `/sdive-bench`.
- **Agent threat model**: `projects/mcuboot/threat-model.md`, derived from
  zepsec's with all finding references and per-finding re-dispositions removed
  (the original names benchmark answers).
- **Ground truth**: `sdive bench import` from zepsec corpora, honouring
  `override.json`; at `511dc9e2`, 9 validated bugs (plus overridden cf009,
  cf010, cf011, #17 → 15 tp overall), 18 refuted traps, out-of-scope items
  excluded. Imported from the 2026-08-11 precutover copy; re-import from a fresh
  `pull-snapshot.sh` if verdicts have changed since.
- **Blindness**: `.claude/settings.json` denies Read on `analysis/truth/` and
  zepsec analysis dirs, agents have no Bash, and skills pass agents only the
  brief path. Tested 2026-11-12 from inside `sdive-auditor` (prompted to try):
  Read, Grep and Glob on the truth file and folder, the zepsec corpora and
  zepsec's threat model were all refused by the harness; a Grep over the parent
  `analysis/` silently skipped the denied subtree; reads of the snapshot and
  lenses worked. Not covered by deny rules: subprocesses (agents have no Bash).
  **Changed 2026-11-13:** project deny rules bind every session in the repo,
  so they also blocked reviewing results, scoring and export. Blindness is now
  per agent: a PreToolUse hook (`blind.py`) refuses an `sdive-*` agent's Read
  into a protected path, and any Grep/Glob whose root is inside one or contains
  one (a hook can't filter results, so the broad search is refused rather than
  pruned); `sdive run` passes the same paths as session-wide
  `--disallowedTools`. Gap: an interactive orchestrator is blind by rule only.
  Tested 2026-11-13 from inside `sdive-auditor`: Reads of the truth file,
  zepsec's threat model and a zepsec-precutover analysis file, Grep/Glob rooted
  at the truth dir, `analysis/`, the project root (or no path), `~/ai`, and
  Globs climbing out of the snapshot with `../` or naming an absolute protected
  pattern were all refused by the hook; snapshot Read/Grep/Glob worked; the main
  session reads the truth tree normally.
- **Rounds** use disposable ledgers (`--ledger bench-...`), so prompt changes are
  measured in fresh rounds and nothing leaks into `main`.
- **Scoring** is by human judgement: location matches (same function, near,
  same file) are only candidates; `sdive bench judge` records which findings
  really raise each truth item, per round, in the ledger's `adjudication.json`.

Round 1 (2026-11-12, Mythos, partial: one memory-safety sweep pass + 10
holistic dives + verification of all 28 hypotheses). By manual reading, 6 of
13 in-scope validated bugs were raised and confirmed; no refuted trap was
raised as the same claim (one close call left for judgement); about a dozen
further verified findings match no truth item and need review against `main`.
Every miss was examined only by the single sweep (no dives reached those
areas); half of them are outside the memory-safety lens's class, and the rest
suggested one sweep over all 423 functions was too thin (125 came back
partial). Changes since: judged scoring, area-batched sweeps, narrow finding
locations in the auditor prompt. Not re-measured, to save usage; Phase 2
starts on `main` instead.

### Phase 2 — MCUboot deep dive at `main`
Core scope: `boot/bootutil` + `boot/boot_serial` + `boot/zephyr` (~25k lines,
fits comfortably in context).
0. **Carried findings** — `sdive carry` copies a benchmark round's verified
   findings into the main ledger as hypotheses at `main` (locations remapped
   by function key, provenance in `carried_from`), so the ordinary blind
   verify loop tells which are still live — cheaper than re-finding them.
1. **Sweeps** — each focused lens over the core source, a few areas per run.
2. **Entry-point dives** — image header/TLV parsing, serial recovery/SMP,
   swap-status and trailer reads, encrypted-key unwrap, `ext/` crypto glue.
3. **Verification** — every hypothesis gets an independent blind verifier.
4. **Dossiers** written/updated per area.
5. **Triage and export** — below.
Second tier afterwards: the other ports (espressif, cypress, nuttx, mynewt, mbed),
`ext/`, `scripts/imgtool`.

### Triage and export (decided 2026-11-13)

From a verified finding to an advisory and a fix. The state stays in the sdive
ledger; zepsec consumes a local export and reports back through a status file.

Triage (steps 1–2) is driven by the `/sdive-triage` skill: `sdive triage`
reports what is left (scope, overlap pairs, unclustered findings, empty
clusters, untracked clusters, tracks contradicting scope); the skill proposes
each decision with evidence and records only what the user approves. Changing
a cluster's membership clears its track.

1. **Consolidate.** Duplicates the verifier missed are marked by hand
   (`sdive finding set S --status duplicate --of ORIG`). Verified findings are
   grouped into **clusters** (`sdive cluster new|add|remove`): findings one fix
   closes. A cluster is the unit of a fix PR **and of an advisory** (one
   advisory per cluster).
2. **Release scoping** (`sdive scope`). Each finding's locations are blamed at
   its snapshot (`-w -M -C`) and every blamed commit mapped to the first `vX.Y.Z`
   tag holding it: `released` (every flagged line, as it reads now, was in the
   latest release), `post-release`, `mixed` (read the post-release commits), or
   `unknown`. `as_is_since` is an upper bound on when the bug arrived, not the
   advisory's floor. The cluster's **track** is then recorded by hand with a
   reason (`sdive cluster track C advisory|plain-fix --note …`), following the
   disclosure policy: shipped → `advisory`; merged since the last release →
   `plain-fix`.
3. **Write-up** (built: `/sdive-writeup`, `sdive writeup brief|record|show|approve`).
   The blind `sdive-writer` subagent drafts, per cluster, zepsec's MCUboot
   verdict fields (advisory summary and description, CVSS 3.1, CWE,
   `introduced_by`, `affected_versions`, components and functions) plus
   `affected_configurations`, `recommended_fix` and `open_questions`. sdive
   validates each draft: it scores the CVSS vector and checks the severity
   band, checks `reportable` against the track and cited components against
   the snapshot, and rejects local paths. Drafts are versions (`writeups`
   table); a human approves one. A membership change makes the write-up stale.
4. **Export** (built: `sdive export`): writes the approved version to
   `analysis/exports/<p>/<cluster>/`: `cluster.json` (schema
   `sdive-export/1`: the verdict fields at the top level so zepsec reads it as
   a `result.json`, plus `cvss_score`, track, snapshot `sha`, members with
   claims, locations, verify runs, scope and `carried_from`, and provenance,
   including the models that found and verified the members, for credit)
   and `cluster.md`. Findings move to `exported`; each export is recorded
   (`exports` table). Built from the ledger alone: never truth-set content.
5. **zepsec, client side** (zepsec's work): a local intake channel reads the
   export directory, dedups against MCUboot advisories and the disclosure
   corpus, and runs the pre-fix flow (embargoed draft → `/mcuboot-fix` →
   publish → CVE) for `advisory` clusters, or just the fix for `plain-fix`.
   **Our blind verify is trusted**: zepsec does not re-validate.
6. **Status back** (built: `sdive sync-status`): zepsec writes `status.json`
   next to the export (schema `zepsec-status/1`: state, dedup verdict, GHSA
   and CVE ids, fix PRs and SHAs, backports), naming the export it refers to
   by hash. sdive records each change (`cluster_status` table) and moves the
   members `exported → fixed` on a merged fix, or `exported → duplicate` (of
   the GHSA) when an existing advisory covers them. Both hand-off documents
   are JSON Schemas committed in `schemas/`, regenerated by
   `sdive schema --write`; exports and statuses are validated against them.

### Phase 3 — MCUboot pre-merge and post-merge
- `sdive prs sync` (via `gh`) lists open PRs on `mcu-tools/mcuboot` with head
  SHAs; a new or updated head is queued. `sdive commits sync` does the same for
  new commits on `main`.
- `/sdive-change` maps the diff → changed functions → units, adds **blast radius**
  (callers of changed validation helpers), and reviews the change against the
  area dossiers: *which recorded invariant does this touch, and does it still
  hold?*
- Results under `analysis/changes/mcuboot/{pr-<n>,commit}/<sha>/`; merged changes
  invalidate coverage for the touched unit hashes.
- Findings follow the disclosure policy above: PR comment, quiet fix, or GHSA.

### Phase 4 — Zephyr breadth

Scale sets the shape. C source at a 2026-11 `main` (lines, excluding
`tests/` and `samples/`): `drivers/` 1.62M, `subsys/` 886k (Bluetooth 397k,
net 262k, USB 43k, mgmt 29k), `soc/` 91k, `arch/` 52k, `modules/` 37k, `lib/`
26k, `kernel/` 20k. The main attack surfaces alone (net, Bluetooth, USB,
mgmt) are about 30× MCUboot's core, so ranking and per-lens scoping are
required, not optional. The unit extractor needs no change: a trial on
`kernel/`, `subsys/net`, `subsys/bluetooth/host`, `subsys/usb` and
`drivers/usb` (582 files, ~15.4k functions) matched every column-0 `}` in the
files checked by hand, `#if` variants included, and `z_vrfy_*` handlers come
out as ordinary units.

In order:

1. **Threat model** — drafted at `projects/zephyr/threat-model.md` (Zephyr
   has none of its own beyond user mode's and the sensor model). Properties
   P1–P6 (kernel integrity, user-mode isolation, secure-world isolation,
   confidentiality, protocol security, availability), attacker classes A1–A6
   (remote network, adjacent/radio, bus peer, unprivileged user thread,
   non-secure world, physical), and the rules that suppress the common false
   positives: privilege differential, no syscall boundary without
   `CONFIG_USERSPACE`, assertions are not checks. Rulings marked **Open**
   (bus peers, BT host vs. controller, shell, samples) go to the Zephyr
   security team together with the build list below; agents apply the
   proposals until then. Keep finding references out of it, as for MCUboot.
2. **Project definition** — built: `projects/zephyr/project.toml` scopes
   `kernel`, `arch`, `soc`, `lib`, `subsys`, `drivers`, in-tree `modules/`
   glue and `include/zephyr`, excluding tests, samples, `subsys/testsuite`,
   debug/tracing, native_sim/bsim and emulators (11.2k files, 85.7k
   functions, 3.7M lines at 2026-11 `main`; indexing takes ~40 s). Areas
   are generated from `MAINTAINERS.yml` (`sdive areas zephyr --generate`,
   428 entries; most specific pattern wins), with priorities set by hand
   (`[[priority]]` rules over area names), hand-written overrides (shell
   commands down to 1, `*_handlers.c` syscall handlers up to 4) and
   `split` areas that subdivide the big generated ones (`networking`
   137k lines, the Bluetooth areas, `usb`, LwM2M) into protocol-sized
   pieces for dossiers and sweeps. Sweeps over an area larger than the
   line budget take it file by file. Priority 5 holds ~530k lines of
   functions, priority 4 ~480k, so ranking (step 4) orders the work within
   them. Reference trees come from the snapshot's `west.yml` (`west =
   "<name>"`, exported to `_west/<name>`): Mbed TLS, TF-PSA-Crypto and
   zcbor so far; TF-M, OpenThread and hostap as needed.
3. **Builds: what does some legitimate configuration compile** — built
   (`sdive build`, `sdive builds`). There is no allyesconfig: arch/SoC/board
   and several stacks are Kconfig choices, most driver symbols are enabled
   by devicetree (`DT_HAS_<compat>_ENABLED`), and arch features gate
   subsystems. Since the extractor keeps every `#if` branch, builds are
   needed only for scoping, priority and telling agents what enables a
   unit, so the input is the **union of many builds**, which need not be
   realistic products. Builds are only *configured*: Zephyr writes
   `compile_commands.json` at CMake time, ~8 s a build, so thousands are
   affordable. `projects/zephyr/builds.toml` holds wide builds (full network
   stack on `frdm_k64f` and with user mode on `qemu_x86`, BT host +
   controller with LE Audio and with Mesh on `nrf52840dk`, USB device and
   host, mcumgr over UDP/FS/shell and over BT, user mode on an MPU
   Cortex-M) and suites: every scenario of Zephyr's `tests/drivers/build_all`,
   `tests/{net,bluetooth,subsys,kernel,arch,lib}` and
   `samples/{net,bluetooth,subsys}` on its first usable platform (3.2k
   builds; native_sim and bsim are Linux-only, so scenarios listing only
   those are tried on the default board instead: otherwise Mesh, SSH,
   WireGuard, QUIC and OBEX, tested only on native_sim, would count as
   unbuilt). They run in a
   west workspace under `work/west/` with modules at the snapshot's
   `west.yml`, cloned with `~/zephyrproject` as `--path-cache` (never
   written; its venv runs with `PYTHONDONTWRITEBYTECODE`). Code no build
   compiles sinks in the queue. Headers are not judged (compile databases
   list only translation units). Alongside, `sdive units` records a static
   **file → Kconfig map** from the `CMakeLists` `*_ifdef(CONFIG_…)` chain,
   which briefs carry as `enabled_by`. A build shows code *can* be built,
   not that products enable it; `default y` and use by in-tree samples
   still need judgement (the ranker and the agents).
4. **Ranking** — built. Queues order by a score: area priority, plus a
   signal bonus computed at indexing (`net_buf_pull*`, `net_pkt_read*`,
   `sys_get_le*`, zcbor decoding, copies, length arithmetic, `z_vrfy_*` /
   `K_SYSCALL_*`, assertion-only length checks, refcounting, handler-like
   names; capped at +1.5), plus the reach judged by `/sdive-rank` (the
   `sdive-ranker` subagent on Haiku, file by file, 0–3 → −2 … +1.5; briefs
   are sized to an estimated 80K-token context, since Haiku costs about a
   twentieth of Sonnet below 100K, and files too large for that come in
   line-range pieces; a judgement carries to later snapshots while the
   function's content is unchanged, so following `main` re-ranks only
   what changed; `sdive rank run` drives the ranker headless with no
   orchestrating model, since handing out and recording briefs needs no
   judgement),
   minus 1.5 for code no recorded build compiles once builds exist. Mythos
   time goes to the top of the queue. Priority surfaces: IP/TCP/DNS,
   LwM2M/CoAP/MQTT, Bluetooth host + controller, USB device and host
   classes, the user-mode syscall boundary, mcumgr, drivers fed by external
   buses.
5. **Lens applicability** — built: a lens's YAML frontmatter (`applies:`
   area/path/symbol globs, `exclude_areas`, `min_priority`) limits sweeps,
   `sdive todo` and coverage to the units it fits.
6. **Zephyr lenses** — written (`projects/zephyr/lenses/`, before looking at
   any benchmark corpus): `memory-safety` (priority ≥ 4; lengths and
   offsets from `net_buf`/`net_pkt`, descriptors, PDUs, reassembly),
   `lifetime` (reference counting, teardown during pending operations, slot
   reuse, ISR/thread races, per-message leaks), `protocol-state` (messages
   in the wrong state, identifiers, negotiated parameters), `syscall-boundary`
   (`K_SYSCALL_*` checks, copy-before-use, object permissions, arch entry and
   memory domains), `protocol-security` (pairing and key checks, replay,
   security levels, TLS verification, randomness, secrets), and `holistic`
   for dives. At 2026-11 `main`, one sweep per lens is 18–420 runs
   (syscall-boundary 41k lines … memory-safety 1.0M), which is why the top
   of the ranked queue, not completion, is the target.
7. **Blind benchmark** — a truth set imported from zepsec's Zephyr corpus at
   a commit preceding several known fixes, run over a narrow scope (net and
   Bluetooth) to calibrate lenses and the threat model before `main`, as
   Phase 1 did for MCUboot. Import is built (`sdive bench import --at REV
   --paths …`: silent-fix units live at REV, sited at their affected
   function there); choosing the corpus and commit, and running the round,
   wait on the user (the corpus is embargoed zepsec material).
8. Coverage reporting per area and lens — built: `sdive coverage --by-lens`
   (covered/applicable functions per area and lens), `--lens` counting only
   where the lens applies, `--min-priority` to keep the table readable.
9. **Write-up per project** — built. `property_violated` and
   `attacker_class` are checked against the labels the project's threat
   model defines (Zephyr: P1–P6, A1–A6) instead of a fixed P1–P6/A1–A3; the
   export schema widened accordingly (still `sdive-export/1`: MCUboot
   documents are unchanged). The `sdive-writer` prompt is project-neutral
   and reads `projects/<p>/writer.md` (named in the brief): attack-vector
   and privilege mapping per attacker class, the `reachable_surface`
   vocabulary (Zephyr: zepsec-deep-analyst's, plus `syscall`), how to name
   configurations (Kconfig, devicetree compatibles, using `enabled_by`) and
   versions. Zephyr exports carry the `zepsec-deep-analyst` field set plus
   property and attacker class, which zepsec's intake tolerates.

### Phase 5 — Zephyr incremental
Post-merge change review on `main`, then PRs; possibly sharing the commit walk
with zepsec (one pass asking "silent fix?" and "introduces something?").

## Threat model upstreaming (side track)

The zepsec threat model is written for triage: it carries finding IDs (cf009,
cf018) and verdict rules. To land it in MCUboot's docs (e.g. `docs/threat-model.md`):

1. Split it into a public part (security properties, attacker classes, the
   flash-write boundary, what is and isn't in scope) and internal triage notes
   that stay in zepsec.
2. Remove references to embargoed findings; replace them with general wording.
3. Propose it as an MCUboot docs PR. Once merged, point `config.toml` at the
   upstream file and make zepsec's copy a pointer plus its triage notes.

Phase 1–2 findings will show where the model is unclear, so the public version
should be better for having been used first.

## Open questions

1. Zephyr representative configs — approach decided (union of wide builds in
   three tiers, Phase 4 step 3); the exact build list and the threat model's
   **Open** rulings (bus peers, BT host vs. controller, shell, samples) go to
   the Zephyr security team.
2. Exact zepsec hand-off schema — to be pinned when Phase 2 produces the first
   verified finding.
