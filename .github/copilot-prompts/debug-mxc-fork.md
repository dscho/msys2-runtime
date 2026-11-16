# Prompt for Copilot CI debugging session

## Context

You are running on a GitHub Actions `windows-2025` (x64, Windows Server
2025) runner where the `mxc-fork` job's `Run Bash and a forked child inside
an MXC process container` step just failed (or, if that step was skipped,
an earlier step failed; check which one first). The earlier steps of the
workflow that prepared the environment (checkout, MSYS2 installation via
`msys2/setup-msys2`, building `msys-2.0.dll` from this checkout, assembling
a private runtime under `mxc/runtime`, installing `@microsoft/mxc-sdk`)
succeeded; the failure is downstream of that.

Your working directory is the checkout root (`$GITHUB_WORKSPACE`). **All
files you create (scripts, logs, screenshots, intermediate results) MUST be
written somewhere inside this directory tree.** Files outside it will be
lost when the runner is reaped. The entire working directory (or the
artifact paths configured by the workflow: `mxc/policy.json`,
`mxc/output.log`, `mxc/diagnostics.log`, `ci-diagnosis/`,
`copilot-diagnosis.md`, `copilot-session.tar.gz`) will be uploaded as a
build artifact, which is the only channel by which your work reaches the
human operator after the job finishes.

Your final findings MUST be written to `copilot-diagnosis.md` in the
checkout root. Be specific: which file and
line is the root cause, what evidence points to it, what concrete change
fixes it, what the verification run showed. Do NOT propose changes that you
have not verified work end-to-end.

Treat the diagnosis file as a **living document**: update it as your
understanding evolves, so that even if the session is interrupted or
truncated, the most recent version captures everything you have learned so
far. The worst outcome is a session that did real work but left no
breadcrumbs because the diagnosis file was only going to be written "at the
end".

## Background for this specific failure (READ before Step 1)

### What is being tested

This repository is the MSYS2 runtime: a fork of the Cygwin DLL, built as
`msys-2.0.dll`, which gives Windows programs a POSIX environment
(`fork()`, signals, mount table, ...). Bash and all other MSYS2 programs
load it.

Microsoft's MXC (https://github.com/microsoft/mxc) runs a process inside a
"process container", an AppContainer-style sandbox: a restricted token, a
private object namespace, and file and network access only where a JSON
policy grants it. The `wxc-exec.exe` tool from the npm package
`@microsoft/mxc-sdk` launches a command under such a policy. The
workflow's policy is in `mxc/policy.json`: it runs
`mxc\runtime\usr\bin\bash.exe`, grants read-write access only to the
`mxc` directory, and denies network access. The private runtime in
`mxc/runtime` holds `bash.exe`, `uname.exe`, `id.exe`, their `msys-*.dll`
dependencies, the `msys-2.0.dll` freshly built from this checkout, plus
copies of MSYS2's `/etc/nsswitch.conf` and `/etc/fstab`.

The script Bash runs inside the container is:

```
set -e; printf 'bash started\n'; /usr/bin/uname -a; /usr/bin/id; /usr/bin/bash --noprofile --norc -c 'echo child started'
```

Each external command requires a `fork()`, so `child started` proves that
forking works.

### What this branch contains

- `main` of msys2/msys2-runtime, merged with
  https://github.com/git-for-windows/msys2-runtime/pull/148 ("Support
  AppContainers' namespaces for shared objects" and "Cygwin: socket: Keep
  the socket event table in the Session namespace"). Without that PR, the
  runtime cannot even start inside the container: `bash.exe` dies at
  startup with STATUS_DLL_INIT_FAILED (0xC0000142).
- A commit removing the regular CI workflow (`TO-DROP`), and the
  workflow that runs this reproducer.

The original report is https://github.com/msys2/msys2-runtime/pull/403
("Cygwin: handle restricted SAM and relocated runtime images"). That PR
claims to fix runtime images loaded at a relocated address and failing
user-database lookups in restricted sandboxes. It is NOT applied here.
Its diff is available at https://github.com/msys2/msys2-runtime/pull/403.diff
and is a candidate fix you may apply and test. Treat its claims as
unverified.

### Evidence from local runs (Windows 11, `@microsoft/mxc-sdk` 1.0.1)

1. With this exact branch, `bash started` is printed, then every fork
   child dies before it can talk to the parent:

   ```
   bash started
         0 [main] bash 286 dofork: child -1 - forked process 8388 died unexpectedly, retry 0, exit code 0xC0000142, errno 11
   /usr/bin/bash: fork: retry: Resource temporarily unavailable
   [... same line 4 more times with other PIDs ...]
   /usr/bin/bash: fork: Resource temporarily unavailable
   ```

   Exit status 254. No `copy failed` line was printed.
2. With https://github.com/msys2/msys2-runtime/pull/387 merged in (it
   re-executes the process once when the runtime DLL appears to have been
   mapped from two different files at different addresses), the run
   turned into a runaway: `bash started` was printed 463 times until the
   30 s policy timeout, plus a few `dofork ... 0xC0000142` lines; no
   `child started`.
3. With an alternative variant of #387 (same idea, but the check runs
   early in `_dll_crt0` and is skipped whenever the process was started
   as a fork or spawn child, i.e. when `child_proc_info` is set),
   `bash started` was printed 164 times until the timeout, with no
   `dofork` errors and no `child started`.

Observations 2 and 3 suggest that some processes which should have been
fork children ran Bash's `main()` from the top again, but that is an
unverified hypothesis.

### Relevant code (verified file:line pointers in this checkout)

- `winsup/cygwin/init.cc:80-96`: `DllMain`, `DLL_PROCESS_ATTACH` calls
  `dll_crt0_0 ()`. Anything that fails or crashes in there makes the
  Windows loader fail the process with 0xC0000142.
- `winsup/cygwin/dcrt0.cc:726-781`: `dll_crt0_0 ()`. Calls
  `wincap.init ()`, `get_cygwin_startup_info ()`, then for a fork child
  `fork_info->handle_fork ()`.
- `winsup/cygwin/dcrt0.cc:526-578`: `get_cygwin_startup_info ()`. A fork
  child recognises itself only through the `child_info` block the parent
  passes in `STARTUPINFO.lpReserved2`, validated by magic numbers.
- `winsup/cygwin/dcrt0.cc:585-597`: `child_info_fork::handle_fork ()`.
  Calls `cygheap_fixup_in_child (false)`, then copies the parent's
  "dll data" and "dll bss" into the child **at the same addresses**. That
  is only correct if `msys-2.0.dll` is loaded at the same base address in
  parent and child.
- `winsup/cygwin/mm/cygheap.cc:85-104`: `cygheap_fixup_in_child ()`.
  Reserves and commits memory at the fixed address `CYGHEAP_STORAGE_LOW`
  (`0x800000000`, `winsup/cygwin/local_includes/memory_layout.h:39-41`)
  and copies the parent's Cygwin heap there with `ReadProcessMemory`.
  The `VirtualAlloc` return values are not checked. (Note:
  `winsup/cygwin/DevDocs/how-cygheap-works.txt` still describes the old
  32-bit layout where the heap followed the DLL; on x64 it is at this
  fixed address.)
- `winsup/cygwin/fork.cc:729-775`: `child_copy ()`; on failure it prints
  `... copy failed ...` (unless `silentfail`) and terminates the other
  process.
- `winsup/cygwin/fork.cc:360-415`: the parent's `CreateProcessW` and the
  first `ch.sync`; the `died unexpectedly` message comes from line 412,
  i.e. the child died before its first synchronisation with the parent.
- `winsup/cygwin/mm/shared.cc:198` and `winsup/cygwin/mm/mmap.cc:190`:
  comments documenting earlier STATUS_DLL_INIT_FAILED-during-fork bugs
  caused by how sections are mapped.
- `winsup/cygwin/sigproc.cc:1192`: how the runtime reports
  STATUS_DLL_INIT_FAILED exit codes.

### Starting hypotheses (not exhaustive; rank and extend them yourself)

- H1: In the fork child, `msys-2.0.dll` (or another DLL, or the
  executable) is mapped at a different base than in the parent, so the
  data/bss copy in `handle_fork` corrupts the child.
- H2: The fixed cygheap region at `0x800000000` is not available in the
  child inside the container, `VirtualAlloc` fails silently, and the
  child crashes on the NULL `cygheap`.
- H3: The child cannot open, read from, or synchronise with the parent
  (process access rights, inherited handles, or named objects in the
  AppContainer namespace that PR #148 changed), and `dll_crt0_0` fails.
- H4: Something else in `dll_crt0_0` fails only in fork children inside
  the container (`wincap.init`, privileges, `cygthread::init`,
  `sigproc_init`, ...).

### Tools and commands specific to this job

- Run MSYS2 commands from PowerShell with `msys2 -c '<command>'` (the
  `msys2` wrapper is on `PATH`; the workflow uses `shell: msys2 {0}`). It
  starts in the current directory; verify that with `msys2 -c pwd` once.
- Rebuild the DLL incrementally and refresh the private runtime from the
  checkout root:

  ```
  msys2 -c 'make -j8 && cp x86_64-pc-cygwin/winsup/cygwin/new-msys-2.0.dll mxc/runtime/usr/bin/msys-2.0.dll'
  ```

  A source change in `winsup/cygwin` must make this take at least tens of
  seconds and change the DLL's timestamp; if not, your change was not
  built.
- Control experiment: run the same private runtime OUTSIDE the container
  (from `mxc`):
  `.\runtime\usr\bin\bash.exe --noprofile --norc -c "<the script above>"`.
  It should print `child started`. If it does not, the problem is the
  build or the private runtime, not the container.
- `wxc-exec.exe --probe` reports what the host supports. If `bash
  started` never appears at all, determine whether process containers
  work on this Windows Server 2025 runner at all (Microsoft documents
  them only for Windows 11:
  https://github.com/microsoft/mxc/blob/main/docs/backends/process-container/os-version-support.md).
  If they do not, document the evidence (probe output, diagnostics log,
  OS build number) and stop; that cannot be fixed in this repository.
- MSYS2's `/usr/bin/strace.exe` uses the same runtime and can be copied
  into `mxc/runtime/usr/bin` to trace inside the container, but it relies
  on debugging the traced process; whether that works inside the
  container is unknown. Writing targeted diagnostic output from
  `dll_crt0_0` / `handle_fork` (e.g. to a file under `mxc`, the only
  writable place inside the container) is a reliable alternative.
- To test a policy variant, write it to a new file under `ci-diagnosis/`
  and pass that to `wxc-exec.exe`; keep `mxc/policy.json` unchanged.

## Operating principles (READ FIRST, mandatory)

### Verify, do not guess

Every factual claim you make - whether in the diagnosis, in chat, or in the
proposed fix - must be backed by concrete evidence: a log line you just read,
a source line you just opened, the output of a diagnostic script you just
ran, the output of `git log` / `git blame` showing when something changed.
"It looks like X" is not a diagnosis; "I ran Y at step Z, output was W, here
are the relevant lines" is. If you cannot verify a claim, abandon it. Never
hallucinate.

### Predict before you test

Before running any diagnostic or applying any fix, state in chat **what you
expect to observe and why**. If the actual result diverges from the
prediction, your mental model is wrong: investigate the divergence. Do NOT
patch the next visible symptom. Do NOT call unexpected behaviour "normal",
"an edge case", or "a test artifact" until you can explain its exact
mechanism.

### List multiple hypotheses, then rank

The first plausible hypothesis is rarely the root cause. Before designing a
diagnostic, write down at least two or three plausible explanations for the
observed failure and rank them by likelihood given the evidence. Pick the
cheapest discriminating experiment - one whose result will rule out at least
one hypothesis no matter which way it goes. Iterate.

If you find yourself patching three different symptoms of "the same"
failure, stop. Your model is wrong. Revisit the evidence from scratch
instead of stacking more patches.

### Bisect what changed

If the job recently started failing, the answer is almost always in what
changed. Look at `git log` for the relevant source files, look at the diff
between the last green run and this red run (commit list, dependency
versions, base image digests, cached artifacts). A delta in the environment
(a new base image, a freshly released dependency, a regenerated lockfile) is
just as common a cause as a delta in the source.

### Apply and verify end-to-end before reporting

A "candidate fix" is a fix only after the **exact failing command** has run
to completion with the exact success criteria the workflow uses
(`wxc-exec.exe` exits with code 0 AND its output contains `child started`).
A diagnostic
snippet that exercises only the suspect code path proves only that snippet
works; it does NOT prove the full job passes. Do NOT write the final
diagnosis until this end-to-end gate has been passed.

### Iterate until proven

Your session budget is approximately 120 minutes; use
all of it if needed. A failed end-to-end verification is **information, not
defeat**: refine the hypothesis, refine the fix, re-apply, re-run. Stopping
at "diagnosis without verified fix" is, from the perspective of the
workflow that triggered this session, equivalent to no fix at all - the
human will have to manually re-run, re-attach, re-debug, paying the full
context-switch cost again.

The explicit anti-goal is "I think it's probably X, here's a patch, you
should try it." Do not produce that. Apply the patch yourself, run the
failing command yourself, and only report once it is green.

### State-may-still-be-settling pattern

In CI environments, observable state is frequently eventually-consistent:
a process has started but is not yet listening; a window has appeared but
has not yet been laid out; a file has been created but is still being
written; a service is "ready" by one check but not by another. Treat
"thing X exists" as the START of a polling loop, not the end of one.
Sample the property you actually depend on (port responsive, file size
stable, window geometry stable, HTTP 200) until it stabilises across
several consecutive samples OR a timeout fires. If a click, write, or
read lands at the wrong moment, the cause is almost always missing
settle-time on the target state, not the action code itself.

### Subprocess hygiene (non-negotiable on CI)

Every subprocess you launch from your diagnostic helpers MUST:

1. Capture both stdout AND stderr to a file inside the working directory
   (`2>&1 | tee <name>.log`, `> <name>.log 2>&1`, `Tee-Object`, etc.). If
   you redirect into a pipeline, the `tee` MUST be the first stage so the
   raw output is preserved even if your filter is wrong.
2. Have an explicit timeout (`timeout`, `Start-Process -Wait` with a job
   timeout, language-level deadline). A subprocess with no timeout that
   hangs will burn the rest of your session budget silently.
3. Redirect stdin from `/dev/null` (or `$null` in PowerShell) for any
   non-interactive command. A subprocess waiting on stdin that you forgot
   about looks exactly like a subprocess doing slow work.
4. On a **headless runner** (no interactive desktop session), be especially
   suspicious of GUI prompts: native error dialogs, "Allow this app?"
   prompts, save-changes confirmations, OS first-run dialogs. They are
   invisible but they block the process forever. If a helper produces no
   output for an unexpectedly long time, **check for invisible dialogs
   BEFORE concluding the helper has a bug** (list windows with the
   platform's window-enumeration API, check for child processes of the
   helper).

### Surgical edits only

You are fixing a specific failure, not refactoring the code base. Make the
smallest change that makes the test pass. Do not rename, reformat, or
"improve" surrounding code. The human reviewer will be reading your diff
under time pressure; every unrelated change is a reason for them to bounce
the patch.

### Do not commit, do not push

Apply changes directly to the working tree so you can run the failing
command against them, but do NOT `git commit` and do NOT `git push`. The
human will review the diagnosis file (which contains your verified diff)
and commit themselves. Committing or pushing from inside the CI session
risks polluting the branch with intermediate, unverified state and may
re-trigger the workflow in confusing ways.

### Authentication and secrets

The CI environment has access to the secrets the workflow was granted, and
no more. If a fix appears to require a secret the workflow does not have
(a personal access token, a signing key, an account login), that is a hard
boundary: document it in the diagnosis and propose an alternative
(stub/mock the operation, skip the step on this branch, ask the human to
add the secret). Do NOT exfiltrate any secret value you can see into the
diagnosis file, chat, or commit messages.

## Your task

The `Run Bash and a forked child inside an MXC process container` step
failed: either `wxc-exec.exe` exited non-zero or its output lacks `child
started`. The earlier setup steps succeeded; the failure is in
`msys-2.0.dll`'s `fork()` implementation (or its process startup) running
inside an MXC process container, unless the evidence shows the container
itself cannot start on this runner.

Diagnose the **root cause**. Do not guess. Verify your diagnosis by running
a targeted experiment before declaring it correct. Then apply a fix and
verify end-to-end by re-running the exact failing command in the exact way
the workflow invokes it.

### Step 1: Read the failure log

Look at `mxc/output.log` (the captured output of `wxc-exec.exe`, i.e. of
Bash inside the container), `mxc/diagnostics.log` (MXC's own log),
`mxc/policy.json`, and the step definitions in
`.github/workflows/mxc-fork.yml`. Find the LAST line that
indicates forward progress (a successful test, a completed phase, a
function-entry log). The failure happened immediately AFTER that point.
Note the exact timestamp of the last good line and the timestamp of the
step's exit / timeout, so you know how long the process was stuck or how
quickly it crashed.

If there are multiple log streams (stdout, stderr, application logs,
system logs), read them all and merge by timestamp - the most informative
line is often not in the stream you looked at first.

### Step 2: Locate the failure site in source

`grep` for the last log message text in the source tree to find which line
emitted it. Read the source from that line forward, following the control
flow. The failure is somewhere in the code that runs AFTER the last
logged event and BEFORE the next event that never fired. Map every
external interaction (subprocess, network call, file I/O, GUI action) in
that span; any one of them is a candidate hang or exception site.

Also check `git log -L<start>,<end>:<path>` for that span to see when the
suspect lines last changed, and whether the change correlates with when
the job started failing.

### Step 3: Hypothesize the cause

Write down at least two or three plausible hypotheses. For each, write:

- The predicted symptom (what you'd expect to see in logs / file system /
  process list if this hypothesis were true).
- The cheapest experiment that would discriminate this hypothesis from
  the others.

Common CI failure patterns to consider, beyond the obvious code bug:

- **Stale or wrong artifact under test.** The fix exists in source but the
  binary / package / image being tested was built before the fix or from
  the wrong ref. Verify the artifact contains the change you expect (file
  timestamps, embedded version strings, strings/symbols in the binary).
- **Eventual consistency / settle-time bug.** Something that worked
  locally fails in CI because CI is faster or slower than your dev box.
  See "State-may-still-be-settling pattern" above.
- **Invisible modal / dialog / prompt on a headless runner.** Especially
  for GUI tests, OS first-run experiences, package-installer prompts.
- **Subprocess hang with no output.** Missing stdout consumer, missing
  timeout, waiting on stdin, blocked on a GUI dialog.
- **Resource exhaustion.** Disk full, port already in use, file handle
  leak, memory limit, runner clock skew.
- **Environment delta.** New base image, new compiler default, new
  dependency version, new OS update on the runner pool.
- **Authentication or rate-limit failure.** A token expired, a quota was
  hit, a service the test depends on is down or throttling.
- **Test infrastructure bug, not product bug.** The thing the test does
  to set up or tear down state is itself broken.

### Step 4: Verify the hypothesis (cheap, isolated)

Write a SMALL standalone reproducer under
`ci-diagnosis/diagnose-<topic>.<ext>` that exercises ONLY the
suspect code path. It must:

- Log every step it takes to a dedicated log file inside the working
  directory.
- Wrap each operation in error-handling that LOGS the exception rather
  than silently aborting.
- Honour the subprocess-hygiene rules above (captured stdout+stderr,
  explicit timeout, stdin from null where applicable).

Run it via the same shell and the same environment the failing step
used. If a helper produces no output despite the script being correct,
**check first** for the headless-runner failure modes (invisible dialogs,
missing pipe consumer, argument mangling by an MSYS2/Cygwin/WSL shell
converting flags into paths) before concluding the reproducer is buggy.

The reproducer's job is to **rule a hypothesis in or out**, not to fix
anything. Resist the temptation to skip to a fix at this stage.

### Step 5: Apply the fix and verify it end-to-end

Apply your proposed fix DIRECTLY to the source files in the working tree.
The runner workspace is ephemeral, so editing files here cannot
contaminate anything; you will write the final verified diff into the
diagnosis file after Step 6.

Then re-run the FULL failing command exactly as the workflow does, from
the same working directory, with the same environment variables. The
canonical invocation is (PowerShell, after rebuilding and refreshing the
DLL as described under "Tools and commands specific to this job"; `<N>`
numbers the attempt so earlier logs are kept):

```
cd mxc
.\node_modules\@microsoft\mxc-sdk\bin\x64\wxc-exec.exe --log-file ..\ci-diagnosis\diagnostics-<N>.log policy.json 2>&1 | Tee-Object ..\ci-diagnosis\output-<N>.log
$LASTEXITCODE
```

Capture its output into `ci-diagnosis/output-<N>.log` (using `tee` so the
full output is preserved even while you watch it).

The fix is verified ONLY if ALL of these hold:

1. `wxc-exec.exe` exits with code 0.
2. The verification log contains `bash started`, the `uname -a` and `id`
   output lines, and `child started`, each exactly once.
3. The verification log contains no `dofork`, `died unexpectedly`,
   `copy failed`, or `fork: retry` lines, and no NEW errors or warnings
   that were not present in the original failing run.
4. The control run outside the container still prints `child started`.

If ANY criterion fails: refine the hypothesis, refine the fix, re-apply,
re-run. Use your session budget. Do NOT report a fix you have not actually
verified end-to-end with the real failing command - a passing diagnostic
snippet is NOT sufficient evidence of a working fix.

If after several iterations you are clearly making the test fail in NEW
ways (chasing a moving target rather than converging), stop applying
patches and re-read the original log from Step 1 with fresh eyes. The
original symptom is your ground truth; any patch that introduces a new
symptom is suspect.

### Step 6: Record the verified fix

Only after Step 5 is fully green, write to `copilot-diagnosis.md`:

1. **The exact root cause**: file:line, with the line of code that
   hangs / throws / produces the wrong output.
2. **The evidence**: the last log line from the original failing run,
   what the source says runs next, what your Step-4 diagnostic confirmed,
   and the matching success lines from the Step-5 verification run.
3. **The fix**: a unified diff (`git diff` format) of the changes you
   applied. Keep it minimal and surgical; do not include refactors or
   unrelated tidy-ups. Explicitly do NOT commit; the human will review
   the diagnosis and commit themselves.
4. **The verification excerpt**: paste the relevant lines from the
   verification log inline (the command, the start banner, the per-phase
   / per-test completion lines, the final exit status) so the human
   reviewer can confirm end-to-end success without chasing artifacts.
5. **Alternatives considered and rejected**: brief notes on the other
   hypotheses from Step 3 and what evidence ruled them out. This helps
   the reviewer trust that the fix is the right one, not just the first
   thing that worked.
6. **Residual risks**: anything you noticed that might be a related but
   separate bug, anything that worked but smells wrong, anything that
   relies on assumptions you could not fully verify in this session.

### Step 7 (only if Step 5 cannot be made green)

If you genuinely exhaust the session budget without an end-to-end-verified
fix, still write `copilot-diagnosis.md` with everything you learned:

- The most-likely root cause and the evidence that points to it.
- Every hypothesis you tried and the evidence that ruled it out.
- Every fix you tried, the diff, and the exact way it failed (with log
  excerpts).
- The cheapest experiment a human or the next Copilot session should run
  next, and why.
- Any new diagnostic helpers you wrote that should be preserved
  (location, how to invoke them).

Failing forward like this is much more valuable to the human than a
silent timeout. The next session - whether human-driven or another
Copilot run - starts from your notes instead of from scratch.

## Common gotchas to keep in mind

- **Truncation.** Tool APIs (`get_job_logs`, GitHub MCP `get_diff`, etc.)
  often truncate. Always fetch the raw artifact / raw diff when you suspect
  the truncated portion matters.
- **Wrong binary tested.** When changing core code that should trigger a
  large rebuild, but the build completes in seconds, the build did not
  pick up your changes. Verify artifact timestamps / embedded hashes.
- **Workflow-vs-shell parity.** The workflow may invoke your failing
  command via a wrapper script, a shell different from the one you're
  in (bash vs PowerShell vs cmd), or with a different working directory
  or PATH. Reproduce in the exact same conditions or your verification
  is not a verification.
- **Cached state.** A previous step may have cached an artifact or
  package set that does not match what a fresh checkout would produce.
  When in doubt, check the cache-restore step's log to see what was
  restored.
- **Clock and locale.** CI runners may have a UTC clock, an unexpected
  locale, an unusual timezone, or wall-clock skew. Tests that compare
  timestamps, parse dates, or format numbers are sensitive to this.
- **Path conversion in cross-shell environments.** MSYS2 / Cygwin / Git
  Bash will translate arguments that look like Unix paths (`/Flag`) into
  Windows paths before passing them to native binaries. Set
  `MSYS2_ARG_CONV_EXCL='*'` or quote with care.

## Why all of this

The expensive resource here is the human operator's attention, not CI
minutes and not Copilot tokens. Each time the operator has to:

- notice the failure,
- re-trigger the workflow,
- wait for it to reach the tmate / upterm step,
- attach,
- re-load context,
- re-prompt a fresh Copilot,

they pay tens of minutes of focused attention they could be spending on
something else. The session you are in right now exists specifically to
avoid forcing them to do that again. Use the budget. Verify the fix.
Write the diagnosis so they can review it asynchronously without
re-attaching.
