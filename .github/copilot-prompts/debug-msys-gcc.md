# Investigate counter-fix verification on msys2/msys2-runtime#375

## Context

You are running in the `debug-msys-gcc` job on a GitHub Actions
`windows-2025` runner. The `Run CMake and investigate with the live watcher` step
runs up to twenty bounded full CMake targets after the original toolchain, rust,
and python prerequisites. Copilot runs ONLY if verification failed: a counter
probe, public-API regression, full target, or watcher check failed. Determine
which gate actually failed; do not assume a CMake hang was reproduced.

The installed runtime is built from this checkout in the prerequisite `build`
job. Its correction saves the incoming unsigned `incyg` in
`_cygtls::call_signal_handler()` and restores it after the user handler instead
of restoring the constant 1. The earlier DLL-base experiment was reverted in
source; both control and candidate use preferred base 0x180040000.
The original runtime artifact from successful msys2/msys2-runtime run
37015007624 (revision 0eed0a44c3b8366ea17b2f0ddca0c2d0eeb429a7) is supplied
under `ci-diagnostics/control-runtime` for isolated control probes. It is NOT
installed over the candidate. The original CMake 4.4.3 package is restored.
Verify the executed versions, loaded DLLs, test SHA, and package inventory
rather than assuming setup succeeded.

The original failing PR run was 37015007624, job 110867718574. Its tests
stopped printing output at 2026-10-02 13:59:53 UTC on
`-- Detecting C compiler ABI info` while configuring
`i686-w64-mingw32` with CMake's Unix Makefiles generator. The job was
cancelled nearly six hours later. At the SAME source commit, push run
37014998883/job/110867726701 passed the whole job in 4m23s and the CMake
phase in 14 seconds. An independent msys2/msys2-tests scheduled run,
37110665545/job/111167793137, also stopped at that ABI detection (but
do not assume these failures have the same underlying cause).

Working directory: the checked-out msys2-runtime repository at
`$GITHUB_WORKSPACE`. The test source repository is checked out at
`$GITHUB_WORKSPACE/msys2-tests`, pinned to
msys2/msys2-tests@a5a6995b100ef2b09cd96b4c6262a573840b3af9.
Its committed blobs are archived into the original action directory
`_actions/msys2/msys2-tests/main`, recorded in `MSYS2_TESTS` and
`provenance.log`. The archive explicitly disables native Git's autocrlf
conversion: run 37275179103 proved that archiving alone still converted
the payload to CRLF. Verify bytes against committed blobs, not just the SHA.
The reproducer sources that directory's `group_helper.sh` and invokes
`make -C "$tests" -j cmake` through the original `msys2 {0}` wrapper with `MSYSTEM=MSYS`,
`CC=gcc`, `CXX=g++`, and `FC=gfortran`. Its CMake test script loops over
Ninja and Unix Makefiles, building native and MinGW cross-compiled samples.
Like the original runner, native stdin is a closed pipe and stdout/stderr
are separate pipes, drained asynchronously to `cmake-N.log` and
`cmake-N.stderr.log`. The command script and per-attempt native process
records are preserved. Previous focused runs used a separate test path,
direct file redirection, and omitted the group helper; do not claim those
execution contexts were identical.
The first fork diagnostic run passed this CMake target in 24 seconds, then
failed in a different `runtime` symlink test. Do not investigate that
later failure here.

## Proven defect and current regression gates

Fork run 37372647021 captured an actual, separately labelled
DEBUGGER-PERTURBED CMake/libuv `posix_spawn` SIGCHLD lifecycle:
incoming count 2 -> constant restore 1 -> stabilization 0 -> SIGBE
0xffffffff. The trace required the SAME handler restore, thread, TLS and
RSP before counting later stages; all six applicable validity bits were set.
After explicit detach, the same CMake process stalled in poll/select, and a
native read BEFORE GDB found count 0. Natural unchanged full-target stalls
independently had count 0 and queued, unblocked SIGCHLD. The normal controlled
wakeup path requires nonzero `incyg`. Do not repeat the already-completed
search for the first causal transition.

Takashi Yano proposed this exact original-count preservation on 2025-05-28:
https://inbox.sourceware.org/cygwin-patches/20250528125311.2589-1-takashi.yano@nifty.ne.jp/
The landed revision omitted that part. The checkout applies the missing
save/restore, not a new signal-hold or address-layout theory.

Start with `ci-diagnostics/counter-probes/results.json` and its raw
stdout/stderr. The same compiled executables run beside isolated original
and corrected DLL copies. Quiet probes record the ACTUAL loaded DLL path,
base, hash and version. Each process has closed stdin, separate native pipes,
a 45-second deadline and a separate drain check.

The debugger-free `once-probe` records counts in memory with QPC and flushes
afterward. Its initializer handles `raise(SIGUSR1)` inside `pthread_once`.
Predictions:

- Both quiet controls: before 0, initializer entry 1, initializer after 1,
  outside 0.
- Original handled-signal control: before 0, initializer entry 1, handler 0,
  initializer after 0, outside 0xffffffff.
- Corrected handled-signal probe: before 0, initializer entry 1, handler 0,
  initializer after 1, outside 0.

`once1` is the existing ordinary pthread_once test; both DLLs must pass it.
`once2` is the new public-API regression: normal and nested handlers,
including a signal in a pthread_once initializer, must not prevent SIGALRM
from promptly interrupting a finite poll with EINTR. It also exercises an
alternate handler stack and asynchronous delivery outside runtime calls.
The original DLL's specific poll failure is an
EXPECTED control result, not a new CI failure; the corrected DLL must pass.
Do not mistake a missing DLL, compiler failure, timeout, or unrelated
assertion for the expected original regression.

If a probe disagrees with its prediction, investigate the actual installed
and loaded DLL, compiler/header/layout and error evidence before proposing
another source change. In particular, the private-offset probe is not a
substitute for the public regression or the unchanged full CMake target.

## Live failure capture

The native Node watcher `.github/copilot-prompts/watch-cmake.cjs` is already
started in the SAME owning PowerShell step as this Copilot session. The
owner stays alive until analysis finishes: a previous run's watcher
disappeared between steps without an error record, consistent with the
runner's descendant cleanup on shell exit. Verify current watcher liveness
and its saved records; do not assume readiness proves continued operation.
It scopes processes to
`$MSYS2_ROOT/usr/bin/cmake.exe` created after watcher startup. After the same
process has survived 45 seconds and the full-target logs have made no progress
for 45 seconds, it saves `hang-PID.json`, the native process inventory, and
`hang-PID-debugger.log`. CDB, if available at the SDK path, captures modules
and all thread stacks noninvasively, then explicitly detaches. Run 37275179103
verified that this SDK rejects `-pd` even with exit 0 and treats bare `no`
after `-netsyms` as an executable. `-netsyms` is a standalone switch.
The watcher now requires actual runtime-module and stack output, not just
exit 0. `!address` failed without ntdll symbols; obtain shared mappings
through typed runtime state or read-only VirtualQueryEx instead. CDB's
export-symbol labels are not runtime DWARF frames. If CDB is absent, the
installed MSYS GDB captures modules, all stacks and loaded sections, then
detaches. Read `watcher-ready.json` and every capture/exit/error record:
an exit code alone does not prove valid stacks or symbols were obtained.
The 120-second native target deadline leaves the stalled process alive.
Do not kill it, its parent, or any other process.

If all initial targets passed and there was no natural watcher capture,
the owner then runs `cmake -E sleep 90` solely to exercise the native
debugger. `watcher-smoke/command.json` identifies this SYNTHETIC PID;
its result and debugger evidence are saved under `watcher-smoke/`.
If the smoke check failed, its PID's partial capture may still be in the
top-level directory. This is NOT a reproduced CMake ABI hang or a runtime
fix. Inspect its actual stack/module output to establish whether the
backend works; a failed smoke check does not warrant another hang search.
The smoke check occurs after initial targets, so it cannot explain their
outcomes. Do not stop, restart, or replace the still-live main watcher.
If all full targets passed and only this smoke check failed, diagnose the
capture backend, not an invented CMake ABI hang.

If a full target stalled, start with THIS stall and its stack/module
evidence. Preserve the raw capture before changing settings or rerunning.
If the debugger is still running, inspect its preserved output and status
before attaching another debugger. The watcher does not kill a debugger
that exceeds its 30-second observation deadline. Never use broad taskkill,
Stop-Process, pkill, or killall. A missing/failed capture is an infrastructure
problem to resolve explicitly, not proof that no process or hang exists.

If tracing is needed, reuse the durable native controller rather than
recreating its already-fixed argument, expression and buffering bugs.
The workflow downloads artifact 11359045945 from
dscho/msys2-runtime/run 37336886615 into `ci-diagnostics/prior-control`
BEFORE starting this session. Its top-level diagnostic sources include
`trace-controller.ps1`, `native-diagnostics.ps1`, `trace-controls.ps1`,
`trace-configures.ps1`, wrapper scripts and `once-probe.c`. Read those
sources directly; do not recursively inspect its historical build trees
or download it again. Run 37364304285 lost time because the CLI's tools
had no GH_TOKEN despite the owning step having it. Do not search checkout
credentials or session history to retrieve sources already provided here.
If this download failed, record the missing files and workflow error.
Preserve the originals before deriving a new trace. The v3
controller verified signal/no-signal probes AND normal-exit/quiet CMake
controls, using `-G`, CDB-owned `-logo`, retained stdin, canonical identities
and error-safe `finally` records. Its fixed RVAs and instruction guards are
for the ORIGINAL DLL ONLY. Resolve the corrected DLL's actual DWARF and
instructions before adapting a trace; this source change moves code.
Do not blindly reuse an original before-clear, constant-restore,
stabilization or SIGBE address against the rebuilt candidate.

Before invasive GDB attachment, take a native counter snapshot of a current
natural stall. Verify thread identity, loaded binary and actual layout
before interpreting it. Do not treat a failed expression, zero debugger
exit, or uninitialized zero buffer as a counter observation.

CDB previously truncated a 6101-character startup command to 4095
characters. Avoid this measured input-length failure before launch.
Use CDB's documented `-cf` startup file with separate bounded command
lines, not one long `-c` string or a script reader that joins its lines:
https://learn.microsoft.com/en-us/windows-hardware/drivers/debugger/cdb-command-line-options.
Write the ASCII startup file before tracing. Keep the instruction guard
on its own line, with an explicit bad-instruction detach/quit branch;
then initialize buffers, define each breakpoint on a separate line, list
them, emit TRACE_SETUP and continue. Do not enclose the whole setup in
one multiline conditional. Measure EVERY actual CDB input line, including
breakpoint command strings and deadline commands, and refuse to launch if
any reaches 4095 characters. Preserve the startup file and line lengths.
Revalidate the signal/no-signal lifecycle pair first: TRACE_SETUP and real
buffered transitions are required, not debugger exit 0 or all-zero buffers.
If a control fails, repair that exact failure before CMake; do not repeat
established provenance/pipe/layout dumps in place of this experiment.

If current evidence warrants another lifecycle trace, use a bounded one-shot
trace, not an all-write GDB watch. Save the selected thread, TLS and handler
RSP; do not count handler-internal API returns as post-handler transitions.
For the corrected DLL predict incoming 2 -> restored 2 -> stabilization 1
-> SIGBE 0. Record deviations rather than forcing that model. Buffer samples
in debugger memory and flush on completion or an independent host deadline.
Validate real applicable transitions on the synthetic signal/no-signal pair
before using it for a separately labelled DEBUGGER-PERTURBED CMake configure.

Preserve commands, phase records and errors before returning, including
incomplete drains from a still-live detached target. Queue capture/detach
commands before requesting a native break; verify fresh identities and
never terminate a target. The original natural stalled process, if any,
must stay untouched. Do not repeat established pipe/layout inspections in
place of investigating the current failed verification gate.
No per-event file I/O is permitted. Label these runs DEBUGGER-PERTURBED
and separate them from unchanged full-target results. Do not call inferior
functions or modify runtime variables, and detach before quitting a live
inferior. A filter that never fires is not evidence that no bug occurred.

**All files you create for the operator (scripts, logs, diffs, diagnostics)
MUST go inside `$GITHUB_WORKSPACE/ci-diagnostics/`.** Inspect files under
`msys2-tests` and the installed runtime as necessary, but copy relevant
existing CMake logs into `ci-diagnostics/` BEFORE rerunning a test that
overwrites its build directory. The workflow uploads that directory even
when Copilot exits nonzero; the CLI's full stdout and stderr stream into
`ci-diagnostics/copilot.log`, with readable diagnosis checkpoints also
streamed into `ci-diagnostics/copilot-readable.log` and the CI job log.
Do not copy tokens, credentials, environment dumps containing secrets, or
the entire `~/.copilot` directory into artifacts.

Your findings MUST be written to
`$GITHUB_WORKSPACE/ci-diagnostics/copilot-diagnosis.md`. It already contains
a brief seed note. Replace it immediately with the observed CMake attempt
statuses and the exact last progress line if one hung; then update it
**after each meaningful observation or experiment, not only at the end**.
An interrupted session or a late `exit 1` must never erase the analysis
already completed.
If a late error occurs, record its exact command, exit status, and output
and continue writing the diagnosis when possible. Do not use an unconditional
`exit 1` as the last action of a diagnostic helper. Do NOT mark a fix as
verified merely because a targeted reproducer passed.

## Operating principles (mandatory)

### Verify, do not guess

Every factual claim you make - whether in the diagnosis, in chat, or in the
proposed fix - must be backed by concrete evidence: a log line you just read,
a source line you just opened, the output of a diagnostic script you just
ran, the output of `git log` / `git blame` showing when something changed.
"It looks like X" is not a diagnosis; "I ran Y at step Z, output was W, here
are the relevant lines" is. If you cannot verify a claim, abandon it. Never
hallucinate. The old PR logs are clues, not proof that THIS run failed at the
same point: check what actually happened here first.

### Predict before you test

Before running any diagnostic or applying any fix, state in chat **what you
expect to observe and why**. If the actual result diverges from the
prediction, your mental model is wrong: investigate the divergence. Do NOT
patch the next visible symptom. Do NOT call unexpected behaviour "normal",
"an edge case", or "a test artifact" until you can explain its exact
mechanism.

### List multiple hypotheses, then rank

The nesting defect is already proven. Rank explanations for THIS failed
verification gate, not alternative theories for the established defect.
Before designing a diagnostic, write down the plausible explanations and
rank them by likelihood given the evidence. Pick the
cheapest discriminating experiment - one whose result will rule out at least
one hypothesis no matter which way it goes. Iterate. Compare the actual
package versions, artifact SHA, and runner image of the working and failing
runs before attributing the failure to msys2-runtime source.

### Bisect what changed

If the job recently started failing, the answer is almost always in what
changed. Look at `git log` for the relevant source files, look at the diff
between the last green run and this red run (commit list, dependency
versions, base image digests, cached artifacts). A delta in the environment
(a new base image, a freshly released dependency, a regenerated lockfile) is
just as common a cause as a delta in the source.

### Apply and verify end-to-end before reporting a fix

A "candidate fix" is a fix only after the **exact failing command** has run
to completion with the exact success criteria for the CMake target: exit
code 0, all native and cross-compiled generator tests complete, and repeated
attempts do not hang. A diagnostic snippet exercises only the suspect code
path; it does NOT prove the full CMake target passes. Do NOT report an
unverified candidate as a fix. The full composite test suite is NOT the
verification gate here: it failed later in an unrelated `runtime` symlink
test on the previous fork run. Do not chase that failure or let it obscure
the CMake hang. Distinguish the measured counter correction from the number
of passing full targets; passing candidate attempts are not reproductions
of the original unchanged-DLL hang.

### Iterate until proven

Your session budget is approximately 23 minutes. Reserve at least five
minutes for final documentation and copying any patch and logs into
`ci-diagnostics/`; finish the diagnosis before 22 minutes have elapsed.
A failed end-to-end verification is **information, not defeat**: refine
the hypothesis, refine the fix, re-apply, re-run. Do not
spend the whole session waiting on a hung child: give each subprocess a
reasonable timeout, capture its output, and inspect its process tree while
it is still hung. Preserve the original build/log evidence before any test
script removes or overwrites its own build directory. If all full targets
passed, investigate the actual failed regression or watcher gate rather
than starting another unneeded configure search.
Preserve any natural full-target wait for live inspection. Do not delete
build directories, clean-build, or install extra tools just to retry.

### Subprocess hygiene (non-negotiable on CI)

Every subprocess you launch from diagnostic helpers MUST:

1. Capture both stdout AND stderr to a file inside `ci-diagnostics/`.
   If you use a pipeline, `tee` must be its first stage; keep the raw
   output even when the command exits nonzero. Note the exit code and
   duration without dropping earlier output.
2. Have an explicit timeout, well inside the remaining session budget.
3. Redirect stdin from `/dev/null` (or `$null` in PowerShell) when the
   command is non-interactive.
4. If it unexpectedly goes quiet, inspect the preserved log and the live
   native Windows and MSYS2 process trees while it is STILL stuck. On a
   headless runner, investigate invisible dialogs and blocked pipes.
   Never kill the runner shell or another unrelated process.

Do not rely on MSYS `timeout` to release a native CMake process or an output
pipeline; that channel failed in earlier sessions. Use a native PowerShell
wait and independent native pipe drains to files, leaving a timed-out target
alive for inspection. Preserve both stdout and stderr. A recorded
`output-timeout` means the native parent exited but its output pipes did not
close; it is not automatically a CMake ABI stall.
For further full-target attempts use `ci-diagnostics/cmake-N.log` with fresh
numeric N values so the background watcher can observe forward progress.
After every complete attempt require exit0 and exactly eight lines matching
`^100% tests passed out of 1$`. Do not assume the older CTest summary format.

When invoking native Windows programs through MSYS2 or Git Bash, watch for
argument/path mangling; use the actual `msys2 {0}` shell or its wrapper for
the reproducer. Use PowerShell for independent Windows process inspection.
Keep source/build/package/runtime provenance separate; a passing snippet
against a different `msys-2.0.dll` is not a verification of this run.

### Surgical edits only; do not commit or push

You are investigating a specific CI hang, not refactoring either project.
Change only what a discriminating experiment and the evidence warrant. The
msys2-tests source is in a separate checkout under `msys2-tests`: if a
test-side change is necessary, save its unified diff under `ci-diagnostics/`
BEFORE the runner is reaped. If runtime source must change, save that diff
too, then verify that it was actually rebuilt, installed, and loaded before
claiming a runtime fix. Apply and test an existing upstream fix for this
same hang before inventing an alternative. Do NOT commit, push, publish,
or upload anything besides the configured diagnostic artifact.

## Investigation and output

1. **Read the CMake attempt logs first.** Use
   `ci-diagnostics/cmake-attempts.log` and `cmake-N.log` to record each
   `cmake-results.csv`, attempt statuses, the last forward-progress line if
   any hung, and the exact command. Read the watcher stack/module records.
   If all initial attempts passed, label the initial hang
   NOT REPRODUCED in this runner; identify the actually failed regression
   or watcher gate. Do not waste the session retrying unavailable GitHub
   CLI authentication or fetching
   multi-megabyte historical logs: the earlier session's tool processes
   could not access `GH_TOKEN` and its run log was truncated. Verify
   which runtime DLL was installed and which test SHA ran. Copy relevant
   CMake build records to `ci-diagnostics/` before another attempt.
2. **Trace the stalled operation.** Follow the pinned `cmake/test.sh`,
   CMake's `try_compile`/ABI detection logs, invoked compiler/linker
   subprocesses, and any MSYS2/Windows process-wait code implicated by
   the evidence. Compare the previous passing run and independent test
   run. Rank at least two plausible causes and select the cheapest
   experiment that distinguishes them; update the diagnosis BEFORE
   starting it.
3. **Run a bounded reproducer.** In the same `MSYSTEM=MSYS` environment,
   rerun the CMake target or a narrower test of the exact stalled
   compiler command with a native deadline; capture full stdout/stderr and
   inspect the live process tree while it is stuck. First inspect the
   original live full-target PID: all thread stacks, ACTUAL DLL/module and
   shared mapping addresses, selected fds/pipe roles, fd0-2/ctty, and pending
   signal state. Use small read-only GDB commands for DWARF types if CDB has
   only export symbols. Do not execute functions in the inferior. A previous
   extended debugger script crashed; do not blindly reuse it. Take another
   bounded stack snapshot to distinguish a persistent wait from sampling.
   Do not replace a full-target stall with an unlabelled narrowed experiment.
   Write the prediction, command, exit code, evidence, and implications
   immediately.
   Unexpectedly quick runs or a failing known-good baseline require
   checking artifact timestamps, DLL versions, and executed binaries,
   not a speculative source patch.
4. **Fix and verify only if justified.** Apply a minimal change in the
   right source tree, preserve its unified diff in `ci-diagnostics/`,
   and rerun the exact failing CMake target under the actual test shell.
   Require completion of every generator/native/cross-compiled CMake
   test and repeat the target to check the intermittent hang. Respect
   explicit subprocess deadlines, capture full logs, and record the
   commands, timestamps, statuses, and excerpts in the diagnosis.
   Do not mistake a fix for the unrelated `runtime` test failure for
   a fix for this CMake hang.
5. **Leave a usable artifact even if nothing is green.** Keep
   `copilot-diagnosis.md` current with supported findings, ruled-out
   hypotheses, each attempted change and its diff/status, residual
   uncertainty, and the cheapest next experiment. If no end-to-end
   verification succeeds, label every candidate UNVERIFIED. Near the
   session deadline, finish and flush the diagnosis rather than starting
   another experiment. Errors and nonzero statuses should be visible
   alongside the preserved analysis, never replace it.
