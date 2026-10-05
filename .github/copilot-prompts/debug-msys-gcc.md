# Diagnose the MSYS-gcc timeout on msys2/msys2-runtime#375

## Context

You are running in the `debug-msys-gcc` job on a GitHub Actions
`windows-2025` runner. The `Run CMake and investigate with the live watcher` step
runs up to twenty bounded full CMake targets after the original toolchain, rust,
and python prerequisites. It may have timed out, failed, or passed every
attempt. Determine which happened; do not assume a hang was reproduced.
The workflow installs MSYS2, enables the staging repository, and unpacks
the `install` artifact from the successful
msys2/msys2-runtime run 37015007624 (runtime 0eed0a44c3b8366ea17b2f0ddca0c2d0eeb429a7).
The workflow restores the original CMake 4.4.3 package. Verify the executed
version, loaded DLL, test SHA, and package inventory rather than assuming
that setup succeeded. The checkout's one-line DLL-base candidate is NOT
installed: this session investigates the original control artifact.
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

## Live capture and previous evidence

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
fix. Briefly inspect its actual stack/module output to establish whether
the backend works, then prioritize the original full-target search.
The smoke check occurs after initial targets, so it cannot explain their
outcomes. Do not stop, restart, or replace the still-live main watcher.

Start with THIS full-target stall and its stack/module evidence. Preserve
the original raw capture before changing debugger settings or rerunning.
If the debugger is still running, inspect its preserved output and status
before attaching another debugger. The watcher does not kill a debugger
that exceeds its 30-second observation deadline. Never use broad taskkill,
Stop-Process, pkill, or killall. A missing/failed capture is an infrastructure
problem to resolve explicitly, not proof that no process or hang exists.

Fork run 37275179103 reproduced a NATURAL full-target UCRT/Ninja ABI-start
stall with the original control DLL and CMake 4.4.3. Attempts 1-16 and 18
each passed all eight tests; attempt 17 reached one CTest success before
its native deadline. Its PID 8768 is HISTORICAL: that runner has finished.
Do not reuse its PID or addresses as live observations. Recovered typed
snapshots showed main `incyg=0`, `current_sig=0`, an unblocked SIGCHLD
(20/CLD_EXITED 28) queued, and an indefinite `poll/select` wait. The selected
fd6/fd8 were measured as libuv's signal/async pipes, not child output.
The actual SIGFE increment address matched DWARF exactly; a simple TLS
offset mismatch does not explain that capture. The initiating event is
STILL UNPROVED, and the original i686/Unix Makefiles failure has not
specifically been reproduced.

Prioritize the FIRST bad incyg transition over another large configure
search. Before invasive GDB attachment, take a native noninvasive counter
snapshot if a current natural stall exists. For the exact control artifact
0eed0a44 (SHA256 cfc995e7946b292debf42ec2b296ee9f4658289f653f7ceb8d9cae18da6d04ad),
`incyg` is at main StackBase minus 0x1d6c, independently verified against
DWARF and actual stub instructions. A CDB read-only probe can select the
main thread and examine `dd poi(@$teb+0x8)-0x1d6c L2`; verify its actual
output, thread identity and loaded binary before interpreting the values.
Do not treat a failed expression or zero debugger exit as a counter value.

Trace nesting through `scripts/gendef`, `exceptions.cc`, `thread.cc`,
`fork.cc`, `sigproc.cc` and the ACTUAL loaded libuv spawn path.
SIGFE increments and SIGBE decrements a count, but `call_signal_handler`
restores the constant 1. A cheap SYNTHETIC probe is a handled
`raise(SIGUSR1)` inside a `pthread_once` initializer: measure the counter
before/inside/after it using the validated layout, without a debugger.
Predict the values first; a nesting defect here is not yet proof of the
natural CMake initiating event. Record samples in memory with QPC timestamps
and flush after the probe, never per-event file I/O.

Run 37305836013 reproduced a natural x86_64/Unix Makefiles ABI stall after
four complete passes. Corrected automatic CDB capture worked, and a separate
native read established `incyg=0` BEFORE GDB. Nine relevant action files
matched their committed blobs byte for byte. The debugger-free once probe
confirmed the predicted 0 -> 1 -> 0 -> 0xffffffff sequence; its no-signal
baseline ended at 0. These establish a real nesting bug, but not its CMake
call site.

Do NOT repeat that run's all-write GDB watch: it left an inferior and
debugger alive without flushing the in-memory ring. A deadline tested only
on the next watch event cannot expire while the target is quiet. Instead
prefer one narrowly filtered native CDB breakpoint on the FIRST nested
handler, validating it on the synthetic signal/no-signal pair before CMake.
The exact control DLL instruction at RVA 0x24029 (loaded address
0x180064029) is `movl $0,0x1494(%rax)`; RAX is this thread's TLS and the
incoming count has not yet been erased. Validate the loaded binary and
instruction bytes, then use a conditional breakpoint for unsigned count
greater than 1 but below 0x80000000 at RAX+0x1494. Microsoft documents
`bp /w` C++-style pointer/register conditions at
https://learn.microsoft.com/en-us/windows-hardware/drivers/debugger/setting-a-conditional-breakpoint.
Record the old count, signal at RAX+0x1490, registers, raw caller stack and
modules, clear breakpoints, and explicitly detach. Resolve runtime raw PCs
with the exact control DLL's DWARF; do not trust nearby export labels.

Run 37336886615 passed ALL 29 unchanged full targets. Its separately
labelled DEBUGGER-PERTURBED i686/Unix Makefiles configure DID catch signal
20 with incoming count 2 at the validated before-clear instruction.
Exact control DWARF resolved the caller as stabilization -> setjmp ->
dofork -> __posix_spawn_fork -> posix_spawn; the captured libuv PC was just
after its actual posix_spawn import call. After explicit CDB detach, that
same process stalled at CXX ABI detection. A later native read BEFORE GDB
found `incyg=0`; typed inspection found queued, unblocked SIGCHLD and an
indefinite poll/select wait. PID 2104 is HISTORICAL, not a current target.
The intervening counter transitions were NOT recorded. Do not equate this
perturbed configure with the original unchanged PR failure.

REUSE the durable v3 controller from that SUCCESSFUL run rather than
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
and error-safe `finally` records. Briefly revalidate its CMake controls
against this runner; do not spend the session rebuilding the controller.

The next discriminating experiment is a SHORT, ONE-SHOT lifecycle trace
after the first nested handler, not another immediate detach or all-write
watch. Save the selected thread and TLS in DEBUGGER pseudo-registers.
Validate actual instructions/loaded bytes before using these exact-control
RVAs: after the constant-1 restore 0x2423c; stabilization's handler return
0x16fa0b and after its decrement 0x16fa13; SIGBE before its decrement
0x16f866 and after it 0x16f86d. Restrict subsequent breakpoints to that SAME
thread/TLS, and stop after one sequence. Record the auxiliary return stack
and the SIGBE return target, not nearby export names. Buffer samples in
debugger memory and emit them only when the sequence completes or the
independent host deadline breaks and detaches. Predict whether CMake
actually follows 2 -> restored 1 -> stabilization 0 -> SIGBE 0xffffffff
before its next SIGFE-wrapped wait; record deviations rather than forcing
that model. Validate the applicable stages on the synthetic nesting probe.

Preserve commands, phase records and errors before returning, including
incomplete drains from a still-live detached target. Queue capture/detach
commands before requesting a native break; verify fresh identities and
never terminate a target. The original natural stalled process, if any,
must stay untouched. Do not repeat established pipe/layout inspections in
place of capturing these FIRST causal transitions.
No per-event file I/O is permitted. Label these runs DEBUGGER-PERTURBED
and separate them from unchanged full-target results. Do not call inferior
functions or modify runtime variables, and detach before quitting a live
inferior. A filter that never fires is not evidence that no bug occurred.
The setjmp decrement was introduced by 41e1013e6846f1774dfec085ff983990f67e6437.
Do not blame it without tracing guards: fork's __SIGHOLD sig_send already
calls the handler, and libuv 1.53.0 registers a child-only atfork callback.
Both original red and GfW green installed libuv 1.53.0-1.

Fork run 37134733906 passed **all six initial full targets**. A later,
separately labelled narrowed search passed 117 configures and captured
one natural UCRT/Ninja ABI wait. On that narrowed wait, typed GDB inspection
identified fd6 as libuv's signal pipe and fd8 as its async-wakeup pipe.
The main thread was in `poll/select_stuff::wait`; a signal thread was
sampled through `wait_sig -> process -> setup_handler -> interrupt_now ->
inside_kernel`. These are clues, NOT established facts about THIS process.
Its fd0-2/controlling tty were not captured. Do not infer that the selected
pipe is subprocess output, or that PTY startup never occurred.

Paired run 37183040185 produced 17 complete control passes, then a full-target
UCRT/Unix Makefiles timeout before the ABI-start message; the higher-base
candidate passed all 20 targets. Both arms used CMake 4.4.4, not the original
4.4.3. No stack was captured on that full-target timeout, so neither its
cause nor the base-address change is verified. Current shared mappings use
the fixed range in `memory_layout.h:19-21` through `mm/shared.cc:116-180`;
the old base patch's below-DLL shared-console rationale does not describe
this allocator. Capture ACTUAL loaded module addresses and shared-region
addresses; a PE preferred ImageBase is not a loaded address.

A passing Git for Windows run
(git-for-windows/msys2-runtime run 37015654781, job 110868776450)
used the SAME test action SHA and runner image version 20260925.250.1,
but loaded runtime 53a3dd31 instead of c0b496fb. Its source DESCENDS
from c0b496fb, and the final `select.cc`, `fhandler/pipe.cc`, and
`fhandler/console.cc` trees are identical between the two commits.
Git for Windows also has distinct PTY, descriptor-setup, and path
changes. One passing run does not show those changes fix this
intermittent hang, especially after 14 full passes with c0b496fb.
Treat that patch-set hypothesis as a candidate to discriminate, not
an established cause. The upstream console-mode v18 and owner-exit v5
fixes in msys2/msys2-runtime#368 are already present in both trees.
If analyzing GfW changes, inspect only the first-parent successors of
the merging-rebase marker 8029ebf0305e037cde2e474acc49339fcd2c8916 up to
53a3dd3145547c314b4df6cb0b0a045e27e4b1cf. The first merge imports the common
MSYS2 base; do not count that imported base as GfW-only patches.

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

The first plausible hypothesis is rarely the root cause. Before designing a
diagnostic, write down at least two or three plausible explanations for the
observed failure and rank them by likelihood given the evidence. Pick the
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
the CMake hang. If no attempt reproduces the hang, state that limitation
clearly instead of claiming a fix.

### Iterate until proven

Your session budget is approximately 23 minutes. Reserve at least five
minutes for final documentation and copying any patch and logs into
`ci-diagnostics/`; finish the diagnosis before 22 minutes have elapsed.
A failed end-to-end verification is **information, not defeat**: refine
the hypothesis, refine the fix, re-apply, re-run. Do not
spend the whole session waiting on a hung child: give each subprocess a
reasonable timeout, capture its output, and inspect its process tree while
it is still hung. Preserve the original build/log evidence before any test
script removes or overwrites its own build directory. If all initial
attempts pass, focus on reproducing the intermittent CMake hang and
explaining the environmental differences; do not switch to investigating
other test targets. This original-action-path, native-pipe context is the
next discriminating experiment after the previous separate-path run passed
32 full targets. Prefer additional complete targets with the current
watcher over repeating the earlier narrowed configure search; preserve any
natural full-target wait for live inspection. Do not otherwise delete build
directories, clean-build, or install extra tools just to retry.

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
   NOT REPRODUCED in this runner; still investigate the intermittent
   failure using the prior live-wait evidence above. Do not waste the
   session retrying unavailable GitHub CLI authentication or fetching
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
   Compare this original-path, pipe-backed execution with the earlier
   separate-checkout, direct-file attempts before attributing differences
   to the runtime. Write the
   prediction, command, exit code, evidence, and implications immediately.
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
