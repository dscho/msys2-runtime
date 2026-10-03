# Diagnose the MSYS-gcc timeout on msys2/msys2-runtime#375

## Context

You are running in the `debug-msys-gcc` job on a GitHub Actions
`windows-2025` runner. The `Exercise MSYS-gcc CMake test` step runs up to
six bounded CMake-only attempts after the original action's toolchain, rust,
and python prerequisites. It may have timed out, failed, or passed every
attempt. Determine which happened; do not assume a hang was reproduced.
The workflow installs MSYS2, enables the staging repository, and unpacks
the `install` artifact from the successful
msys2/msys2-runtime run 37014998883 (commit c0b496fb63f26893a1d1085ebeecc54c99c9e2d1).
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
`$GITHUB_WORKSPACE`. The test repository is checked out at
`$GITHUB_WORKSPACE/msys2-tests`, pinned to
msys2/msys2-tests@a5a6995b100ef2b09cd96b4c6262a573840b3af9.
The original action ran under the runner's `_actions/msys2/msys2-tests`
directory. The focused reproducer uses a different checkout path; record
that difference when comparing results. It invokes
`make -C msys2-tests -j cmake` under the `msys2 {0}` shell with `MSYSTEM=MSYS`,
`CC=gcc`, `CXX=g++`, and `FC=gfortran`. Its CMake test script loops over
Ninja and Unix Makefiles, building native and MinGW cross-compiled samples.
The first fork diagnostic run passed this CMake target in 24 seconds, then
failed in a different `runtime` symlink test. Do not investigate that
later failure here.

**All files you create for the operator (scripts, logs, diffs, diagnostics)
MUST go inside `$GITHUB_WORKSPACE/ci-diagnostics/`.** Inspect files under
`msys2-tests` and the installed runtime as necessary, but copy relevant
existing CMake logs into `ci-diagnostics/` BEFORE rerunning a test that
overwrites its build directory. The workflow uploads that directory even
when Copilot exits nonzero; the CLI's full stdout and stderr stream into
`ci-diagnostics/copilot.log`. Do not copy tokens, credentials, environment
dumps containing secrets, or the entire `~/.copilot` directory into artifacts.

Your findings MUST be written to
`$GITHUB_WORKSPACE/ci-diagnostics/copilot-diagnosis.md`. It already contains
a brief seed note. Replace it immediately with the observed CMake attempt
statuses and the exact last progress line if one hung; then update it
**after each meaningful observation or experiment, not only at the end**.
An interrupted
session or a late `exit 1` must never erase the analysis already completed.
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

Your session budget is approximately 90 minutes. Reserve at least ten
minutes for final documentation and copying any patch and logs into
`ci-diagnostics/`. A failed end-to-end verification is **information, not
defeat**: refine the hypothesis, refine the fix, re-apply, re-run. Do not
spend the whole session waiting on a hung child: give each subprocess a
reasonable timeout, capture its output, and inspect its process tree while
it is still hung. Preserve the original build/log evidence before any test
script removes or overwrites its own build directory. If all initial
attempts pass, focus on reproducing the intermittent CMake hang and
explaining the environmental differences; do not switch to investigating
other test targets. Do not otherwise delete build directories, clean-build,
or install extra tools just to retry.

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
   attempt's status, the last forward-progress line and time if any hung,
   and the exact command. If all six attempts passed, label the hang
   NOT REPRODUCED in this runner; still investigate the intermittent
   failure. Earlier failure logs are available via the run and job IDs
   above if needed; fetch the full archive if the API truncates. Verify
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
   compiler command with a deadline; capture full stdout/stderr and
   inspect the live process tree while it is stuck. If necessary, compare
   the original action directory with the separate pinned checkout
   to test whether path or preceding action steps matter. Write the
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
