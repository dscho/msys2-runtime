# Debug the Windows 2025 ctrl-c UI-test flake

## Context

You are running inside the `ui-tests` job on a GitHub Actions
`windows-2025` runner. The checkout, known-good MSYS2 runtime artifact,
portable Windows Terminal, AutoHotkey, Node.js, and Win32 OpenSSH have
already been prepared.

The test under investigation is `ui-tests/ctrl-c.ahk`. Its initial result
is available as `$INITIAL_TEST_OUTCOME`. Whether that result passed or
failed, investigate the known flakiness and prove the final code robust.

Write all diagnostics, scripts, logs, screenshots, and intermediate files
inside the checkout. Maintain a living report at
`copilot-diagnosis.md`; update it whenever the working hypothesis changes.

Do not commit or push. Leave the verified working-tree diff for review.

## Goal

Find and fix the root cause of any remaining flake in
`ui-tests/ctrl-c.ahk`, then make the shared stress script complete all 20
iterations consecutively on this runner.

Success requires all of the following:

1. Every AutoHotkey invocation exits with status 0.
2. Every log reaches the SSH-clone completion and PowerShell-window
   teardown messages.
3. No run times out or leaves a Windows Terminal, OpenConsole, `sshd.exe`,
   Git, MSYS2 shell, or AutoHotkey process behind.
4. `git diff --check` succeeds.
5. `copilot-diagnosis.md` contains the evidence, final diff, and all 20
   results.
6. `copilot-verification.ok` exists and identifies the successful
   20-iteration attempt.

Do not claim success after a single pass.

## Historical evidence

Recent Windows 2025 failures had three distinct signatures:

1. A successful clone printed:

   ```
   Receiving objects: 100% ..., done.
   remote: Total ...
   GIT_CLONE_EXIT_CODE=0
   PS ...> [24~
   ```

   The test nevertheless timed out because it required a clean PowerShell
   prompt after the explicit exit-code marker. The `[24~` came from the
   Windows Terminal buffer-export hotkey.

2. The test sometimes sent Ctrl+C after a fixed 500 ms, before the shell
   alias had proved that `sleep` was running. The log ended at the sleep
   command and timed out waiting for the interrupt.

3. The SSH clone completed, but the AutoHotkey process hung after logging
   `Cleaning up worktree`. The exported terminal buffer did not contain
   the final `exit` command, showing that focus had moved before teardown.

The current source contains candidate fixes for these signatures. Treat
them as hypotheses to verify, not as facts.

## Required method

### 1. Read the current evidence

Read all existing files matching:

```
ui-tests/ctrl-c-initial*
ui-tests/wt-buffer-export.txt
ui-tests/mintty-export.html
ui-tests/screenshot.png
```

Find the last line showing forward progress. Correlate it with the current
control flow in `ui-tests/ctrl-c.ahk` and
`ui-tests/ui-test-library.ahk`.

Use `git log -L` and `git blame` on every suspect span. Record exact file
and line references in `copilot-diagnosis.md`.

### 2. Rank hypotheses before editing

List at least three plausible causes, their predicted evidence, and the
cheapest experiment that distinguishes them. Include timing, focus,
terminal-buffer export, stale files, lingering processes, and wrong
process/runtime selection where applicable.

Before each experiment, state what it should show. If the result differs,
revise the model instead of patching the next symptom.

### 3. Reproduce with the workflow's exact command

The workflow invokes one test as follows from `ui-tests`:

```powershell
$env:LARGE_FILES_DIRECTORY = "${env:RUNNER_TEMP}\large-diagnose"
& "${env:RUNNER_TEMP}\ahk\AutoHotKey64.exe" /ErrorStdOut /force `
  ctrl-c.ahk "$PWD\ctrl-c-diagnose" 2>&1 |
  Tee-Object -FilePath ctrl-c-diagnose.console.log |
  Out-Default
exit $LASTEXITCODE
```

Create PowerShell helpers under `ci-debug/` when repeated invocation is
needed. Preserve stdout and stderr with `Tee-Object`, enforce explicit
deadlines, and use a fresh test worktree and
`LARGE_FILES_DIRECTORY` for every iteration.

Verify the exact paths and versions of `git.exe`, `sh.exe`,
`msys-2.0.dll`, `wt.exe`, AutoHotkey, and Win32 `sshd.exe` before drawing
conclusions.

Do not terminate processes by name. Track the process IDs started by the
test and only stop those specific processes when cleanup is required.
Do not run verification detached or in the background. Wait for each
stress-script invocation so its failure remains available for diagnosis.

### 4. Apply only a proven fix

Edit only the UI-test code directly implicated by evidence. Do not
refactor unrelated code.

After each candidate fix, rerun the exact failing command. If it fails,
preserve the result, revise the hypothesis, and continue.

### 5. Prove the flake fixed

After a candidate passes once, remove any stale success marker and run the
same stress script the workflow uses:

```powershell
Remove-Item copilot-verification.ok -ErrorAction SilentlyContinue
& .\ui-tests\run-ctrl-c-stress.ps1 -Count 20 `
  -Prefix copilot-attempt-1
```

The script stops at the first failure and preserves separate stdout,
stderr, and test logs for every completed iteration. If it fails, inspect
that exact failure, revise the diagnosis, apply a surgical correction, and
rerun the full script with a fresh prefix such as `copilot-attempt-2`.

Keep iterating until one invocation completes all 20 runs. Only then write
`copilot-verification.ok` with the successful prefix and a concise summary.
The workflow treats absence of this marker as failure.

## Final report

Before exiting, write `copilot-diagnosis.md` with:

1. Root cause, with exact source lines.
2. Evidence from the original failure and discriminating experiments.
3. The minimal `git diff`.
4. The exact 20-run verification table.
5. Relevant successful log excerpts.
6. Rejected hypotheses and why the evidence rejected them.
7. Residual risks.

If 20 consecutive passes cannot be achieved, remove
`copilot-verification.ok`, do not claim a fix, and record every attempted
change and failure. Restore the best evidence-backed working tree and state
the cheapest next experiment.
