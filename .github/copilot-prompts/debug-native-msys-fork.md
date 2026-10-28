# Prompt for Copilot CI debugging session

## Context

You are running on the native GitHub Actions Windows runner selected by the
MSYS-gcc matrix entry, outside Docker, where the `msys2-tests MSYS-gcc` job's
`Run native MSYS tests with logs` step just failed (exited non-zero).
The earlier steps of the workflow that prepared the environment (checkout,
MSYS2 installation, staging packages, and deployment of the runtime built
by the build job) succeeded; the failure is downstream of that.

Your working directory is the runtime checkout at `GITHUB_WORKSPACE`
(`$env:GITHUB_WORKSPACE` in PowerShell). **All diagnostic files you create
(scripts, logs, screenshots, intermediate results) MUST be written somewhere
inside this directory tree.** The necessary exception is the existing test
tree at `TEST_ACTION_PATH`: its build outputs MUST stay at their original
paths because GNU ld hashes the DLL output pathname. Do not copy the tests
elsewhere to satisfy the artifact-location rule.
The artifact paths configured by the workflow, `fork-diagnostics/`, will be
uploaded as a build artifact, which is the only channel by which your work
reaches the human operator after the job finishes.

Your final findings MUST be written to
`fork-diagnostics/copilot-diagnosis.md`. Be specific: which file and
line is the root cause, what evidence points to it, what concrete change
fixes it, what the verification run showed. Do NOT propose changes that you
have not verified work end-to-end.

Treat the diagnosis file as a **living document**: update it as your
understanding evolves, so that even if the session is interrupted or
truncated, the most recent version captures everything you have learned so
far. The worst outcome is a session that did real work but left no
breadcrumbs because the diagnosis file was only going to be written "at the
end".

## User's authorization and decision

Use **Claude Sonnet 5.5**, maximum reasoning effort and long context. Do not
silently select another model or launch agents using other models.
You may investigate and attempt a fix inside this ephemeral runner. Do not
commit, push, create a PR, post a comment, or modify any remote resource.
The human will review your evidence and patch.

First capture the missing real CI evidence. Then pursue the functional
routes in this explicit user-selected order:

1. **B: Parent-side DLL placement policy.** Prevent fork-hostile mappings
   during loading, before DLL initializers execute. Start here, not with
   the smaller stack-reservation mitigation.
2. **A: Retain the parent's vacated Windows-stack reservation**, decommitting
   pages rather than releasing that address range.
3. **C: Selective child-side stack handling**, only after switching safely
   away from the original stack, while retaining other DLL protection.
4. **D: Coordinated toolchain/post-link image bases**, assigning disjoint
   whole-image ranges, not one shared fixed ImageBase.
5. **E: A Rust process-launch path that avoids fork**, if the required child
   setup can be expressed with appropriate spawn semantics.

Do not treat this ordering as proof that any route is correct. Explain
with evidence why a route fails or is unsafe before moving to the next.
Keep one functional candidate at a time; save rejected candidates as
separate patches and return only your own changes to the measured baseline.
Never accumulate unrelated fixes or stack all five approaches.

Read **all** of `fork-diagnostics/AGENTS.md` before editing. It is the
`git-for-windows/main:AGENTS.md` guidance requested by the user, fetched from:
https://raw.githubusercontent.com/git-for-windows/msys2-runtime/main/AGENTS.md
If its guidance and this concrete CI setup differ, identify the difference
and preserve the exact failing test environment rather than guessing.

## Evidence already established in the parent investigation

This section is a handoff, not permission to promote hypotheses to facts.
Read the source and verify the actual runner state. Do not repeat completed
negative controls or compiler-fix validation without a new reason.

### Failure, controls, and scope

The original error was:

```text
child_info_fork::abort: address space needed by
'indoc-f2b72953791bb301.dll' (0x400000) is already occupied
```

It happened in **native MSYS-gcc, outside Docker**, during Python's
setuptools-rust test, while rustc was attempting to launch GCC.
The Docker MSYS variant was passing. Do not diagnose this as a Docker
failure or change Docker configuration to fix it.

Important public records:

- Original good native run:
https://github.com/msys2/msys2-runtime/actions/runs/39278421557/job/118153198776
- Original bad native run:
https://github.com/msys2/msys2-runtime/actions/runs/40511844976/job/122218374040
- Runtime preferred-base-change negative control:
https://github.com/msys2/msys2-runtime/actions/runs/40531649455/job/122291523147
- Preferred-base change plus PR #386 negative control:
https://github.com/msys2/msys2-runtime/actions/runs/40538050517/job/122315167895
- Successful Cargo-path workaround, all 11 jobs passed:
  https://github.com/msys2/msys2-runtime/actions/runs/40565799922
- Successful native job from that run:
https://github.com/msys2/msys2-runtime/actions/runs/40565799922/job/122410655612
- Earlier discussion with a potential hint:
  https://github.com/msys2/msys2-runtime/pull/396#issuecomment-6445291645
- Original compiler discussion:
  archive https://inbox.sourceware.org/cygwin-developers/ and Message-ID
  `7ae045b2-3d29-4c7e-960f-f5e136d77b5d@dronecode.org.uk` (thread /t/#u).

The source delta from good
`cd6a0bec8d161822c7c9e67b39b126ed91b35c98` to bad
`e1a5d5f75c044117130da43240ed581f5c156dda` was six small compiler fixes:
volatile incyg updates, top-level volatile fork parameter qualifiers, and
const-correct archive/strace/cygcheck cursors. The affected components built;
strict object builds also corroborated the volatile changes. No direct
causal source defect was found. This is NOT a controlled exclusion of every
possible compiler or binary-layout effect.

The equivalent compiler commits in this branch are `b2d4e30bf9`,
`4a4f6ab214`, `c8543ec3bf`, `5e7e57e22d`, `cfe69b056d`, and `e1a5d5f75c`.
Do not undo them or suppress their GCC 16 diagnostics.

An initial old-runtime control accidentally selected newer source.
The corrected control did select cd6a, but failed compilation on the known
volatile diagnostics; **it never reached runtime tests**. Do not cite it
as an old-runtime failure or repeat that build as a useful control.
The original good install artifact, if still available, was artifact
`12198956980`, name `install`, run `39278421557`, 13,561,979 bytes, digest:
`sha256:ea6597e60f63dc1cc9b626fead2f8b6e462e14c63ebee8728a5af6849f78be07`.
Recheck availability and identity before using it.

Original good versus original bad native environment:

| Input | Good | Bad |
|---|---|---|
| Runtime | cd6a0bec | e1a5d5f7 |
| Runner image | 20261007.264.1 | 20261021.278.1 |
| Rust | 1.99.0-1 | 1.99.1-1 |
| Python | 3.12.15-1 | 3.12.16-1 |
| Test GCC | 16.2.0-1 | 16.2.0-1 |
| Test binutils | 2.47-1 | 2.47-1 |

Those are test-job packages, not proof of runtime build-compiler equality.
The generated host and Docker MSYS matrix dictionaries, including package
strings, were compared between provider commits `35115a71...` and
`59cf905cfb344aa09deaaa6eb03f0e0f0cd7e553`: they were identical.
The provider's Docker-introducing commit
`0a7db91b758fd166f570e214917b74462c5d9297` already provided `-docker` names;
the consumer hid those suffixes by reconstructing names. The display is now
`matrix.name`. Duplicate old names do not prove duplicate host execution.

The preferred-base change
`370e5af99b0ce535a86fcc3fce130a7b2c8eb967` changes only the runtime's
preferred base from `0x180040000` to `0x210040000`. Its tested cherry-pick
still failed identically with loaded runtime `3.6.11-3adedbb9-api-357`.
PR #386 changes `GENERIC_READ` to `FILE_READ_ATTRIBUTES` when finding the
runtime installation root. Its documented case is an earlier runtime-data
copy failure in Server 2019 containers, not this later native reservation.
Adding its cherry-pick still failed with `3.6.11-24b6a589-api-357`.
Both changes are already in this branch; neither fixes this native case.
The user initially said PR #383 but corrected that to **PR #386**.

### Cargo-path workaround and address calculations

Commit `ee6bf1fbe1b0b1d40d790e639690bdd29ad09968` exports
`CARGO_TARGET_DIR=/tmp/cargo-target` only for native MSYS. Its actual CI run
passed all 11 jobs. The previously failing native job loaded
`3.6.11-ee6bf1fb-api-357` and printed `Hello from Rust!`.
It used image `20261021.278.1`, Rust `1.99.1-1`, LLVM `21.1.8-2`,
binutils `2.47-1`, and Python `3.12.15-1`, matching those core inputs of the
failed PR #386 control. The indoc and pyo3 macro filenames were unchanged.

**That workaround is deliberately disabled in this fork investigation.**
Do not restore it, move the provider checkout, change Cargo.lock, rename
the DLL, skip Rust, or change the output path to claim a runtime fix.
Keep the provider reference at `msys2/msys2-tests@main`: pinning it to a
SHA changes the action cache directory, which can change the image bases.
The provider main observed while preparing this investigation was
`59cf905cfb344aa09deaaa6eb03f0e0f0cd7e553`. Snapshot actual source hashes;
do not assume a mutable main or a weekly runner image is immutable.

GNU ld's automatic DLL image base depends on the **full output pathname**.
The parent independently disassembled the installed linker and reproduced
its 64-bit path hash. Local ld was `2.47.20260726`, not established to be
byte-identical to CI's package `2.47-1`.

An archived LLVM package inspected in the independent investigation was
`llvm-libs-21.1.8-2-x86_64.pkg.tar.zst`, containing `msys-LLVM-21.dll`:

```text
Preferred ImageBase:  0x4d5df0000
SizeOfImage:         0x04b0e000
Full image interval: [0x4d5df0000, 0x4da8fe000)
DllCharacteristics:  0
```

Calculated preferred bases, not measurements of the failing CI process:

| Output path | Calculated preferred base |
|---|---|
| bin/msys-LLVM-21.dll | 0x4d5df0000 |
| Old action-path indoc-fb8e4230a48fbe2e.dll | 0x584940000 |
| New action-path indoc-f2b72953791bb301.dll | 0x4d9f80000 |
| Provider checkout new indoc path | 0x5cec30000 |
| /tmp/cargo-target/debug/deps/indoc-f2b72953791bb301.dll | 0x4822e0000 |

The native action prefix was:
`/d/a/_actions/msys2/msys2-tests/main/python/setuptools-rust/target/debug/deps/`
The provider-checkout prefix was:
`/d/a/msys2-tests/msys2-tests/python/setuptools-rust/target/debug/deps/`
Docker instead builds under `/c/msys2-tests/`.
Whole intervals matter: `0x4d9f80000` lies inside LLVM's preferred interval,
even though the preferred starting addresses differ.
Gemini initially gave `/tmp` the wrong result `0x590860000`; the parent
corrected that to `0x4822e0000`. Do not repeat the withdrawn value.
Do not use one global fixed ImageBase for all Rust DLLs; it creates clashes.

Before this run, actual failing CI DLL headers and mapped image intervals
had not been captured. The complete production causal chain therefore
remained a hypothesis despite the passing output-path workaround.

### Controlled local reproducer, not production proof

`.github/ci/dll-collision-control.c` is the warning-free standalone control
already exercised in the user's local SDK. It reserves exactly the LLVM
interval above, dlopens a small DLL, and forks. With the SAME reservation:

```text
DLL preferred at 0x4d9f80000:
  DLL loaded at 0x400000 with LLVM's preferred range reserved
  child_info_fork::abort: address space needed by
  'cargo-base-collision.dll' (0x400000) is already occupied
  fork: Resource temporarily unavailable
  exit status 1

DLL preferred at 0x4822e0000:
  DLL loaded at 0x4822e0000 with LLVM's preferred range reserved
  Child exit status: 0
```

Use this as a cheap paired control, not a substitute for Rust. For example,
in the CI MSYS shell, with outputs under `fork-diagnostics/repro/`:

```bash
mkdir -p fork-diagnostics/repro
out="$PWD/fork-diagnostics/repro"
printf 'int probe_symbol (void) { return 42; }\n' > "$out/dll-probe.c"
gcc -Wall -Wextra -Werror -O2 .github/ci/dll-collision-control.c \
  -o "$out/control.exe"
gcc -shared "$out/dll-probe.c" -o "$out/collision.dll" \
  -Wl,--image-base,0x4d9f80000,--disable-dynamicbase
gcc -shared "$out/dll-probe.c" -o "$out/safe.dll" \
  -Wl,--image-base,0x4822e0000,--disable-dynamicbase
```

Capture both PE headers and both runs' complete outputs and exit statuses.
If the current packages differ, record that before interpreting the result.
Failure to reserve the control's LLVM interval is an infrastructure/control
failure, not proof of the Rust mechanism.

A separate successful local SDK fork probe showed this child TEB after
the stack handoff:

```text
StackBase=0x800000000 StackLimit=0x7ffff9000
DeallocationStack=0x7ffe00000
```

Its low map nevertheless contained:

```text
00400000-005F6000 reserved
005F6000-005F9000 guard
005F9000-00600000 committed
006A0000-006DA000 committed [win heap 0 default grow]
006DA000-007A0000 reserved  [win heap 0 default grow]
00880000-00A80000 another thread's stack
00A80000-00C80000 another thread's stack
```

The 0x400000 region was stack-shaped and consistent with the old Windows
stack, not labeled as the current stack after TEB rewriting. The other
low heap and stack regions are independently relevant. Another local
probe reported that forcing relocation to 0x6E0000 also failed.
Do not claim keeping one old-stack hole reserved solves all low mappings.
These are local SDK observations, NOT the actual failed CI child's map.

### Fork invariant, source ordering, and loader path

The invariant is preservation of pointer values in copied parent state.
Windows creates a fresh process; Cygwin reconstructs its contents. Loading
the DLL at some other free address would invalidate copied code/data
pointers. The error's `0x400000` is the **actual parent address**, not the
PE preferred ImageBase.

Read the complete relevant source flow, not only the emitted error:

- `winsup/cygwin/dll_init.cc`, `dll_list::alloc`, around 351-370, records
  actual `d->handle`, whole `d->image_size`, and PE `d->preferred_base`.
- `dll_list::reserve_space`, around 690, calls
  `VirtualAlloc(d->handle, d->image_size, MEM_RESERVE, PAGE_NOACCESS)`.
  This reserves addresses, not committed DLL contents. Its existing
  failure diagnostic does not save GetLastError or query the occupant.
- `winsup/cygwin/dcrt0.cc`, around 629, calls that reservation early.
- `reserve_at`, around dll_init.cc:644, and `load_after_fork_impl`, around
  720, are the LATER loader-coercion algorithm: probe without resolving
  references, unload misplaced probes, retain owned wrong-hole blockers,
  recurse with a six-retry limit, and finally initialize in dependency
  order at the parent handles.
- The observed abort happens BEFORE that coercion loop. Its ASLR TODO is
  not an established explanation for this earlier reservation failure.
- `winsup/cygwin/fork.cc`, `frok::child`, around 135-205, runs after the
  longjmp. Shared-memory fixup precedes DLL and fd fixup deliberately.
- The parent later copies DLL data/BSS around fork.cc:529-537.
- `child_info_fork::alloc_stack`, dcrt0.cc:405-483, reserves/commits the
  parent stack and guard as needed, including application-provided stacks.
  It does not release the child's original Windows stack.
- Around dcrt0.cc:875-887, TEB stack fields are replaced and execution
  longjmps into the copied parent context.
- `_dll_crt0`, dcrt0.cc:1027-1064, explains the initial Windows-stack
  nonreproducibility and moves the non-fork main stack into Cygwin's
  controlled pthread arena. Line 1059 releases the former Windows stack.
  Fork instead calls alloc_stack. Early DLL reservation at 629 still runs
  on the child's original Windows stack.
- Inspect `local_includes/memory_layout.h`, `local_includes/dll_init.h`,
  and `dlfcn.cc`; do not infer actual mappings from `.din` preferred bases.
  Runtime linking uses --dynamicbase. Some layout comments have inaccurate
  "16 Gigs" labels for 8-GiB ranges; calculate rather than repeat them.

The exact packaged Rust release was traced through:

```text
Rust 1.99.1 rustc_metadata/host_dylib.rs
 -> libloading 0.8.9 Unix backend
 -> Cygwin dlopen
 -> Windows LoadLibraryW (dlfcn.cc:280)
```

Sources:
https://github.com/rust-lang/rust/tree/1.99.1
Files: `compiler/rustc_metadata/src/host_dylib.rs`,
`compiler/rustc_target/src/spec/base/cygwin.rs`, and `Cargo.lock`.
https://github.com/rust-lang/rust/blob/1.99.1/Cargo.lock
https://github.com/nagisa/rust_libloading/blob/0.8.9/src/safe.rs
https://github.com/nagisa/rust_libloading/blob/0.8.9/src/os/unix/mod.rs

Rust's Cygwin target is in the unix family, is_like_windows, and passes
`--disable-dynamicbase --enable-auto-image-base` to the GNU linker.
Cargo.lock contains libloading 0.8.9 AND 0.9.0, but rustc_metadata uses
**0.8.9**. Its loader intentionally leaks the library handle because
objects may outlive the immediate load. The Unix backend uses
RTLD_LAZY | RTLD_LOCAL and calls dlopen. The MSYS2 1.99.1 package recipe
listed upstream source with no source patches; that identifies the
relevant release, not byte-for-byte proof of installed binaries.
Thus option B is on Rust's relevant loading path. It does NOT automatically
cover applications calling Win32 LoadLibrary directly.

### Primary maintainer history and API constraints

Read the primary discussion, not just AI summaries or commit subjects:

- `023c107a22ebd2f540fa3f4888535aad32839fe2`, March 2019,
  "Cygwin: fork: reserve dynloaded dll areas earlier":
https://github.com/Cygwin/cygwin/commit/023c107a22ebd2f540fa3f4888535aad32839fe2
  Discussion: https://inbox.sourceware.org/cygwin-patches/ and Message-ID
  `c52ec077-d1e6-f61a-df9c-fe9ede1ba1ff@ssi-schaefer.com`.
  It moved exact reservations from after longjmp into handle_fork, before
  more initialization. Corinna questioned the event-object allocator
  rationale because events use kernel pools. Haubenwallner explained that
  fresh build DLLs make rebasing/restarting impractical; he was NOT sure
  the patch helped and called the allocator explanation "nothing more
  than a wild guess". This establishes historical intent and a regression
  concern, not proof of this CI occupant or every alleged allocator.
- `6642f7daa369ede921ce92eb819f01dc58b18b30`, May 2011:
https://github.com/Cygwin/cygwin/commit/6642f7daa369ede921ce92eb819f01dc58b18b30
  Replaced broad reserve_upto/release_upto with exact reservations and
  recursively owned wrong-hole blockers. Old release_upto warned that it
  could free unrelated reservations. Track ownership; do not resurrect
  blind low-address reservation/release sweeps.
  A DONT_RESOLVE_DLL_REFERENCES probe must be unloaded before a real load
  will initialize that DLL. Keeping the probe handle then doing another
  LoadLibrary is not a valid general initialization strategy.
- `e753e4129ad0843859e97a4c56962b5395f390b6`, December 2015:
https://github.com/Cygwin/cygwin/commit/e753e4129ad0843859e97a4c56962b5395f390b6
  Moves x86_64 main stacks into the pthread arena for reproducibility,
  releases the original stack, and discusses 32/64-bit startup behavior.

Original Microsoft documentation:
https://learn.microsoft.com/en-us/windows/win32/api/
Pages `memoryapi/nf-memoryapi-virtualfree` and
`libloaderapi/nf-libloaderapi-loadlibraryw`.

MEM_RELEASE releases the reservation; MEM_DECOMMIT with allocation base and
size 0 leaves the entire address range reserved without committed pages.
LoadLibrary loads dependencies and calls DLL_PROCESS_ATTACH. Do NOT
presume a successfully initialized DLL can safely be unloaded, moved and
reloaded: initializers can publish pointers or perform irreversible work.

For B, investigate legitimate preferred/fixed bases, dependencies,
initialization ordering, nested/concurrent loading, reservation ownership,
and native callers bypassing dlopen. Do not reserve enormous low address
ranges indiscriminately or unmap allocations you do not own.
For A, test low heap/other-stack destinations, not only 0x400000.
For C, never free a live stack; preserve TEB/TLS/exception handling and
early protection for unrelated DLL regions. Do not merely move the whole
reservation pass later.
For D, coordinate full image intervals and preserve distinct DLL bases.
For E, first trace Rust's actual process backend and required child setup.

## Concrete environment and evidence gate

`fork-diagnostics/native-tests.log` is the complete initial test output.
`fork-diagnostics/capture.log` and `baseline/` contain package versions,
original runtime copy/hash, generated DLLs, PE headers, and provider inputs.
These post-failure snapshots cannot reveal an already-exited child's map.
Check the initial log for the expected error. If it is instead a distinct
infrastructure failure, diagnose that honestly; do not invent the old one.

Before functional fixes, rebuild a **diagnostic-only runtime** and run the
same original-path Rust test. Save instrumentation separately as
`fork-diagnostics/diagnostic-only.patch`. Capture at least:

- GetLastError immediately after failed VirtualAlloc, before logging or
  any other Win32 call overwrites it.
- The DLL's actual parent handle, preferred ImageBase, full image size,
  pathname and the relevant parent DLL/dependency mappings.
- VirtualQuery data across the WHOLE requested interval, including
  allocation base, region extent, state, protection and type.
- The child's current TEB stack base, limit and deallocation stack, and
  enough allocation/module/heap identity to identify the actual conflict.

Prefer read-only queries after the failed allocation so instrumentation
does not itself move the allocation that you are trying to observe.
Do not call an arbitrary MEM_PRIVATE region a stack solely because it is
low or has a guard page. Correlate with actual stack/allocation identities.
Do not load additional diagnostic DLLs or allocate large buffers before
the reservation under investigation.

If instrumentation changes reproduction, preserve that result and revise
the experiment. Do not claim a child allocation was measured if it was
only inferred from the local SDK probe or a parent mapping.

## Source, build, deployment, and exact reproducers

This runner has its own source checkout; do not use the user's local
parent-worktree build. In the parent session that build still targeted PR
#383 sources, NOT the designated test-MSYS-gcc worktree. No functional
runtime change had been implemented or selected before this CI task.

The successful CI build uses:

```bash
(cd winsup && ./autogen.sh)
./configure --disable-dependency-tracking \
  --with-msys2-runtime-commit="$GITHUB_SHA"
make -j8
make DESTDIR="$(pwd)/_dest" install
```

Use a dedicated build directory inside this checkout, configure it against
THIS source tree, and reuse it across attempts. Derive the target directory
from the generated makefiles; do not assume the user's local target alias.
Do the initial required build, then use affected-component builds when
their prerequisites already exist. Verify real source/object/link paths,
timestamps, output hash and installed runtime for EVERY tested candidate.
An unexpectedly fast build is a provenance warning, not proof of success.

The build job's proven MSYS package list is:

```text
msys2-devel base-devel autotools cocom diffutils gcc gettext-devel
libiconv-devel make mingw-w64-cross-crt mingw-w64-cross-gcc
mingw-w64-cross-zlib perl zlib-devel xmlto docbook-xsl libzstd-devel
```

Install missing build prerequisites only in this ephemeral runner's MSYS2
installation, using --needed, and record package changes. Do not perform
another wholesale update or silently replace the candidate runtime.
Keep the original installed runtime copy/hash for rollback and controls.

**Run the Copilot CLI and runtime replacement from native PowerShell, not
from a long-lived MSYS shell that keeps the old runtime mapped.** The CLI
already runs in PowerShell. Use MSYS shells for build/test subprocesses,
wait for them to exit, then replace the installed DLL using native Windows
file operations. `MSYS2_LOCATION` is the installation used by the tests.
Check for remaining processes mapping it; do not kill them or swap a
different MSYS installation. Never claim that building alone deployed it.
Launch a fresh shell and verify uname plus the installed DLL hash before
each reproduction. Keep the original and each candidate's identity.

From PowerShell, the existing `msys2 -c '...'` wrapper runs the same MSYS
environment as the workflow. Preserve MSYSTEM=MSYS and the existing CC,
CXX, FC, PATH, RUSTFLAGS and working directories. For native executables
called from MSYS, avoid argument conversion where needed. Quote Windows
paths carefully; PowerShell does not support Bash heredocs. Pass scripts
to shells via files or correctly quoted stdin, not fragile nested strings.

The exact focused reproducer, IN THE ORIGINAL PROVIDER TREE, is:

```bash
root="$(cygpath -u "$TEST_ACTION_PATH")"
out="$(cygpath -u "$GITHUB_WORKSPACE")/fork-diagnostics/verification"
mkdir -p "$out"
set -o pipefail
(cd "$root/python/setuptools-rust" && ./test.sh) </dev/null 2>&1 |
  tee "$out/rust-test.log"
```

Use `set -o pipefail` and save the real exit status. That script computes
LIBPYTHON, exports RUSTFLAGS, runs `./setup.py build_rust --inplace`, then
`python -m setuptools_rust_test`. Do not replace it with a merely similar
Cargo invocation. The expected success output includes `Hello from Rust!`.
For repeated verification, ensure rustc really reruns and loads the same
proc-macro DLLs: touching the existing test's `src/lib.rs` can trigger a
rebuild without changing its pathname or Cargo.lock. A cache-only Python
import is not verification of the fork path. Never clean/delete the build
directory to force it. Check the actual command log.

After the focused reproducer passes, the FULL original driver is:

```bash
root="$(cygpath -u "$TEST_ACTION_PATH")"
out="$(cygpath -u "$GITHUB_WORKSPACE")/fork-diagnostics/verification"
mkdir -p "$out"
set -o pipefail
bash "$root/run-tests.sh" </dev/null 2>&1 |
  tee "$out/full-tests.log"
```

The complete driver must exit 0 with all suites enabled. Run relevant
existing runtime regression tests too if a candidate changes more general
fork/loader behavior. A standalone collision control or a changed Cargo
path alone does not meet the acceptance gate.
The workflow's initial test step remains failed by design even if your
later verification succeeds; report the actual verification logs rather
than treating the overall red run as a new failure of a verified patch.

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

This checkout may be shallow. Lack of older local history does not prove a
change never existed; fetch specific public commits when that matters.

### Apply and verify end-to-end before reporting

A "candidate fix" is a fix only after the **exact failing command** has run
to completion with the exact success criteria the workflow uses
(exit code 0, `Hello from Rust!`, rustc actually exercised, original output
paths unchanged, and the complete original driver passing). A diagnostic
snippet that exercises only the suspect code path proves only that snippet
works; it does NOT prove the full job passes. Do NOT write the final
diagnosis until this end-to-end gate has been passed.

### Iterate until proven

Your session budget is approximately 90 minutes; use all of it if needed.
A failed end-to-end verification is **information, not defeat**: refine
the hypothesis, refine the fix, re-apply, re-run. Stopping at "diagnosis
without verified fix" is, from the perspective of the workflow that
triggered this session, equivalent to no fix at all - the human will have
to manually re-run, re-attach, re-debug, paying the full context-switch cost
again.

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
   output for an unexpectedly long moment, **check for invisible dialogs
   BEFORE concluding the helper has a bug** (list windows with the
   platform's window-enumeration API, check for child processes of the
   helper).

### Surgical edits only

You are fixing a specific failure, not refactoring the code base. Make the
smallest change that makes the test pass. Do not rename, reformat, or
"improve" surrounding code. The human reviewer will be reading your diff
under time pressure; every unrelated change is a reason for them to bounce
the patch.

Never use sudo, reset --hard, cleanbuild, or checkout/restore to overwrite
changes. Never pipe output through head or tail. Never delete build trees
or artifacts to start over. Never kill/stop/restart a process without human
approval; inspect preserved logs before deciding that a quiet build is
stuck. Do not disable ASLR globally, rebase the active installation, unmap
foreign allocations, or disable tests to make the result green.
Keep diagnostics and candidates separately recorded; if a candidate fails,
revisit the model instead of patching the next symptom.

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

Do not dump the complete environment or archive authentication/config
directories. The workflow preserves only Copilot session state and logs,
not the Copilot home directory. Do not upload process memory dumps that
could contain credentials; address-space metadata is sufficient here.

## Your task

The `Run native MSYS tests with logs` step exited non-zero. The earlier
setup steps succeeded; the suspected failure is native MSYS fork while
Rust loads proc-macro DLLs and launches GCC.

Diagnose the **root cause**. Do not guess. Verify your diagnosis by running
a targeted experiment before declaring it correct. Then apply a fix and
verify end-to-end by re-running the exact failing command in the exact way
the workflow invokes it.

### Step 1: Read the failure log

Look at `fork-diagnostics/native-tests.log`,
`fork-diagnostics/capture.log`, and `fork-diagnostics/baseline/`.
Find the LAST line that indicates forward progress (a successful test, a
completed phase, a function-entry log). The failure happened immediately
AFTER that point. Note the exact timestamp of the last good line and the
timestamp of the step's exit / timeout, so you know how long the process
was stuck or how quickly it crashed.

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
  hit, or a service the test depends on is down or throttling.
- **Test infrastructure bug, not product bug.** The thing the test does
  to set up or tear down state is itself broken.

### Step 4: Verify the hypothesis (cheap, isolated)

Write a SMALL standalone reproducer under
`fork-diagnostics/repro/` that exercises ONLY the suspect code path,
reusing `.github/ci/dll-collision-control.c` where useful. It must:

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
Complete the in-process failed-CI-allocation measurements described above
before selecting a functional patch.

### Step 5: Apply the fix and verify it end-to-end

Apply your proposed fix DIRECTLY to the source files in the working tree.
The runner workspace is ephemeral, so editing files here cannot
contaminate anything; you will write the final verified diff into the
diagnosis file after Step 6.

Then re-run the FULL failing command exactly as the workflow does, from
the same working directory, with the same environment variables. The
canonical invocation is:

```bash
root="$(cygpath -u "$TEST_ACTION_PATH")"
bash "$root/run-tests.sh"
```

Capture its output into `fork-diagnostics/verification/full-tests.log`
(using `tee` so the full output is preserved even while you watch it).

The fix is verified ONLY if ALL of these hold:

1. The full driver exits with code 0 and all original suites remain enabled.
2. The exact focused test exercises rustc/proc macros and prints
   `Hello from Rust!` at the original output path, without the workaround.
3. The deployed runtime hash matches the candidate built from this source,
   with no unexpected new errors or warnings or untested loader assumptions.

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

Only after Step 5 is fully green, write to
`fork-diagnostics/copilot-diagnosis.md`:

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

Also save `fork-diagnostics/verified-fix.patch` only after that gate. Include
new regression-test files in the proposal, not just tracked-file diffs.
Keep diagnostic-only changes separate from the proposed functional fix.
The always-run workflow archive also saves `working-tree.patch`, which may
contain unfinished experiments and must not be mislabeled as verified.

### Step 7 (only if Step 5 cannot be made green)

If you genuinely exhaust the session budget without an end-to-end-verified
fix, still write `fork-diagnostics/copilot-diagnosis.md` with everything
you learned:

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
  locale, or a different timezone. Tests that compare dates, parse dates,
  or format numbers are sensitive to this.
- **Path conversion in cross-shell environments.** MSYS2 / Cygwin / Git
  Bash will translate arguments that look like Unix paths (`/Flag`) into
  Windows paths before passing them to native binaries. Set
  `MSYS2_ARG_CONV_EXCL='*'` or quote with care where needed.

## Why all of this

The expensive resource here is the human operator's attention, not CI
minutes and not Copilot tokens. Each time the operator has to:

- notice the failure,
- re-trigger the workflow,
- wait for it to reach the debugging step,
- attach,
- re-load context,
- re-prompt a fresh Copilot,

they pay tens of minutes of focused attention they could be spending on
something else. The session you are in right now exists specifically to
avoid forcing them to do that again. Use the budget. Verify the fix.
Write the diagnosis so they can review it asynchronously without
re-attaching.
