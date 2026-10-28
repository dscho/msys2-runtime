#!/usr/bin/env bash

set -euo pipefail

out="${1:-fork-diagnostics/baseline}"
root="$(cygpath -u "${TEST_ACTION_PATH:?missing test action path}")"
outcome="${NATIVE_TEST_OUTCOME:-unknown}"
mkdir -p "$out"/{headers,images,provider}

if test ! -e fork-diagnostics/copilot-diagnosis.md; then
  printf '%s\n' \
    '# Native MSYS fork investigation' \
    '' \
    "Original native test outcome: $outcome." \
    'Baseline log and PE headers are archived; no fix is verified.' \
    'The failed child allocation still needs in-process measurement.' \
    > fork-diagnostics/copilot-diagnosis.md
fi

printf 'Native test outcome: %s\n' "$outcome"
printf 'Runtime commit: %s\n' "$GITHUB_SHA"
printf 'Run: %s attempt %s\n' "$GITHUB_RUN_ID" "$GITHUB_RUN_ATTEMPT"
printf 'Runner image: %s %s\n' "${ImageOS:-unknown}" \
  "${ImageVersion:-unknown}"
printf 'MSYSTEM=%s CC=%s CXX=%s FC=%s\n' "$MSYSTEM" "$CC" "$CXX" "$FC"
printf 'Test action: %s\n' "$root"
printf 'CARGO_TARGET_DIR=%s\n' "${CARGO_TARGET_DIR:-<unset>}"
printf 'RUSTFLAGS=%s\n' "${RUSTFLAGS:-<unset>}"

uname -a
pacman -Q > "$out/packages.txt"
gcc --version
ld --version
rustc -vV
cargo -V
python --version

cp /usr/bin/msys-2.0.dll "$out/original-msys-2.0.dll"
sha256sum /usr/bin/msys-2.0.dll > "$out/runtime.sha256"
cp "$root"/{action.yml,Makefile,run-tests.sh} "$out/provider/"
cp "$root/python/test.sh" "$out/provider/python-test.sh"
cp "$root/python/setuptools-rust"/{Cargo.lock,Cargo.toml,setup.py,test.sh} \
  "$out/provider/"
sha256sum "$root"/{action.yml,Makefile,run-tests.sh} \
  "$root/python/setuptools-rust"/{Cargo.lock,Cargo.toml,test.sh} \
  > "$out/provider.sha256"

headers ()
{
  local image="$1" name
  name="$(basename "$image")"
  printf 'PE headers: %s\n' "$image"
  sha256sum "$image" >> "$out/images.sha256"
  objdump -p "$image" > "$out/headers/$name.txt" 2>&1
}

headers /usr/bin/msys-2.0.dll
headers "$(command -v rustc)"
shopt -s nullglob
for image in /usr/bin/msys-LLVM-*.dll; do
  headers "$image"
done

target="$root/python/setuptools-rust/target"
if test -d "$target"; then
  while IFS= read -r -d '' image; do
    headers "$image"
    cp "$image" "$out/images/"
  done < <(find "$target" -type f -name '*.dll' -print0)
else
  printf 'No default Rust target directory: %s\n' "$target"
fi
