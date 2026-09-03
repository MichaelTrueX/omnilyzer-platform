#!/usr/bin/env bash
set -euo pipefail

readonly ZOT_VERSION='v2.1.20'
readonly RELEASE_BASE='https://github.com/project-zot/zot/releases/download/v2.1.20'
readonly CHECKSUMS_SHA256='a9fe260d8259084d884f2135f33a6f63ce898665e2c1115b76c871a196df6653'
readonly INSTALL_PATH='/usr/local/bin/zot'

if [[ "${EUID}" -ne 0 ]]; then
  echo 'install-zot.sh must run as root' >&2
  exit 1
fi

work_dir="$(mktemp -d)"
trap 'rm -rf -- "$work_dir"' EXIT
curl --fail --show-error --silent --location \
  --proto '=https' --tlsv1.2 \
  --output "$work_dir/checksums.sha256.txt" \
  "$RELEASE_BASE/checksums.sha256.txt"
printf '%s  %s\n' "$CHECKSUMS_SHA256" "$work_dir/checksums.sha256.txt" | sha256sum --check --strict -

curl --fail --show-error --silent --location \
  --proto '=https' --tlsv1.2 \
  --output "$work_dir/zot-linux-amd64" \
  "$RELEASE_BASE/zot-linux-amd64"
(
  cd "$work_dir"
  expected_line="$(grep -E '^[0-9a-f]{64} [* ]zot-linux-amd64$' checksums.sha256.txt)"
  [[ "$(printf '%s\n' "$expected_line" | wc -l)" -eq 1 ]]
  printf '%s\n' "$expected_line" | sha256sum --check --strict -
)

install --owner=root --group=root --mode=0755 \
  "$work_dir/zot-linux-amd64" "$INSTALL_PATH"
"$INSTALL_PATH" --version
printf 'Installed zot %s after two-stage SHA-256 verification.\n' "$ZOT_VERSION"
