#!/usr/bin/env bash
# File: spikes/api/scripts/generate-typescript.sh
# Purpose: Generate and compile-check spike-only TypeScript OpenAPI definitions.
# Related: spikes/api/scripts/generate_openapi.py, spikes/api/results/comparison.md
set -eu

spike_root="$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)"
node_major="$(node --version | sed -E 's/^v([0-9]+).*/\1/')"
test "$node_major" -ge 20

npx --yes openapi-typescript@7.13.0 \
    --default-non-nullable false \
    "$spike_root/results/drf-openapi.json" \
    -o "$spike_root/results/drf-types.d.ts"
npx --yes openapi-typescript@7.13.0 \
    --default-non-nullable false \
    "$spike_root/results/ninja-openapi.json" \
    -o "$spike_root/results/ninja-types.d.ts"

npx --yes --package typescript@7.0.2 tsc \
    --noEmit \
    --strict \
    --skipLibCheck false \
    "$spike_root/results/drf-types.d.ts" \
    "$spike_root/results/ninja-types.d.ts"

printf '%s\n' "Generated both definitions with openapi-typescript 7.13.0."
printf '%s\n' "TypeScript 7.0.2 validated both definitions with no emit."
