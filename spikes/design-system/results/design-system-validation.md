# Design-system validation result

## Evidence

- **DTCG source result:** PASS — four canonical files identify the DTCG 2025.10 schema and retain structured sRGB colors and px dimensions. The fail-closed profile checks supported types/shapes, component ranges, hex agreement, aliases, schema IDs, and theme keys.
- **Runtime result:** PASS — the initial Node 20 run exposed an unsupported-engine mismatch. Node 20 is EOL and was rejected as the frontend/design-system tooling baseline. The spike was rerun with an isolated official Node.js 24.20.0 runtime; pinned dependencies satisfied their engine requirements, and the Node 20 jsdom workaround was removed.
- **Style Dictionary result:** PASS — the narrow in-memory adapter preserves aliases and Style Dictionary 5.5.2 resolves/builds both platforms under the supported runtime. Complete DTCG 2025.10 support was not validated.
- **Semantic-token result:** PASS — generated consumer artifacts contain the 31 semantic keys and no primitive namespace; validation text uses the dedicated `color.textDanger` role rather than the danger-fill role.
- **Light/dark result:** PASS — both themes expose the same keys through the same component source/classes with different resolved color values.
- **Web output result:** PASS — deterministic static CSS contains light/dark selectors and semantic `--omni-*` properties only.
- **Native output result:** PASS — light/dark JSON has matching resolved keys, string colors, numeric dimensions/numbers/weights, and no aliases or primitives.
- **Tailwind result:** PASS — the CSS-first bridge resets defaults and maps deliberate semantic values; the production inspection checks emitted semantic utilities, Omnilyzer variables, and absence of default palette variables.
- **Radix wrapper result:** PASS — Dialog wraps the primitive behavior and public exports contain only Omnilyzer components/types.
- **Accessibility result:** PASS — both-theme contrast thresholds, semantic assertions, axe rules, and 44px contracts are automated. jsdom's layout-dependent axe color rule is excluded in favor of explicit contrast math.
- **CSP/static-style result:** PASS — Omnilyzer source uses static generated/Tailwind CSS without CSS-in-JS, inline style objects, external fonts, or remote assets. Final application CSP is not proven.
- **Governance result:** PASS — lint/tests reject common literal colors, arbitrary brackets, raw palettes, inline styles, product references, and public Radix leakage. Equivalent rules must later be distributed to product repositories.

## Recommendation

adopt

Adopt the validated design-system foundation on the Node.js 24 LTS frontend tooling baseline. The token compatibility adapter is deliberately small and fail-closed; revisit or retire it as upstream DTCG 2025.10 support changes.

## Scope statement

The synthetic palette, typography, and spacing values are validation evidence only. Task 005 decides the token/component architecture, not Omnilyzer's final brand identity. Final brand tokens can replace primitive values without changing semantic component APIs.

Native evidence validates cross-platform token transformation only. It does not validate React Native rendering, Dynamic Type, platform font mapping, or density behavior. Style Dictionary 5.5.2 does not constitute proof of complete DTCG 2025.10 feature support.
