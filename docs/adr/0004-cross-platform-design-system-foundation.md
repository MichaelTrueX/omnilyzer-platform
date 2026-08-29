# ADR 0004: Cross-Platform Semantic Design-System Foundation

- Status: Accepted
- Date: 2026-08-29

## Context

Omnilyzer requires a reusable design-system foundation for independent products and eventual web and native clients. The foundation must provide one semantic design vocabulary, allow brand and theme values to change without routine component rewrites, support light and dark themes, generate deterministic web and native token artifacts, constrain shared components away from raw design values, support WCAG 2.2 AA, exclude product-specific styling, support static and CSP-friendly styling, and establish a maintained frontend tooling runtime.

Task 005 validated:

- Node.js 24.20.0;
- DTCG 2025.10 canonical token sources with structured sRGB colors and dimensions;
- semantic and primitive token separation;
- a narrow, fail-closed Style Dictionary compatibility adapter;
- Style Dictionary 5.5.2 and deterministic web/native generation;
- identical light/dark semantic token key sets;
- a Tailwind CSS v4 semantic bridge with default theme design scales reset;
- Radix Dialog behind an Omnilyzer wrapper;
- representative Button, TextField, and Dialog component boundaries;
- distinct danger-text and danger-fill semantic roles;
- accessibility and contrast checks, including a 44px interactive-target contract;
- semantic-source governance;
- a static Vite production build;
- zero high or critical runtime dependency audit findings during the spike.

Reference evidence:

- [`spikes/design-system/README.md`](../../spikes/design-system/README.md)
- [`design-system-validation.md`](../../spikes/design-system/results/design-system-validation.md)

## Options considered

### Raw product CSS / independent product styling systems

Not selected. Products must not independently invent foundational colors, spacing, typography, and shared interaction semantics.

### Primitive tokens directly consumed by components

Not selected. Primitive values are implementation and theme inputs, not component-facing contracts.

### Semantic design tokens

Selected. Shared components consume semantic roles such as canvas, surface, primary and secondary text, danger text, primary action, control border, focus ring, interaction target, spacing, radius, and typography.

### DTCG 2025.10 canonical format

Selected. The canonical source follows the stable DTCG design-token format rather than a transformation-tool-specific legacy format.

### Downgrading canonical tokens to suit Style Dictionary

Not selected. Transformation-tool limitations must not redefine the canonical Omnilyzer token model.

### Narrow Style Dictionary compatibility adapter

Selected while required. The adapter supports only Omnilyzer's explicitly validated DTCG profile and fails closed for unsupported structures. It is not a general token framework.

### Tailwind default palette/scales as design API

Not selected. Tailwind structural utilities remain useful, but its raw palette and default design scales are not the Omnilyzer design contract.

### Tailwind v4 semantic bridge

Selected for web.

### Radix primitives directly consumed by products

Not selected. Third-party primitives remain implementation details behind Omnilyzer component APIs.

### Radix behind Omnilyzer wrappers

Selected where an accessible primitive supplies justified interaction behavior.

### CSS-in-JS as foundation requirement

Not selected. The validated direction uses generated static CSS and Tailwind build output.

## Decision

1. Omnilyzer uses a canonical cross-platform semantic design-token system.
2. Canonical token source follows DTCG 2025.10.
3. Primitive design tokens are internal inputs.
4. Shared components and consuming products must use semantic design roles rather than primitive color names or raw palette values.
5. Light and dark themes expose the same semantic token vocabulary.
6. Components do not branch on theme-specific primitive values.
7. Theme changes occur through semantic token resolution.
8. Final Omnilyzer branding is not encoded by this decision. Primitive values may change without changing semantic component APIs where meaning remains stable.
9. Style Dictionary is the selected token transformation and build tool.
10. Because complete DTCG 2025.10 support is not assumed, Omnilyzer may maintain a narrow, fail-closed compatibility adapter.
11. Canonical DTCG data must not be downgraded merely to accommodate transformation-tool limitations.
12. The compatibility adapter must be retired or simplified when upstream support makes it unnecessary.
13. Generated web consumer artifacts expose semantic variables only.
14. Primitive CSS variables are not part of the supported consumer API.
15. Generated native token artifacts derive from the same canonical source as web.
16. Native output contains resolved semantic values rather than unresolved primitive references.
17. Cross-platform token generation does not imply identical web and native UI source code.
18. Tailwind CSS v4 is the accepted styling foundation for Omnilyzer web components.
19. Tailwind's default design palette and scales are not the platform design API.
20. Tailwind structural and layout utilities may be used.
21. Platform design values are deliberately mapped from Omnilyzer semantic tokens.
22. Tailwind arbitrary-value syntax is not considered a sufficient governance boundary by itself.
23. Source and repository governance must detect common raw colors, raw palettes, arbitrary styling, and inline-style escapes in shared components.
24. Product repositories consuming the design system must eventually receive equivalent governance.
25. Radix primitives may be used as low-level accessibility and interaction primitives where justified.
26. Radix primitives remain behind Omnilyzer wrapper components.
27. Platform public APIs must not directly re-export Radix primitives.
28. Shared components should expose controlled variants and normal accessibility and HTML behavior rather than unrestricted styling escape hatches by default.
29. Component styling uses semantic tokens and semantic Tailwind utilities.
30. Semantic roles remain meaning-specific. Danger text and danger-filled surfaces, for example, are distinct roles even when a theme resolves them to the same primitive color.
31. Accessibility is part of the design-system contract.
32. Normal-text semantic combinations must meet contrast requirements appropriate to WCAG 2.2 AA.
33. Relevant non-text focus and control boundaries must meet applicable contrast requirements.
34. Shared interactive controls support an appropriate target-size contract; Task 005 validated 44px.
35. Components retain accessible labels, descriptions, states, keyboard behavior, focus behavior, and other required semantics.
36. Automated accessibility tools supplement rather than replace explicit semantic and contrast tests and later browser and manual review.
37. Omnilyzer's shared component layer prefers static build-time styling rather than CSS-in-JS or runtime style generation.
38. Shared components do not require external font downloads or remote visual assets as part of the foundation.
39. Node.js 24 LTS is the accepted frontend and design-tooling runtime baseline.
40. Task 005 validated Node.js 24.20.0 as its development version.
41. Tooling projects declare and enforce supported runtime versions rather than silently running unsupported Node versions.
42. Backend Python runtime decisions are independent from the frontend Node.js tooling runtime.
43. Design-system dependency versions remain normal versioned implementation dependencies and require regression testing when upgraded.

## Architecture

```text
              Canonical DTCG 2025.10
                      tokens
                        |
                semantic contract
                        |
              Style Dictionary
             compatibility layer
                   /        \
                  /          \
                 v            v
          semantic CSS    native tokens
                 |            |
          Tailwind v4      future native
         semantic bridge    consumers
                 |
        Omnilyzer components
                 |
        controlled public API
                 |
              products

          Radix primitives
                 |
         implementation detail
                 |
        Omnilyzer wrappers
```

Radix is an implementation input to Omnilyzer wrappers, not a parallel product-facing API.

## Token layering

```text
primitive tokens
      ↓
semantic tokens
      ↓
platform mappings
      ↓
shared components
      ↓
product UI
```

Primitive names do not leak into product component contracts. Semantic names describe role rather than color. Theme and brand changes should normally affect primitive-to-semantic resolution rather than component source. Semantic roles must not be overloaded merely because current primitive values happen to match.

## Web implications

Web output uses generated static semantic CSS variables, Tailwind CSS v4, CSS-first Tailwind configuration, semantic Omnilyzer theme mappings, and structural Tailwind utilities where useful. The validated pattern resets Tailwind's default theme design values and deliberately introduces Omnilyzer semantic values.

This architecture does not claim that Tailwind technically prevents arbitrary values. Repository governance is required.

## Component boundary

Shared components are platform-owned APIs. Task 005 validated representative Button, TextField, and Dialog components; this does not freeze the final component catalogue.

Components should consume semantic roles, preserve accessibility, provide controlled variants, hide third-party primitive implementation where practical, avoid product-domain imports, and avoid unrestricted visual overrides as the default extension model. Third-party primitives may change without requiring products to consume their APIs directly.

## Native boundary

Task 005 validated only transformation of the shared semantic token vocabulary into native-usable resolved data. It did not validate React Native rendering, Expo, native components, Dynamic Type, Android or iOS font mapping, density behavior, native theming implementation, or platform accessibility APIs.

The Native Mobile architecture therefore remains **TO VALIDATE**. This ADR does not accept React Native or Expo.

## Frontend tooling runtime

The initial Task 005 attempt exposed that Node 20 no longer matched supported engine ranges for the selected current design tooling. The spike was therefore validated on Node.js 24.20.0.

Node.js 24 LTS is the platform frontend and design-tooling baseline. Frontend and tooling repositories must declare supported engine ranges, and unsupported EOL Node releases must not be retained solely to avoid upgrading the development toolchain. This does not automatically upgrade server system-wide Node installations, does not change the backend Python runtime, and does not require every production service to run Node 24. Product and deployment runtime choices still need validated configuration.

## Style Dictionary compatibility requirement

Task 005 does not establish complete DTCG 2025.10 support by Style Dictionary. The compatibility adapter is intentionally constrained to the Omnilyzer-supported token subset. It validates supported structures, fails closed on unsupported structures, preserves aliases until transformation and resolution, and does not silently coerce unknown DTCG features.

Future Style Dictionary upgrades must evaluate whether the adapter can be reduced or removed. A permanent general-purpose adapter is not an architectural goal.

## Accessibility implications

WCAG 2.2 AA is an architectural target. Task 005 automated text contrast, focus and control contrast, labels and descriptions, invalid-state semantics, Dialog naming, keyboard dismissal, focus return, the 44px hit-target contract, and axe-based checks where jsdom supports them.

jsdom does not substitute for real-browser accessibility testing. Layout-dependent automated color checks were complemented by deterministic token mathematics. Final products still require browser, device, and manual accessibility validation.

## CSP and security implications

The shared design-system foundation should remain compatible with strict application CSP by preferring static generated CSS, static build assets, no platform-owned CSS-in-JS requirement, no inline React style objects in shared components, no external font dependency, and no remote design assets.

This ADR neither defines nor validates a final application's complete CSP. Third-party runtime behavior still requires review when integrated into applications. Dependencies require routine vulnerability, provenance, and upgrade review.

## Governance implications

Platform-repository semantic-design validation is insufficient once components and tokens are distributed. Later platform-packaging work must decide how to distribute semantic token artifacts, component packages, lint and governance rules, compatibility metadata, and versions. Products must not manually copy these files.

## Consequences

Positive consequences:

- a stable semantic component contract;
- brand and theme values can evolve without routine component rewrites;
- one canonical token vocabulary can feed web and native;
- accessibility requirements are testable at token and component boundaries;
- third-party primitives remain hidden from product APIs;
- static styling supports CSP-friendly deployment;
- design governance can be automated;
- Node 24 provides a supported modern frontend tooling baseline.

Tradeoffs:

- semantic-token design requires governance discipline;
- the compatibility adapter must be maintained while needed;
- Tailwind still technically permits escape hatches;
- wrapper components create an API-maintenance responsibility;
- accessibility requires continued browser and manual validation;
- final branding remains future work;
- native implementation remains separately unvalidated.

## Operational and versioning implications

Later implementation must determine package structure, npm registry and distribution, versioning policy, semantic-token compatibility rules, component API compatibility, upgrade and migration processes, governance-rule distribution, visual regression, and release provenance. These belong primarily to platform-packaging and implementation work and are not decided here.

## Explicit non-decisions

This ADR does not select or freeze:

- final brand colors, typography, or spacing values;
- the final complete component library;
- Storybook or Figma integration;
- React Native or Expo implementation;
- native component APIs;
- an icon system or animations;
- final application CSP;
- a design-package registry or package-release strategy.

