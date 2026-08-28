<!--
File: docs/architecture/design-system.md
Purpose: Defines governance for reusable, accessible, themed web and native design foundations.
Related:
- docs/architecture/platform-principles.md
- docs/architecture/technology-decisions.md
- spikes/README.md
-->

# Design System

Omnilyzer products use one reusable, versioned design system with a shared semantic token source and governed component contracts. Products may theme and brand approved semantic roles; they must not create arbitrary parallel CSS systems.

## Tokens and styling

Tokens express intent such as surface, text, action, status, focus, spacing, typography, motion, and elevation rather than product-specific raw values. Raw colors must not be scattered through product code. Arbitrary spacing values require a documented design need and should become governed tokens when reused.

DTCG-compatible tokens, Style Dictionary transformations, constrained Tailwind, and Radix-based web primitives are **TO VALIDATE**. The spike must assess semantic naming, transformations, versioning, deprecation, theme completeness, type safety, output stability, and escape-hatch governance.

The shared token source may generate platform-specific outputs. Web and native UI implementations remain separate where interaction, navigation, performance, or operating-system conventions differ; common tokens, accessibility expectations, content language, domain concepts, and component intent do not require sharing every UI implementation.

## Responsive and accessible components

Responsive behavior is required and should be mobile-first where appropriate. Components must adapt by available space and content rather than device labels; use container queries where they improve component-level composition and have acceptable platform support. Touch targets, keyboard interaction, focus visibility, zoom/reflow, reduced motion, contrast, screen-reader semantics, and localization expansion are primitive-level requirements targeting WCAG 2.2 AA.

Components must expose accessible defaults, documented states, and testable contracts. Product code should compose primitives rather than reimplement interaction behavior. Accessibility exceptions require documented impact, mitigation, and approval.

## Branding and documentation

Product branding maps brand values onto stable semantic tokens without bypassing accessibility constraints. Tenant branding may be added later only through bounded, validated theme inputs with contrast and asset-safety controls.

Storybook or an equivalent remains a future candidate for component documentation, interaction examples, accessibility checks, and visual regression testing. It is not selected by this document.
