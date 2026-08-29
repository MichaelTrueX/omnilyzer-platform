import { platformReleaseVersion, normalizeWorkspaceLabel } from "@omnilyzer/platform-web-contract";
import webPackage from "./node_modules/@omnilyzer/platform-web-contract/package.json" with { type: "json" };
import governancePackage from "./node_modules/@omnilyzer/design-governance/package.json" with { type: "json" };
if (platformReleaseVersion !== process.env.EXPECTED_PLATFORM_VERSION) throw new Error("web release mismatch");
if (normalizeWorkspaceLabel("  Alpha Workspace  ") !== "Alpha Workspace") throw new Error("baseline behavior changed");
if (webPackage.version !== process.env.EXPECTED_PLATFORM_VERSION) throw new Error("web installed version mismatch");
if (governancePackage.version !== process.env.EXPECTED_PLATFORM_VERSION) throw new Error("governance installed version mismatch");
console.log(`web=${webPackage.version} governance=${governancePackage.version}`);
