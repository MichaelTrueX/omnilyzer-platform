import { platformReleaseVersion, normalizeWorkspaceLabel, workspaceSlug } from "@omnilyzer/platform-web-contract";
import webPackage from "./node_modules/@omnilyzer/platform-web-contract/package.json" with { type: "json" };
import governancePackage from "./node_modules/@omnilyzer/design-governance/package.json" with { type: "json" };
if (platformReleaseVersion !== process.env.EXPECTED_PLATFORM_VERSION) throw new Error("web release mismatch");
if (normalizeWorkspaceLabel("  Beta Workspace  ") !== "Beta Workspace") throw new Error("baseline behavior changed");
if (workspaceSlug("  Beta Workspace  ") !== "beta-workspace") throw new Error("new API unavailable");
if (webPackage.version !== process.env.EXPECTED_PLATFORM_VERSION) throw new Error("web installed version mismatch");
if (governancePackage.version !== process.env.EXPECTED_PLATFORM_VERSION) throw new Error("governance installed version mismatch");
console.log(`web=${webPackage.version} governance=${governancePackage.version}`);
