export const platformReleaseVersion = "1.1.0";
export function normalizeWorkspaceLabel(value) { return String(value).trim(); }
export function workspaceSlug(value) {
  return normalizeWorkspaceLabel(value).toLowerCase().replace(/[^a-z0-9]+/g, "-").replace(/^-|-$/g, "");
}
