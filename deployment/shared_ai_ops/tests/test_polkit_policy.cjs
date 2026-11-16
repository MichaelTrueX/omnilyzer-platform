// Source-accurate behavioral checks for the restricted polkit rules.
const fs = require("node:fs");
const vm = require("node:vm");
const assert = require("node:assert/strict");
const path = require("node:path");
const rules = [];
const polkit = {
  Result: { YES: "YES" },
  addRule(fn) { rules.push(fn); },
};
const source = fs.readFileSync(path.join(__dirname, "..", "50-shared-ai-ops.rules"), "utf8");
vm.runInNewContext(source, { polkit });
assert.equal(rules.length, 1);
function decide(user, unit, verb = "start", actionId = "org.freedesktop.systemd1.manage-units") {
  return rules[0](
    { id: actionId, lookup(name) { return name === "unit" ? unit : name === "verb" ? verb : null; } },
    { user }
  );
}
for (const [user, unit] of [
  ["sumlaude-agent", "sumlaude-ai-ops@status.service"],
  ["sumlaude-agent", "sumlaude-ai-ops@cleanup-108-110.service"],
  ["omnilyzer-agent", "omnilyzer-ai-ops@status.service"],
]) assert.equal(decide(user, unit), "YES", user + " " + unit);
for (const [user, unit, verb] of [
  ["sumlaude-agent", "omnilyzer-ai-ops@status.service", "start"],
  ["omnilyzer-agent", "sumlaude-ai-ops@status.service", "start"],
  ["trusthansen", "sumlaude-ai-ops@status.service", "start"],
  ["sumlaude-agent", "ssh.service", "start"],
  ["sumlaude-agent", "sumlaude-ai-ops@status.service", "restart"],
  ["sumlaude-agent", "sumlaude-ai-ops@status.service", "stop"],
  ["sumlaude-agent", "sumlaude-ai-ops@../../shell.service", "start"],
  ["sumlaude-agent", "sumlaude-ai-ops@status.service;whoami", "start"],
  ["sumlaude-agent", "sumlaude-ai-ops@status.service\nother.service", "start"],
]) assert.equal(decide(user, unit, verb), undefined, user + " " + unit);
assert.equal(decide("sumlaude-agent", "sumlaude-ai-ops@status.service",
    "start", "org.freedesktop.systemd1.manage-unit-files"), undefined);
console.log("SHARED_AGENT_POLKIT_ALLOWLIST_POSITIVE_NEGATIVE_PASS");
