import { execFileSync } from "node:child_process";
import { readFileSync, mkdirSync, writeFileSync } from "node:fs";
import { dirname } from "node:path";
import { fileURLToPath } from "node:url";

const repoRoot = dirname(dirname(fileURLToPath(import.meta.url)));
const inputPath = process.argv[2] ?? "kubernetes/gatekeeper/examples/failing-ai-pod.yaml";
const policyPath = "kubernetes/gatekeeper/local-eval.rego";

function runOpa(query) {
  return execFileSync("opa", [
    "eval",
    "--format",
    "json",
    "--data",
    policyPath,
    "--input",
    inputPath,
    query
  ], {
    cwd: repoRoot,
    encoding: "utf8"
  });
}

function getValue(query) {
  const output = JSON.parse(runOpa(query));
  return output.result?.[0]?.expressions?.[0]?.value;
}

const allow = getValue("data.gatekeeper.ai.workload.allow");
const deny = getValue("data.gatekeeper.ai.workload.deny") ?? [];
const report = {
  input: inputPath,
  policy: policyPath,
  gatekeeper_decision: allow ? "PASS" : "FAIL",
  violations: deny
};

mkdirSync(`${repoRoot}/reports`, { recursive: true });
writeFileSync(`${repoRoot}/reports/gatekeeper-demo-check.json`, JSON.stringify(report, null, 2));
writeFileSync(`${repoRoot}/reports/gatekeeper-demo-check.md`, [
  "# OPA Gatekeeper AI Workload Demo",
  "",
  `- Input: \`${inputPath}\``,
  `- Policy: \`${policyPath}\``,
  `- Decision: **${report.gatekeeper_decision}**`,
  `- Violations: **${deny.length}**`,
  "",
  ...deny.map((finding) => `- **${finding.id}**: ${finding.message}`)
].join("\n"));

console.log(`OPA Gatekeeper AI workload demo: ${report.gatekeeper_decision}`);
console.log(`Input: ${inputPath}`);
console.log(`Violations: ${deny.length}`);

for (const finding of deny) {
  console.log(`- ${finding.id}: ${finding.message}`);
}

if (!allow) {
  process.exit(1);
}
