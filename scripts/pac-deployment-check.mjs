import { execFileSync } from "node:child_process";
import { mkdirSync, readFileSync, writeFileSync } from "node:fs";
import { basename, resolve } from "node:path";

const inputPath = process.argv[2] ?? "mock-infra/passed-example.json";
const policyPath = "policies/ai-lifecycle-governance.rego";
const reportDir = resolve(process.cwd(), "reports");
const resolvedInput = resolve(process.cwd(), inputPath);

function opaEval(query) {
  const output = execFileSync("opa", [
    "eval",
    "--format",
    "json",
    "--data",
    policyPath,
    "--input",
    inputPath,
    query
  ], { encoding: "utf8" });

  return JSON.parse(output).result?.[0]?.expressions?.[0]?.value;
}

function writeGithubSummary(markdown) {
  if (process.env.GITHUB_STEP_SUMMARY) {
    writeFileSync(process.env.GITHUB_STEP_SUMMARY, markdown, { flag: "a" });
  }
}

const evaluatedInput = JSON.parse(readFileSync(resolvedInput, "utf8"));
const violations = opaEval("data.ai.lifecycle.governance.deny") ?? [];
const allowed = opaEval("data.ai.lifecycle.governance.allow") === true;
const totalControls = 4;
const passedControls = totalControls - violations.length;
const complianceScore = Math.round((passedControls / totalControls) * 100);
const riskLevel = complianceScore >= 90 ? "Low" : complianceScore >= 70 ? "Medium" : "High";
const deploymentGate = allowed ? "PASS" : "FAIL";

const result = {
  input: inputPath,
  policy: policyPath,
  deployment_gate: deploymentGate,
  blocked_deployment: !allowed,
  compliance_score: complianceScore,
  risk_level: riskLevel,
  total_controls: totalControls,
  passed_controls: passedControls,
  failed_controls: violations.length,
  violations,
  evaluated_input: evaluatedInput,
  queries: {
    findings: "data.ai.lifecycle.governance.deny",
    deployment_gate: "data.ai.lifecycle.governance.allow"
  }
};

const violationRows = violations.length === 0
  ? "| None | None | None | None |\n"
  : violations.map((item) => `| ${item.id} | ${item.iso_control} | ${item.title} | ${item.reason} |`).join("\n") + "\n";

const markdown = `# Policy-as-Code Deployment Check

| Metric | Value |
| --- | --- |
| Input | \`${basename(inputPath)}\` |
| Policy | \`${policyPath}\` |
| Deployment Gate | **${deploymentGate}** |
| Compliance Score | ${complianceScore}% |
| Risk Level | ${riskLevel} |
| Passed Controls | ${passedControls}/${totalControls} |
| Failed Controls | ${violations.length}/${totalControls} |

## Violations

| Control | ISO Mapping | Rule | Remediation |
| --- | --- | --- | --- |
${violationRows}
## Evidence

- OPA query: \`data.ai.lifecycle.governance.allow\`
- Decision: \`${allowed}\`
- Report JSON: \`reports/pac-deployment-check.json\`
`;

mkdirSync(reportDir, { recursive: true });
writeFileSync(resolve(reportDir, "pac-deployment-check.json"), JSON.stringify(result, null, 2));
writeFileSync(resolve(reportDir, "pac-deployment-check.md"), markdown);
writeGithubSummary(markdown);

console.log(`Policy-as-Code deployment gate: ${deploymentGate}`);
console.log(`Input: ${inputPath}`);
console.log(`Compliance score: ${complianceScore}%`);
console.log(`Violations: ${violations.length}`);

if (!allowed) {
  console.error("Deployment blocked by OPA/Rego policy evaluation.");
  process.exit(1);
}

// import { execFileSync } from "node:child_process";
// import fs from "node:fs";

// const inputFile = process.argv[2];

// if (!inputFile) {
//   console.error("Usage: node scripts/pac-deployment-check.mjs <input-json>");
//   process.exit(1);
// }

// fs.mkdirSync("reports", { recursive: true });

// const result = execFileSync(
//   "opa",
//   [
//     "eval",
//     "--format",
//     "json",
//     "--data",
//     "policies/ai-lifecycle-governance.rego",
//     "--input",
//     inputFile,
//     "data.ai.lifecycle.governance.deny"
//   ],
//   { encoding: "utf8" }
// );

// const parsed = JSON.parse(result);
// const findings = parsed.result?.[0]?.expressions?.[0]?.value || [];

// const report = {
//   input: inputFile,
//   totalViolations: findings.length,
//   gateDecision: findings.length > 0 ? "BLOCKED" : "APPROVED",
//   findings
// };

// fs.writeFileSync("reports/compliance-report.json", JSON.stringify(report, null, 2));

// console.log("=====================================");
// console.log("AI Governance PaC Deployment Gate");
// console.log("=====================================");
// console.log(`Input: ${inputFile}`);
// console.log(`Violations: ${findings.length}`);
// console.log(`Gate Decision: ${report.gateDecision}`);

// for (const finding of findings) {
//   console.log("");
//   console.log(`❌ ${finding.id} | ${finding.iso_control}`);
//   console.log(`Resource: ${finding.resource_type} - ${finding.resource_name}`);
//   console.log(`Reason: ${finding.reason}`);
// }

// if (findings.length > 0) {
//   console.log("");
//   console.log("Deployment blocked. Fix policy violations before merge.");
//   process.exit(1);
// }

// console.log("");
// console.log("✅ Deployment approved. No policy violations found.");
// process.exit(0);
