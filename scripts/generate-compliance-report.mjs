import { execFileSync } from "node:child_process";
import { mkdirSync, readFileSync, writeFileSync } from "node:fs";
import { basename, resolve } from "node:path";

const inputPath = process.argv[2] ?? "mock-infra/failed-example.json";
const resolvedInput = resolve(process.cwd(), inputPath);
const reportDir = resolve(process.cwd(), "reports");

function opaEval(query) {
  const output = execFileSync("opa", [
    "eval",
    "--format",
    "json",
    "--data",
    "policies/ai-lifecycle-governance.rego",
    "--input",
    inputPath,
    query
  ], { encoding: "utf8" });

  return JSON.parse(output).result?.[0]?.expressions?.[0]?.value;
}

const input = JSON.parse(readFileSync(resolvedInput, "utf8"));
const violations = opaEval("data.ai.lifecycle.governance.deny") ?? [];
const allowed = opaEval("data.ai.lifecycle.governance.allow") === true;
const totalControls = 4;
const passedControls = totalControls - violations.length;
const complianceScore = Math.round((passedControls / totalControls) * 100);
const riskLevel = complianceScore >= 90 ? "Low" : complianceScore >= 70 ? "Medium" : "High";

const summary = {
  input: basename(inputPath),
  deployment_gate: allowed ? "PASS" : "FAIL",
  compliance_score: complianceScore,
  risk_level: riskLevel,
  total_controls: totalControls,
  passed_controls: passedControls,
  failed_controls: violations.length,
  violations,
  evaluated_input: input
};

const findings = violations.length === 0
  ? "No violations detected. Deployment gate passed."
  : violations.map((item) => `- ${item.id} / ${item.iso}: ${item.rule}\n  - Remediation: ${item.recommendation}`).join("\n");

const markdown = `# AI Governance Compliance Report

Input: \`${summary.input}\`

## Summary

| Metric | Value |
| --- | --- |
| Deployment Gate | ${summary.deployment_gate} |
| Compliance Score | ${summary.compliance_score}% |
| Risk Level | ${summary.risk_level} |
| Total Controls | ${summary.total_controls} |
| Passed Controls | ${summary.passed_controls} |
| Failed Controls | ${summary.failed_controls} |

## Violations and Remediation

${findings}

## Audit Evidence

- Policy engine: Open Policy Agent
- Policy file: \`policies/ai-lifecycle-governance.rego\`
- Evaluated input: \`${inputPath}\`
- Query: \`data.ai.lifecycle.governance.deny\`
`;

mkdirSync(reportDir, { recursive: true });
writeFileSync(resolve(reportDir, "compliance-report.json"), JSON.stringify(summary, null, 2));
writeFileSync(resolve(reportDir, "compliance-report.md"), markdown);

console.log(`Generated reports/compliance-report.md for ${summary.input}`);
console.log(`Deployment gate: ${summary.deployment_gate}`);
console.log(`Compliance score: ${summary.compliance_score}%`);
