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
  : violations.map((item) => `| ${item.id} | ${item.iso} | ${item.rule} | ${item.recommendation} |`).join("\n") + "\n";

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
