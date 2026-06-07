import { useMemo, useState } from "react";

type ScenarioKey = "failed" | "passed";

type ResourceFinding = {
  type: "S3 Bucket" | "Bedrock App" | "IAM Role";
  name: string;
  field: string;
  currentValue: string;
  issue: string;
};

type InfrastructureInput = {
  s3: { encryption: boolean; public_access: boolean };
  bedrock: { logging: boolean; guardrails: boolean };
  iam: { policy: string };
  resources: {
    s3Buckets: Array<{ name: string; encryption: boolean; public_access: boolean }>;
    bedrockApps: Array<{ name: string; logging: boolean; guardrails: boolean }>;
    iamRoles: Array<{ name: string; policy: string }>;
  };
};

type PolicyRule = {
  id: string;
  iso: string;
  domain: string;
  policy: string;
  rule: string;
  resource: "s3" | "bedrock" | "iam";
  severity: "Critical" | "High";
  recommendation: string;
  rego: string;
  evaluate: (input: InfrastructureInput) => boolean;
  getFindings: (input: InfrastructureInput) => ResourceFinding[];
  violation: object;
};

const scenarios: Record<ScenarioKey, { label: string; filename: string; input: InfrastructureInput }> = {
  failed: {
    label: "Failed Example",
    filename: "mock-infra/failed-example.json",
    input: {
      s3: { encryption: false, public_access: true },
      bedrock: { logging: false, guardrails: false },
      iam: { policy: "*" },
      resources: {
        s3Buckets: [
          { name: "aigov-training-data-prod", encryption: false, public_access: false },
          { name: "aigov-prompt-logs-prod", encryption: false, public_access: true },
          { name: "aigov-model-artifacts", encryption: true, public_access: false },
          { name: "aigov-evidence-vault", encryption: true, public_access: false }
        ],
        bedrockApps: [
          { name: "claims-assistant-bedrock", logging: false, guardrails: false },
          { name: "customer-support-rag", logging: false, guardrails: true },
          { name: "internal-policy-bot", logging: true, guardrails: true }
        ],
        iamRoles: [
          { name: "BedrockAppExecutionRole", policy: "*" },
          { name: "SageMakerNotebookRole", policy: "*" },
          { name: "AIGovernanceReadOnlyRole", policy: "least-privilege" },
          { name: "CloudWatchEvidenceRole", policy: "least-privilege" },
          { name: "MacieClassificationRole", policy: "least-privilege" },
          { name: "SecurityHubAuditRole", policy: "least-privilege" }
        ]
      }
    }
  },
  passed: {
    label: "Passed Example",
    filename: "mock-infra/passed-example.json",
    input: {
      s3: { encryption: true, public_access: false },
      bedrock: { logging: true, guardrails: true },
      iam: { policy: "least-privilege" },
      resources: {
        s3Buckets: [
          { name: "aigov-training-data-prod", encryption: true, public_access: false },
          { name: "aigov-prompt-logs-prod", encryption: true, public_access: false },
          { name: "aigov-model-artifacts", encryption: true, public_access: false },
          { name: "aigov-evidence-vault", encryption: true, public_access: false }
        ],
        bedrockApps: [
          { name: "claims-assistant-bedrock", logging: true, guardrails: true },
          { name: "customer-support-rag", logging: true, guardrails: true },
          { name: "internal-policy-bot", logging: true, guardrails: true }
        ],
        iamRoles: [
          { name: "BedrockAppExecutionRole", policy: "least-privilege" },
          { name: "SageMakerNotebookRole", policy: "least-privilege" },
          { name: "AIGovernanceReadOnlyRole", policy: "least-privilege" },
          { name: "CloudWatchEvidenceRole", policy: "least-privilege" },
          { name: "MacieClassificationRole", policy: "least-privilege" },
          { name: "SecurityHubAuditRole", policy: "least-privilege" }
        ]
      }
    }
  }
};

const policyRules: PolicyRule[] = [
  {
    id: "DG-001",
    iso: "ISO/IEC 42001 A.6.2",
    domain: "Data Governance",
    policy: "Data Privacy Policy",
    rule: "S3 buckets must use encryption.",
    resource: "s3",
    severity: "Critical",
    recommendation: "Enable S3 default encryption with AWS KMS.",
    violation: { s3: { encryption: false } },
    evaluate: (input) => input.s3.encryption === true,
    getFindings: (input) => input.resources.s3Buckets
      .filter((bucket) => !bucket.encryption)
      .map((bucket) => ({ type: "S3 Bucket", name: bucket.name, field: "encryption", currentValue: String(bucket.encryption), issue: "Bucket encryption is disabled" })),
    rego: `deny contains msg if {
  input.s3.encryption == false
  msg := {
    "id": "DG-001",
    "iso": "ISO/IEC 42001 A.6.2",
    "rule": "S3 buckets must use encryption."
  }
}`
  },
  {
    id: "TR-001",
    iso: "ISO/IEC 42001 A.7.2",
    domain: "Transparency",
    policy: "Transparency Policy",
    rule: "Bedrock invocation logging must be enabled.",
    resource: "bedrock",
    severity: "High",
    recommendation: "Enable Bedrock invocation logging to CloudWatch Logs.",
    violation: { bedrock: { logging: false } },
    evaluate: (input) => input.bedrock.logging === true,
    getFindings: (input) => input.resources.bedrockApps
      .filter((app) => !app.logging)
      .map((app) => ({ type: "Bedrock App", name: app.name, field: "logging", currentValue: String(app.logging), issue: "Invocation logging is disabled" })),
    rego: `deny contains msg if {
  input.bedrock.logging == false
  msg := {
    "id": "TR-001",
    "iso": "ISO/IEC 42001 A.7.2",
    "rule": "Bedrock invocation logging must be enabled."
  }
}`
  },
  {
    id: "RAI-001",
    iso: "ISO/IEC 42001 A.8.4",
    domain: "Responsible AI",
    policy: "Responsible AI Policy",
    rule: "Bedrock Guardrails must be enabled.",
    resource: "bedrock",
    severity: "High",
    recommendation: "Attach an approved Bedrock Guardrail before deployment.",
    violation: { bedrock: { guardrails: false } },
    evaluate: (input) => input.bedrock.guardrails === true,
    getFindings: (input) => input.resources.bedrockApps
      .filter((app) => !app.guardrails)
      .map((app) => ({ type: "Bedrock App", name: app.name, field: "guardrails", currentValue: String(app.guardrails), issue: "Bedrock Guardrails are not attached" })),
    rego: `deny contains msg if {
  input.bedrock.guardrails == false
  msg := {
    "id": "RAI-001",
    "iso": "ISO/IEC 42001 A.8.4",
    "rule": "Bedrock Guardrails must be enabled."
  }
}`
  },
  {
    id: "SEC-001",
    iso: "Security Control",
    domain: "AI Security",
    policy: "AI Security Policy",
    rule: "IAM policies cannot use wildcard permissions.",
    resource: "iam",
    severity: "Critical",
    recommendation: "Replace wildcard permissions with scoped least-privilege IAM statements.",
    violation: { iam: { policy: "*" } },
    evaluate: (input) => input.iam.policy !== "*",
    getFindings: (input) => input.resources.iamRoles
      .filter((role) => role.policy === "*")
      .map((role) => ({ type: "IAM Role", name: role.name, field: "policy", currentValue: role.policy, issue: "Wildcard permissions are allowed" })),
    rego: `deny contains msg if {
  input.iam.policy == "*"
  msg := {
    "id": "SEC-001",
    "iso": "Security Control",
    "rule": "IAM policies cannot use wildcard permissions."
  }
}`
  }
];

const nav = ["Dashboard", "Policy Framework", "Policies (OPA)", "AI Lifecycle", "CI/CD Pipeline", "Compliance Report"];
const lifecycle = ["Scoping", "Data Collection", "Training", "Validation", "Deployment", "Monitoring", "Retirement"];

function evaluatePolicies(input: InfrastructureInput) {
  return policyRules.map((rule) => {
    const findings = rule.getFindings(input);
    return { ...rule, findings, passed: rule.evaluate(input) && findings.length === 0 };
  });
}

function StatCard({ title, value, subtitle, icon, tone }: { title: string; value: string; subtitle: string; icon: string; tone: string }) {
  return (
    <section className="stat-card">
      <div className={`icon-box ${tone}`}>{icon}</div>
      <div>
        <p>{title}</p>
        <strong>{value}</strong>
        <span>{subtitle}</span>
      </div>
    </section>
  );
}

function Donut({ score, failed, passed }: { score: number; failed: number; passed: number }) {
  return (
    <div className="donut-wrap">
      <div className="donut" style={{ background: `conic-gradient(#22c55e 0 ${score}%, #fb4d57 ${score}% 100%)` }}><span>{score}%<small>Overall</small></span></div>
      <div className="legend">
        <p><i className="dot green-dot" />Passed<br /><strong>{passed} ({score}%)</strong></p>
        <p><i className="dot red-dot" />Failed<br /><strong>{failed} ({100 - score}%)</strong></p>
        <p><i className="dot gray-dot" />Not Applicable<br /><strong>0 (0%)</strong></p>
      </div>
    </div>
  );
}

function TrendChart({ score }: { score: number }) {
  const endY = 226 - (score / 100) * 186;
  return (
    <div className="trend-chart" aria-label="Compliance score trend chart">
      <svg viewBox="0 0 520 280" role="img">
        <defs><linearGradient id="area" x1="0" x2="0" y1="0" y2="1"><stop offset="0%" stopColor="#8b5cf6" stopOpacity="0.58" /><stop offset="100%" stopColor="#8b5cf6" stopOpacity="0.05" /></linearGradient></defs>
        <g className="grid-lines"><line x1="34" x2="500" y1="40" y2="40" /><line x1="34" x2="500" y1="102" y2="102" /><line x1="34" x2="500" y1="164" y2="164" /><line x1="34" x2="500" y1="226" y2="226" /></g>
        <path className="area" d={`M34 186 L90 170 L146 176 L202 160 L258 154 L314 138 L370 126 L426 98 L500 ${endY} L500 250 L34 250 Z`} />
        <path className="line" d={`M34 186 L90 170 L146 176 L202 160 L258 154 L314 138 L370 126 L426 98 L500 ${endY}`} />
        <circle cx="500" cy={endY} r="7" className="point" />
        <text x="30" y="44">100%</text><text x="30" y="106">75%</text><text x="30" y="168">50%</text><text x="30" y="230">25%</text><text x="55" y="270">Apr 20</text><text x="184" y="270">Apr 27</text><text x="310" y="270">May 4</text><text x="428" y="270">Today</text>
      </svg>
      <div className="tooltip-card">Current<br /><strong>{score}%</strong></div>
    </div>
  );
}

function App() {
  const [scenarioKey, setScenarioKey] = useState<ScenarioKey>("failed");
  const [selectedRuleId, setSelectedRuleId] = useState(policyRules[0].id);
  const [evidenceFocus, setEvidenceFocus] = useState(false);
  const scenario = scenarios[scenarioKey];
  const results = useMemo(() => evaluatePolicies(scenario.input), [scenario.input]);
  const failed = results.filter((rule) => !rule.passed);
  const passed = results.length - failed.length;
  const score = Math.round((passed / results.length) * 100);
  const blocked = failed.length > 0;
  const selectedRule = results.find((rule) => rule.id === selectedRuleId) ?? results[0];
  const affectedResources = selectedRule.findings;
  const totalAffectedResources = failed.reduce((count, rule) => count + rule.findings.length, 0);
  const resourceSummary = [
    { label: "S3 Buckets", value: scenario.input.resources.s3Buckets.length, compliant: scenario.input.resources.s3Buckets.filter((bucket) => bucket.encryption).length, nonCompliant: scenario.input.resources.s3Buckets.filter((bucket) => !bucket.encryption).length, icon: "□", tone: "green" },
    { label: "Bedrock Apps", value: scenario.input.resources.bedrockApps.length, compliant: scenario.input.resources.bedrockApps.filter((app) => app.logging && app.guardrails).length, nonCompliant: scenario.input.resources.bedrockApps.filter((app) => !app.logging || !app.guardrails).length, icon: "◇", tone: "purple" },
    { label: "IAM Roles", value: scenario.input.resources.iamRoles.length, compliant: scenario.input.resources.iamRoles.filter((role) => role.policy !== "*").length, nonCompliant: scenario.input.resources.iamRoles.filter((role) => role.policy === "*").length, icon: "▣", tone: "amber" },
    { label: "OPA Rules", value: results.length, compliant: passed, nonCompliant: failed.length, icon: "△", tone: "blue" }
  ];

  return (
    <div className="dashboard-shell">
      <aside className="sidebar">
        <div className="brand"><div className="shield">▰</div><div><strong>AI Governance</strong><span>Policy-as-Code Gateway</span></div></div>
        <nav>{nav.map((item, index) => <a className={index === 0 ? "active" : ""} key={item}><span>{["▦", "▧", "⌁", "◌", "⌬", "▤", "▣", "⚙"][index]}</span>{item}</a>)}</nav>
        <div className="sidebar-footer"><div className="env"><span>SCENARIO</span><strong><i />{scenario.label}</strong></div></div>
      </aside>

      <main className="main-panel">
        <header className="topbar">
          <div><h1>Dashboard</h1><p>Interactive OPA/Rego evaluation for {scenario.filename}</p></div>
          <div className="top-actions">
            <label className="environment"><span>Mock Infrastructure</span><select value={scenarioKey} onChange={(event) => { setScenarioKey(event.target.value as ScenarioKey); setEvidenceFocus(false); }}><option value="failed">Failed Example</option><option value="passed">Passed Example</option></select></label>
            <button className="bell">♧<sup>{failed.length}</sup></button>
            <div className="standard"><span>▣</span>ISO/IEC 42001:2023 <b className={blocked ? "not-compliant" : ""}>{blocked ? "Blocked" : "Compliant"}</b></div>
          </div>
        </header>

        <section className="stats-grid">
          <StatCard title="Total Controls" value={`${results.length}`} subtitle="OPA/Rego Controls" icon="▤" tone="blue" />
          <StatCard title="Passed" value={`${passed}`} subtitle={`${score}% of controls`} icon="✓" tone="green" />
          <StatCard title="Failed" value={`${failed.length}`} subtitle={`${100 - score}% of controls`} icon="!" tone="red" />
          <StatCard title="Violations" value={`${totalAffectedResources}`} subtitle={`Across ${new Set(failed.flatMap((rule) => rule.findings.map((finding) => finding.type))).size} resource types`} icon="△" tone="amber" />
          <section className="score-card"><div><p>Compliance Score</p><strong>{score}%</strong><span>{blocked ? "Needs Remediation" : "Ready for Deployment"}</span></div><div className="mini-ring" style={{ background: `conic-gradient(#8b5cf6 0 ${score}%, #243247 ${score}% 100%)` }}><span>{score}%</span></div></section>
        </section>

        <section className={blocked ? "blocked-banner" : "blocked-banner approved-banner"}><div className="banner-icon">{blocked ? "!" : "✓"}</div><div><strong>Deployment Status: <span>{blocked ? "BLOCKED" : "APPROVED"}</span></strong><p>{blocked ? `${failed.length} control(s) failing across ${totalAffectedResources} named resource(s). Remediate before deployment.` : "All OPA policy checks passed for this infrastructure input."}</p></div><button onClick={() => { setSelectedRuleId(failed[0]?.id ?? results[0].id); setEvidenceFocus(true); }}>{blocked ? "View Violations" : "View Evidence"} →</button></section>

        <section className="content-grid top-content">
          <article className="panel policy-panel"><h2>Policy Status <span>(live evaluation)</span></h2><div className="policy-table"><div className="table-head"><span>CONTROL ID</span><span>CONTROL NAME</span><span>STATUS</span><span>VIOLATIONS</span><span>SEVERITY</span></div>{results.map((control) => <button className={`table-row row-button ${selectedRuleId === control.id ? "selected-row" : ""}`} key={control.id} onClick={() => { setSelectedRuleId(control.id); setEvidenceFocus(false); }}><strong>{control.id}</strong><p>{control.domain}</p><span className={control.passed ? "pass" : "fail"}>{control.passed ? "✓ Passed" : "× Failed"}</span><em>{control.findings.length}</em><b className={`pill ${control.passed ? "low" : control.severity.toLowerCase()}`}>{control.passed ? "Low" : control.severity}</b></button>)}</div><a>{scenario.filename}</a></article>
          <article className="panel"><h2>Compliance Score Trend <span>(scenario)</span></h2><TrendChart score={score} /></article>
          <article className="panel breakdown"><h2>Compliance Score Breakdown</h2><Donut score={score} failed={failed.length} passed={passed} /><a>Pass/fail values come from policy evaluation →</a></article>
        </section>

        <section className="content-grid middle-content">
          <article className="panel rule-detail"><h2>Selected OPA Rule <span>{selectedRule.id}</span></h2><div className="rule-meta"><b>{selectedRule.iso}</b><b>{selectedRule.policy}</b><b className={selectedRule.passed ? "pass" : "fail"}>{selectedRule.passed ? "PASS" : "FAIL"}</b></div><p>{selectedRule.rule}</p><pre>{selectedRule.rego}</pre></article>
          <article className="panel input-panel"><h2>Evaluated Mock Infrastructure</h2><pre>{JSON.stringify(scenario.input, null, 2)}</pre></article>
          <article className={`panel input-panel ${evidenceFocus ? "evidence-focus" : ""}`}><h2>{selectedRule.passed ? "Audit Evidence" : "Violation + Remediation"}</h2>{selectedRule.passed ? <pre>{JSON.stringify({ result: "allow", evidence: `${selectedRule.id} passed for ${scenario.filename}` }, null, 2)}</pre> : <div className="finding-list">{affectedResources.map((finding) => <div className="finding-card" key={`${finding.type}-${finding.name}-${finding.field}`}><strong>{finding.name}</strong><span>{finding.type}</span><p>{finding.issue}</p><code>{finding.field}: {finding.currentValue}</code></div>)}<pre>{JSON.stringify({ violation: selectedRule.violation, recommendation: selectedRule.recommendation }, null, 2)}</pre></div>}</article>
        </section>

        <section className="content-grid bottom-content">
          <article className="panel infra"><div className="panel-title"><h2>AWS Infrastructure Overview</h2><a>Derived from mock input →</a></div><div className="resource-grid">{resourceSummary.map((resource) => <div className="resource-card" key={resource.label}><div className={`icon-box ${resource.tone}`}>{resource.icon}</div><p>{resource.label}</p><strong>{resource.value}</strong><span className="good">{resource.compliant} Compliant</span><span className="bad">{resource.nonCompliant} Non-Compliant</span></div>)}</div></article>
          <article className="panel runs"><div className="panel-title"><h2>Recent Pipeline Runs</h2><a>OPA gate →</a></div><div className="run-row"><i className={blocked ? "ko" : "ok"}>×</i><div><strong>{scenarioKey === "failed" ? "feature/ai-infra-update" : "main"}</strong><span className={blocked ? "fail-tag" : "pass-tag"}>{blocked ? "Failed" : "Passed"}</span><small>{failed.length} violations found</small></div><p>Current scan<br /><b>OPA/Rego</b></p></div><div className="run-row"><i className="ok">×</i><div><strong>fix/s3-encryption</strong><span className="pass-tag">Passed</span><small>0 violations</small></div><p>Previous scan<br /><b>1m 18s</b></p></div><a>GitHub Actions uses the same allow query →</a></article>
          <article className="panel actions"><h2>Quick Actions</h2><button className="action-button" onClick={() => { setScenarioKey(scenarioKey === "failed" ? "passed" : "failed"); setEvidenceFocus(false); }}><span className="icon-box blue">▶</span><div><strong>Toggle Scenario</strong><small>Switch pass/fail input</small></div></button><button className="action-button" onClick={() => { setSelectedRuleId(failed[0]?.id ?? results[0].id); setEvidenceFocus(true); }}><span className="icon-box amber">⌬</span><div><strong>View Evidence</strong><small>Show named failing resources</small></div></button></article>
        </section>
      </main>
    </div>
  );
}

export default App;
