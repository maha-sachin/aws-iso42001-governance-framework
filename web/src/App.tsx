import { useMemo, useState } from "react";

type ScenarioKey = "failed" | "passed";
type PageKey = "Dashboard" | "Policy Framework" | "Policies (OPA)" | "AI Lifecycle" | "CI/CD Pipeline" | "Compliance Report";

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

const nav: PageKey[] = ["Dashboard", "Policy Framework", "Policies (OPA)", "AI Lifecycle", "CI/CD Pipeline", "Compliance Report"];
const lifecycle = ["Scoping", "Data Collection", "Training", "Validation", "Deployment", "Monitoring", "Retirement"];
const lifecycleStages = [
  {
    stage: "Problem Definition & Scoping",
    status: "passed",
    goal: "Define the AI use case and classify risk before work starts.",
    gates: [
      ["LC-01-A", "Risk Tier Classification", "Must declare risk_tier 0-3. Tier-0 projects are blocked.", "passed"],
      ["LC-01-B", "Executive Sponsor Gate", "Tier-1 high-risk projects require executive approval.", "passed"]
    ],
    aws: "IAM, Service Catalog, AWS Organizations",
    policies: "CP-001, CP-002"
  },
  {
    stage: "Data Collection & Governance",
    status: "failed",
    goal: "Ingest training data safely with encryption, lineage, and bias screening.",
    gates: [
      ["LC-02-A", "S3 CMK Encryption Gate", "ai-training-data-prod uses AWS-managed KMS instead of a customer-managed key.", "failed"],
      ["LC-02-B", "Data Lineage Documentation", "Dataset source, license, and collection date are tracked.", "passed"],
      ["LC-02-C", "Bias Screening Gate", "Dataset bias_score is below or equal to 0.15.", "passed"]
    ],
    aws: "S3, AWS Glue, Lake Formation, KMS",
    policies: "OP-001, CP-003"
  },
  {
    stage: "Model Training & Experimentation",
    status: "failed",
    goal: "Train models with reproducibility, metrics, artifact tracking, and tags.",
    gates: [
      ["LC-03-A", "Experiment Tracking", "Training metrics are logged to SageMaker Experiments.", "passed"],
      ["LC-03-B", "Artifact Encryption", "Model artifacts in S3 use customer-managed KMS keys.", "passed"],
      ["LC-03-C", "Resource Tagging Gate", "Some training jobs are missing project, cost_center, and data_classification tags.", "failed"]
    ],
    aws: "SageMaker, ECR, CloudWatch",
    policies: "OP-004"
  },
  {
    stage: "Model Evaluation & Bias Assessment",
    status: "passed",
    goal: "Validate model performance and fairness before approval.",
    gates: [
      ["LC-04-A", "Minimum Accuracy Gate", "Model accuracy is greater than or equal to the 0.85 baseline.", "passed"],
      ["LC-04-B", "Bias Report Gate", "SageMaker Clarify report exists and fairness ratio is within range.", "passed"]
    ],
    aws: "SageMaker Clarify, Model Monitor",
    policies: "CP-002, CP-003, OP-004"
  },
  {
    stage: "Model Registration & Approval",
    status: "passed",
    goal: "Register model metadata and capture required approvals.",
    gates: [
      ["LC-05-A", "Registry Metadata Completeness", "Model name, version, training data hash, bias report URI, and approver are present.", "passed"],
      ["LC-05-B", "Dual Approval Gate", "Tier-1 models require MLOps Lead and AI Risk Officer approvals.", "passed"]
    ],
    aws: "SageMaker Model Registry, IAM, SNS",
    policies: "CP-002, OP-004"
  },
  {
    stage: "Production Deployment",
    status: "failed",
    goal: "Deploy to AWS only after ISO 42001 controls pass.",
    gates: [
      ["LC-06-A", "A.6.2 Data Governance", "ai-training-data-prod violates S3 customer-managed KMS encryption.", "failed"],
      ["LC-06-B", "A.7.2 Transparency", "internal-summarizer has Bedrock invocation logging disabled.", "failed"],
      ["LC-06-C", "A.8.4 Responsible AI", "code-assistant has Bedrock Guardrails disabled.", "failed"],
      ["LC-06-D", "IAM Least Privilege", "Production roles are scoped to approved AI deployment permissions.", "passed"]
    ],
    aws: "Bedrock, SageMaker Endpoints, S3, CloudWatch, KMS",
    policies: "OP-001, OP-002, OP-003"
  },
  {
    stage: "Runtime Monitoring & Drift Detection",
    status: "passed",
    goal: "Detect model degradation and operational risk in production.",
    gates: [
      ["LC-07-A", "Monitoring Schedule Gate", "SageMaker Model Monitor is enabled for all endpoints.", "passed"],
      ["LC-07-B", "Drift Alert Gate", "Drift thresholds and SNS alerts are configured.", "passed"]
    ],
    aws: "SageMaker Model Monitor, CloudWatch, CloudTrail",
    policies: "CP-001, OP-002"
  },
  {
    stage: "Model Retirement & Data Purge",
    status: "passed",
    goal: "Decommission models safely and preserve audit trails.",
    gates: [
      ["LC-08-A", "Retirement Approval Gate", "AI System Owner approval and 90-day notice are required.", "passed"],
      ["LC-08-B", "Audit Trail Preservation", "Invocation logs are archived for 24 months before deletion.", "passed"]
    ],
    aws: "SageMaker, S3, KMS, CloudTrail",
    policies: "CP-003, OP-001"
  }
];

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

function lifecycleGateRego(id: string) {
  const snippets: Record<string, string> = {
    "LC-01-A": `package lifecycle.scoping

deny[msg] {
  not input.ai_project.risk_tier
  msg := "LC-01-A: risk_tier must be declared before provisioning"
}

deny[msg] {
  input.ai_project.risk_tier == 0
  msg := "LC-01-A: Tier-0 projects are blocked"
}`,
    "LC-01-B": `package lifecycle.scoping

deny[msg] {
  input.ai_project.risk_tier == 1
  not input.ai_project.executive_sponsor
  msg := "LC-01-B: Tier-1 projects require executive_sponsor"
}`,
    "LC-02-A": `package lifecycle.data_governance

deny[msg] {
  bucket := input.s3_buckets[_]
  bucket.name == "ai-training-data-prod"
  bucket.encryption.key_type != "customer_managed"
  msg := "LC-02-A: training data bucket must use customer-managed KMS"
}`,
    "LC-03-C": `package lifecycle.training

deny[msg] {
  job := input.training_jobs[_]
  missing := {"project", "cost_center", "data_classification"} - object.keys(job.tags)
  count(missing) > 0
  msg := sprintf("LC-03-C: training job %s missing required tags", [job.name])
}`,
    "LC-06-A": policyRules[0].rego,
    "LC-06-B": policyRules[1].rego,
    "LC-06-C": policyRules[2].rego,
    "LC-06-D": policyRules[3].rego
  };

  return snippets[id] ?? `package lifecycle.governance

allow if {
  input.lifecycle_gate["${id}"].status == "passed"
}`;
}

function AppPage({
  page,
  scenario,
  results,
  selectedRule,
  setSelectedRuleId
}: {
  page: PageKey;
  scenario: Record<ScenarioKey, { label: string; filename: string; input: InfrastructureInput }>[ScenarioKey];
  results: ReturnType<typeof evaluatePolicies>;
  selectedRule: ReturnType<typeof evaluatePolicies>[number];
  setSelectedRuleId: (id: string) => void;
}) {
  const [expandedLifecycleStage, setExpandedLifecycleStage] = useState(0);

  if (page === "Policy Framework") {
    return (
      <>
        <header className="topbar"><div><h1>Policy Framework</h1><p>Corporate AI governance policies mapped to AWS controls</p></div></header>
        <section className="content-grid middle-content">
          {[
            ["Responsible AI Policy", "AI systems must use safety controls, harmful content generation must be mitigated, and human oversight is required for high-risk use cases.", "Amazon Bedrock Guardrails"],
            ["Data Privacy Policy", "Data must be encrypted, public access prohibited, and sensitive data protected.", "Amazon S3, AWS KMS"],
            ["Transparency Policy", "AI interactions must be auditable and logging must be enabled.", "Bedrock Invocation Logging, CloudWatch Logs"],
            ["AI Security Policy", "Least privilege access, no wildcard permissions, and security monitoring are required.", "IAM, CloudTrail, Security Hub"]
          ].map(([title, body, mapping]) => (
            <article className="panel rule-detail" key={title}>
              <h2>{title}</h2>
              <p>{body}</p>
              <div className="rule-meta"><b>AWS Mapping</b><b>{mapping}</b></div>
            </article>
          ))}
        </section>
      </>
    );
  }

  if (page === "Policies (OPA)") {
    return (
      <>
        <header className="topbar"><div><h1>Policies (OPA)</h1><p>Open Policy Agent rules enforcing ISO 42001 controls</p></div></header>
        <section className="content-grid middle-content">
          <article className="panel policy-panel">
            <h2>OPA/Rego Controls</h2>
            <div className="policy-table">
              <div className="table-head"><span>CONTROL ID</span><span>CONTROL NAME</span><span>STATUS</span><span>VIOLATIONS</span><span>SEVERITY</span></div>
              {results.map((control) => (
                <button className={`table-row row-button ${selectedRule.id === control.id ? "selected-row" : ""}`} key={control.id} onClick={() => setSelectedRuleId(control.id)}>
                  <strong>{control.id}</strong><p>{control.domain}</p><span className={control.passed ? "pass" : "fail"}>{control.passed ? "✓ Passed" : "× Failed"}</span><em>{control.findings.length}</em><b className={`pill ${control.passed ? "low" : control.severity.toLowerCase()}`}>{control.passed ? "Low" : control.severity}</b>
                </button>
              ))}
            </div>
          </article>
          <article className="panel rule-detail">
            <h2>Selected Rego Rule <span>{selectedRule.id}</span></h2>
            <div className="rule-meta"><b>{selectedRule.iso}</b><b>{selectedRule.policy}</b></div>
            <p>{selectedRule.rule}</p>
            <pre>{selectedRule.rego}</pre>
          </article>
          <article className="panel input-panel">
            <h2>Evaluated Input</h2>
            <pre>{JSON.stringify(scenario.input, null, 2)}</pre>
          </article>
        </section>
      </>
    );
  }

  if (page === "AI Lifecycle") {
    const totalGates = lifecycleStages.reduce((count, stage) => count + stage.gates.length, 0);
    const failingGates = lifecycleStages.reduce((count, stage) => count + stage.gates.filter((gate) => gate[3] === "failed").length, 0);
    const passingGates = totalGates - failingGates;
    const expandedStage = lifecycleStages[expandedLifecycleStage];

    return (
      <>
        <header className="lifecycle-header"><div><h1>AI Lifecycle PaC</h1><p>Policy-as-Code enforcement across the full AI/ML lifecycle on AWS</p></div></header>

        <section className="lifecycle-kpis">
          <article><span>Lifecycle Stages</span><strong>{lifecycleStages.length}</strong><p>End-to-end coverage</p><i>⌬</i></article>
          <article><span>PaC Gates</span><strong>{totalGates}</strong><p>Total checks</p><i>▱</i></article>
          <article className="good"><span>Passing</span><strong>{passingGates}</strong><p>Gates compliant</p><i>✓</i></article>
          <article className="bad"><span>Failing</span><strong>{failingGates}</strong><p>Gates blocked</p><i>×</i></article>
        </section>

        <section className="lifecycle-legend"><strong>Legend:</strong><span><i className="legend-pass" />Compliant Stage</span><span><i className="legend-fail" />Non-Compliant Stage</span><span><i className="legend-pass" />Gate Pass</span><span><i className="legend-fail" />Gate Fail</span></section>

        <section className="lifecycle-timeline">
          {lifecycleStages.map((stage, index) => {
            const passedGateCount = stage.gates.filter((gate) => gate[3] === "passed").length;
            const failedGateCount = stage.gates.length - passedGateCount;
            const expanded = expandedLifecycleStage === index;
            const chips = stage.aws.split(", ");

            return (
              <article className={`lifecycle-stage-row ${stage.status === "failed" ? "noncompliant" : "compliant"} ${expanded ? "expanded" : ""}`} key={stage.stage}>
                <button className={`stage-number ${stage.status === "failed" ? "noncompliant" : "compliant"}`} onClick={() => setExpandedLifecycleStage(index)}>{String(index + 1).padStart(2, "0")}</button>
                <div className="stage-card">
                  <button className="stage-summary" onClick={() => setExpandedLifecycleStage(expanded ? -1 : index)}>
                    <div>
                      <div className="stage-tags"><span className={stage.status === "failed" ? "tag-fail" : "tag-pass"}>{stage.status === "failed" ? "Non-Compliant" : "Compliant"}</span>{chips.map((chip) => <span key={chip}>{chip}</span>)}</div>
                      <h2>{stage.stage}</h2>
                      <p>{stage.goal}</p>
                      <strong className={stage.status === "failed" ? "fail" : "pass"}>{passedGateCount}/{stage.gates.length} gates passing {failedGateCount > 0 ? `| ${failedGateCount} failing` : ""}</strong>
                    </div>
                    <span>{expanded ? "⌃" : "⌄"}</span>
                  </button>

                  {expanded && (
                    <div className="stage-expanded">
                      <p className="governed-by">Governed by: {stage.policies.split(", ").map((policy) => <b key={policy}>{policy}</b>)}</p>
                      {stage.gates.map(([id, title, detail, status]) => (
                        <div className={`gate-code-card ${status === "failed" ? "failed-gate" : "passed-gate"}`} key={id}>
                          <div className="gate-title"><strong>{status === "failed" ? "×" : "✓"} {id} - {title}</strong><span>{detail}</span></div>
                          <div className="mini-code-window">
                            <div className="mini-code-title"><i className="red-dot" /><i className="yellow-dot" /><i className="green-dot" /><span>{id.toLowerCase()}.rego</span><button>Copy</button></div>
                            <pre>{lifecycleGateRego(id)}</pre>
                          </div>
                        </div>
                      ))}
                    </div>
                  )}
                </div>
              </article>
            );
          })}
        </section>
      </>
    );
  }

  if (page === "CI/CD Pipeline") {
    return (
      <>
        <header className="topbar"><div><h1>CI/CD Pipeline</h1><p>GitHub Actions AI governance Policy-as-Code deployment gate</p></div></header>
        <section className="panel rule-detail">
          <h2>Complete CI/CD Flow</h2>
          <div className="pipeline-steps">
            {[
              ["Developer pushes to GitHub", "Infrastructure or mock AWS configuration is modified."],
              ["GitHub Actions Triggered", ".github/workflows/ai-governance-gate.yml starts on push, pull request, or manual dispatch."],
              ["Stage 1-3: Setup", "Checkout repository, setup Node.js, install OPA, and validate Terraform."],
              ["Stage 4: A.6.2 Data Governance Check", "OPA evaluates S3 encryption policy."],
              ["Stage 5: A.7.2 Transparency Check", "OPA evaluates Bedrock invocation logging."],
              ["Stage 6: A.8.4 Responsible AI Check", "OPA evaluates Bedrock Guardrails."],
              ["Stage 7: Gate Decision", "scripts/pac-deployment-check.mjs blocks deployment when violations are greater than zero."]
            ].map(([title, detail]) => <div className="pipeline-step" key={title}><strong>{title}</strong><span>{detail}</span></div>)}
          </div>
        </section>
      </>
    );
  }

  const failedControls = results.filter((rule) => !rule.passed);
  const scannedResources =
    scenario.input.resources.s3Buckets.length +
    scenario.input.resources.bedrockApps.length +
    scenario.input.resources.iamRoles.length;
  const compliantResources =
    scenario.input.resources.s3Buckets.filter((bucket) => bucket.encryption && !bucket.public_access).length +
    scenario.input.resources.bedrockApps.filter((app) => app.logging && app.guardrails).length +
    scenario.input.resources.iamRoles.filter((role) => role.policy !== "*").length;
  const reportControls = results.filter((rule) => ["DG-001", "TR-001", "RAI-001"].includes(rule.id));
  const auditTrail = {
    scan_id: "scan-abc12345xyz",
    timestamp: "2026-06-07 10:32:15 UTC",
    environment: scenario.label === "Failed Example" ? "staging" : "production",
    region: "us-east-1",
    account_id: "123456789012",
    input: scenario.filename
  };

  return (
    <>
      <header className="topbar"><div><h1>Compliance Report — ISO/IEC 42001:2023</h1><p>Detailed audit report for AWS AI governance Policy-as-Code evaluation</p></div></header>

      <section className="report-status-grid">
        <article className={`panel report-status ${failedControls.length > 0 ? "non-compliant" : "compliant"}`}>
          <span>Overall Status</span>
          <strong>{failedControls.length > 0 ? "NON-COMPLIANT" : "COMPLIANT"}</strong>
          <p>{failedControls.length} violation(s) found</p>
        </article>
        <article className="panel report-status"><span>Resources Scanned</span><strong>{scannedResources}</strong><p>S3 buckets, Bedrock apps, IAM roles</p></article>
        <article className="panel report-status"><span>Resource Compliance</span><strong>{Math.round((compliantResources / scannedResources) * 100)}%</strong><p>{compliantResources}/{scannedResources} compliant</p></article>
        <article className="panel report-status"><span>Controls Evaluated</span><strong>{reportControls.length}</strong><p>A.6.2, A.7.2, A.8.4</p></article>
      </section>

      <section className="panel report-summary">
        <h2>A. Overall Status</h2>
        <div className="report-facts">
          <span>Controls Evaluated: <b>{reportControls.length}</b></span>
          <span>Controls Passed: <b>{reportControls.filter((rule) => rule.passed).length}</b></span>
          <span>Controls Failed: <b>{reportControls.filter((rule) => !rule.passed).length}</b></span>
          <span>Policy: <b>policies/ai-lifecycle-governance.rego</b></span>
        </div>
      </section>

      <section className="report-controls">
        {reportControls.map((control) => (
          <article className={`panel report-control ${control.passed ? "control-pass" : "control-fail"}`} key={control.id}>
            <div className="panel-title">
              <h2>CONTROL {control.iso.replace("ISO/IEC 42001 ", "")} — {control.domain}</h2>
              <span className={control.passed ? "pass-tag" : "fail-tag"}>{control.passed ? "Passed" : "Failed"}</span>
            </div>
            <p>{control.rule}</p>
            <div className="rule-meta"><b>Violations: {control.findings.length}</b><b>{control.passed ? "All resources compliant" : "Remediation required"}</b></div>
            <div className="violation-detail-list">
              {control.findings.length === 0 ? (
                <div className="report-violation clean"><strong>No violations</strong><p>All evaluated resources meet this control.</p></div>
              ) : control.findings.map((finding) => {
                const expected = control.id === "DG-001" ? "Customer Managed KMS Key ARN" : control.id === "TR-001" ? "enabled with valid S3 destination" : "enabled with valid guardrail_id and version";
                const current = control.id === "DG-001" ? "alias/aws/s3" : "disabled";
                return (
                  <div className="report-violation" key={`${control.id}-${finding.name}`}>
                    <strong>Resource: {finding.name} ({finding.type})</strong>
                    <span>Issue: {finding.issue}</span>
                    <span>Expected: {expected}</span>
                    <span>Current: {current}</span>
                    <p>Remediation: {control.recommendation}</p>
                  </div>
                );
              })}
            </div>
          </article>
        ))}
      </section>

      <section className="content-grid middle-content">
        <article className="panel input-panel">
          <h2>C. Audit Trail</h2>
          <pre>{JSON.stringify(auditTrail, null, 2)}</pre>
        </article>
        <article className="panel input-panel">
          <h2>Evidence JSON</h2>
          <pre>{JSON.stringify({
  status: failedControls.length > 0 ? "NON-COMPLIANT" : "COMPLIANT",
  resources_scanned: scannedResources,
  resource_compliance: `${Math.round((compliantResources / scannedResources) * 100)}%`,
  controls: reportControls.map((rule) => ({
    control: rule.iso,
    status: rule.passed ? "PASSED" : "FAILED",
    violations: rule.findings
  }))
}, null, 2)}</pre>
        </article>
      </section>
    </>
  );
}

function App() {
  const [activePage, setActivePage] = useState<PageKey>("Dashboard");
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
  const infrastructureRows = [
    ...scenario.input.resources.s3Buckets.map((bucket) => ({
      icon: "▤",
      name: bucket.name,
      subtitle: "S3 Bucket",
      highlighted: bucket.name === "aigov-prompt-logs-prod",
      checks: [
        { label: "Encryption", passed: bucket.encryption },
        { label: "Public Access Block", passed: !bucket.public_access }
      ]
    })),
    ...scenario.input.resources.bedrockApps.map((app) => ({
      icon: "◌",
      name: app.name,
      subtitle: app.name === "claims-assistant-bedrock" ? "anthropic.claude-3-sonnet" : app.name === "customer-support-rag" ? "amazon.titan-text-express-v1" : "meta.llama3-70b-instruct-v1",
      highlighted: false,
      checks: [
        { label: "Logging", passed: app.logging },
        { label: "Guardrails", passed: app.guardrails }
      ]
    })),
    ...scenario.input.resources.iamRoles.map((role) => ({
      icon: "▣",
      name: role.name,
      subtitle: "IAM Role",
      highlighted: false,
      checks: [
        { label: "Least Privilege", passed: role.policy !== "*" },
        { label: "No Wildcards", passed: role.policy !== "*" }
      ]
    }))
  ];

  return (
    <div className="dashboard-shell">
      <aside className="sidebar">
        <div className="brand"><div className="shield">▰</div><div><strong>AI Governance</strong><span>Policy-as-Code Gateway</span></div></div>
        <nav>{nav.map((item, index) => <button className={activePage === item ? "active" : ""} key={item} onClick={() => setActivePage(item)}><span>{["▦", "▧", "⌁", "◌", "⌬", "▤"][index]}</span>{item}</button>)}</nav>
        <div className="sidebar-footer"><div className="env"><span>SCENARIO</span><strong><i />{scenario.label}</strong></div></div>
      </aside>

      <main className="main-panel">
        {activePage !== "Dashboard" ? <AppPage page={activePage} scenario={scenario} results={results} selectedRule={selectedRule} setSelectedRuleId={setSelectedRuleId} /> : (
          <>
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
          <article className="panel infra aws-infra-panel"><div className="aws-infra-header"><div><h2>AWS Infrastructure</h2><span>us-east-1 · 123456789012</span></div></div><div className="aws-infra-list">{infrastructureRows.map((resource) => <div className={`aws-infra-row ${resource.highlighted ? "highlighted" : ""}`} key={`${resource.subtitle}-${resource.name}`}><div className="aws-resource-icon">{resource.icon}</div><div className="aws-resource-name"><strong>{resource.name}</strong><span>{resource.subtitle}</span></div><div className="aws-resource-checks">{resource.checks.map((check) => <span className={check.passed ? "check-pass" : "check-fail"} key={check.label}><i />{check.label}</span>)}</div></div>)}</div></article>
          <article className="panel actions"><h2>Quick Actions</h2><button className="action-button" onClick={() => { setScenarioKey(scenarioKey === "failed" ? "passed" : "failed"); setEvidenceFocus(false); }}><span className="icon-box blue">▶</span><div><strong>Toggle Scenario</strong><small>Switch pass/fail input</small></div></button><button className="action-button" onClick={() => { setSelectedRuleId(failed[0]?.id ?? results[0].id); setEvidenceFocus(true); }}><span className="icon-box amber">⌬</span><div><strong>View Evidence</strong><small>Show named failing resources</small></div></button></article>
        </section>
          </>
        )}
      </main>
    </div>
  );
}

export default App;
