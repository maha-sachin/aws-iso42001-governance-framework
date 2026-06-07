import { useMemo, useState } from "react";
import failedMockInfrastructure from "../../mock-infra/failed-example.json";
import passedMockInfrastructure from "../../mock-infra/passed-example.json";

type ScenarioKey = "failed" | "passed";
type PageKey = "Dashboard" | "Policy Framework" | "Policies (OPA)" | "AI Lifecycle" | "CI/CD Pipeline" | "Compliance Report";

type ResourceFinding = {
  type: "S3 Bucket" | "Bedrock App" | "IAM Role" | "Governance Evidence" | "Risk Record" | "Approval Evidence";
  name: string;
  field: string;
  currentValue: string;
  issue: string;
};

type InfrastructureInput = {
  account: string;
  account_id?: string;
  application: string;
  environment: string;
  region?: string;
  impact_assessment?: { completed: boolean; assessment_id: string; owner: string; reviewed_at: string };
  risk?: { rating: "low" | "medium" | "high" | "critical"; score: number; accepted: boolean };
  production_approval?: { approved: boolean; approver: string; ticket: string };
  s3_buckets: Array<{ name: string; kms_key_type: "AWS_MANAGED" | "CUSTOMER_MANAGED"; public_access: boolean }>;
  bedrock_models: Array<{ name: string; model_id: string; invocation_logging_enabled: boolean; guardrails_enabled: boolean }>;
  iam_roles: Array<{ name: string; wildcard_permissions: boolean }>;
};

type EvaluatedInfrastructureInput = InfrastructureInput & {
  account_id: string;
  region: string;
  impact_assessment: { completed: boolean; assessment_id: string; owner: string; reviewed_at: string };
  risk: { rating: "low" | "medium" | "high" | "critical"; score: number; accepted: boolean };
  production_approval: { approved: boolean; approver: string; ticket: string };
};

type PolicyRule = {
  id: string;
  iso: string;
  domain: string;
  policy: string;
  rule: string;
  resource: "s3" | "bedrock" | "iam" | "governance";
  severity: "Critical" | "High";
  recommendation: string;
  rego: string;
  evaluate: (input: EvaluatedInfrastructureInput) => boolean;
  getFindings: (input: EvaluatedInfrastructureInput) => ResourceFinding[];
  violation: object;
};

function normalizeInfrastructureInput(input: InfrastructureInput): EvaluatedInfrastructureInput {
  return {
    ...input,
    account_id: input.account_id ?? "123456789012",
    region: input.region ?? "us-east-1",
    impact_assessment: input.impact_assessment ?? { completed: false, assessment_id: "", owner: "", reviewed_at: "" },
    risk: input.risk ?? { rating: "critical", score: 100, accepted: false },
    production_approval: input.production_approval ?? { approved: false, approver: "", ticket: "" }
  };
}

const scenarios: Record<ScenarioKey, { label: string; filename: string; rawInput: InfrastructureInput; input: EvaluatedInfrastructureInput }> = {
  failed: {
    label: "Failed Example",
    filename: "mock-infra/failed-example.json",
    rawInput: failedMockInfrastructure as InfrastructureInput,
    input: normalizeInfrastructureInput(failedMockInfrastructure as InfrastructureInput)
  },
  passed: {
    label: "Passed Example",
    filename: "mock-infra/passed-example.json",
    rawInput: passedMockInfrastructure as InfrastructureInput,
    input: normalizeInfrastructureInput(passedMockInfrastructure as InfrastructureInput)
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
    recommendation: "Use customer-managed KMS keys for every evaluated S3 bucket.",
    violation: { s3_buckets: [{ kms_key_type: "AWS_MANAGED" }] },
    evaluate: (input) => input.s3_buckets.every((bucket) => bucket.kms_key_type === "CUSTOMER_MANAGED"),
    getFindings: (input) => input.s3_buckets
      .filter((bucket) => bucket.kms_key_type !== "CUSTOMER_MANAGED")
      .map((bucket) => ({ type: "S3 Bucket", name: bucket.name, field: "kms_key_type", currentValue: bucket.kms_key_type, issue: "Bucket is not using a customer-managed KMS key" })),
    rego: `deny contains msg if {
  bucket := input.s3_buckets[_]
  bucket.kms_key_type != "CUSTOMER_MANAGED"
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
    recommendation: "Enable Bedrock invocation logging for every evaluated model.",
    violation: { bedrock_models: [{ invocation_logging_enabled: false }] },
    evaluate: (input) => input.bedrock_models.every((model) => model.invocation_logging_enabled),
    getFindings: (input) => input.bedrock_models
      .filter((model) => !model.invocation_logging_enabled)
      .map((model) => ({ type: "Bedrock App", name: model.name, field: "invocation_logging_enabled", currentValue: String(model.invocation_logging_enabled), issue: "Invocation logging is disabled" })),
    rego: `deny contains msg if {
  model := input.bedrock_models[_]
  model.invocation_logging_enabled == false
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
    recommendation: "Enable Bedrock Guardrails for every evaluated model.",
    violation: { bedrock_models: [{ guardrails_enabled: false }] },
    evaluate: (input) => input.bedrock_models.every((model) => model.guardrails_enabled),
    getFindings: (input) => input.bedrock_models
      .filter((model) => !model.guardrails_enabled)
      .map((model) => ({ type: "Bedrock App", name: model.name, field: "guardrails_enabled", currentValue: String(model.guardrails_enabled), issue: "Bedrock Guardrails are not attached" })),
    rego: `deny contains msg if {
  model := input.bedrock_models[_]
  model.guardrails_enabled == false
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
    violation: { iam_roles: [{ wildcard_permissions: true }] },
    evaluate: (input) => input.iam_roles.every((role) => role.wildcard_permissions === false),
    getFindings: (input) => input.iam_roles
      .filter((role) => role.wildcard_permissions)
      .map((role) => ({ type: "IAM Role", name: role.name, field: "wildcard_permissions", currentValue: String(role.wildcard_permissions), issue: "Wildcard permissions are allowed" })),
    rego: `deny contains msg if {
  role := input.iam_roles[_]
  role.wildcard_permissions == true
  msg := {
    "id": "SEC-001",
    "iso": "Security Control",
    "rule": "IAM policies cannot use wildcard permissions."
  }
}`
  },
  {
    id: "GOV-001",
    iso: "ISO/IEC 42001 A.5.2",
    domain: "Impact Assessment",
    policy: "AI Governance Policy",
    rule: "AI impact assessment must be completed.",
    resource: "governance",
    severity: "High",
    recommendation: "Complete the AI impact assessment and attach the assessment ID before CI/CD deployment.",
    violation: { impact_assessment: { completed: false } },
    evaluate: (input) => input.impact_assessment.completed,
    getFindings: (input) => input.impact_assessment.completed ? [] : [{
      type: "Governance Evidence",
      name: input.application,
      field: "impact_assessment.completed",
      currentValue: String(input.impact_assessment.completed),
      issue: "Impact assessment evidence is missing or incomplete"
    }],
    rego: `deny contains msg if {
  not input.impact_assessment.completed
  msg := {
    "id": "GOV-001",
    "iso": "ISO/IEC 42001 A.5.2",
    "rule": "AI impact assessment must be completed."
  }
}`
  },
  {
    id: "GOV-002",
    iso: "ISO/IEC 42001 A.5.3",
    domain: "Risk Rating",
    policy: "AI Risk Management Policy",
    rule: "Critical AI risk must be accepted before deployment.",
    resource: "governance",
    severity: "Critical",
    recommendation: "Reduce the AI risk rating or document formal risk acceptance before the deployment gate can pass.",
    violation: { risk: { rating: "critical", accepted: false } },
    evaluate: (input) => input.risk.rating !== "critical" || input.risk.accepted,
    getFindings: (input) => input.risk.rating !== "critical" || input.risk.accepted ? [] : [{
      type: "Risk Record",
      name: input.application,
      field: "risk.rating",
      currentValue: `${input.risk.rating} (${input.risk.score})`,
      issue: "Critical AI risk has not been formally accepted"
    }],
    rego: `deny contains msg if {
  input.risk.rating == "critical"
  not input.risk.accepted
  msg := {
    "id": "GOV-002",
    "iso": "ISO/IEC 42001 A.5.3",
    "rule": "Critical AI risk must be accepted before deployment."
  }
}`
  },
  {
    id: "GOV-003",
    iso: "ISO/IEC 42001 A.6.1",
    domain: "Production Approval",
    policy: "Deployment Governance Policy",
    rule: "Production approval is required.",
    resource: "governance",
    severity: "High",
    recommendation: "Capture production approval with an approver and change ticket before release.",
    violation: { production_approval: { approved: false } },
    evaluate: (input) => input.production_approval.approved,
    getFindings: (input) => input.production_approval.approved ? [] : [{
      type: "Approval Evidence",
      name: input.application,
      field: "production_approval.approved",
      currentValue: String(input.production_approval.approved),
      issue: "Production approval evidence is missing"
    }],
    rego: `deny contains msg if {
  not input.production_approval.approved
  msg := {
    "id": "GOV-003",
    "iso": "ISO/IEC 42001 A.6.1",
    "rule": "Production approval is required."
  }
}`
  }
];

const nav: PageKey[] = ["Dashboard",  "Policies (OPA)", "AI Lifecycle", "CI/CD Pipeline"];
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
      ["LC-02-A", "S3 CMK Encryption Gate", "aigov-training-data-prod uses AWS-managed KMS instead of a customer-managed key.", "failed"],
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
      ["LC-06-A", "A.6.2 Data Governance", "aigov-training-data-prod violates S3 customer-managed KMS encryption.", "failed"],
      ["LC-06-B", "A.7.2 Transparency", "customer-support-rag has Bedrock invocation logging disabled.", "failed"],
      ["LC-06-C", "A.8.4 Responsible AI", "internal-policy-bot has Bedrock Guardrails disabled.", "failed"],
      ["LC-06-D", "IAM Least Privilege", "BedrockAppExecutionRole still allows wildcard permissions.", "failed"]
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

function evaluatePolicies(input: EvaluatedInfrastructureInput) {
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
  bucket.name == "aigov-training-data-prod"
  bucket.kms_key_type != "CUSTOMER_MANAGED"
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
  scenario: Record<ScenarioKey, { label: string; filename: string; rawInput: InfrastructureInput; input: EvaluatedInfrastructureInput }>[ScenarioKey];
  results: ReturnType<typeof evaluatePolicies>;
  selectedRule: ReturnType<typeof evaluatePolicies>[number];
  setSelectedRuleId: (id: string) => void;
}) {
  const [expandedLifecycleStage, setExpandedLifecycleStage] = useState(0);
  const [policyFilter, setPolicyFilter] = useState<"all" | "corporate" | "operational">("all");
  const [expandedPolicyId, setExpandedPolicyId] = useState("Responsible AI Policy");

  if (page === "Policy Framework") {
    const frameworkPolicies = [
      {
        id: "Responsible AI Policy",
        tier: "corporate",
        category: "Responsible AI",
        title: "Responsible AI Policy",
        owner: "Chief AI Officer",
        iso: "ISO/IEC 42001:2023 A.8.4",
        review: "Annual",
        description: "AI systems must use safety controls, harmful content generation must be mitigated, and human oversight is required for high-risk use cases.",
        principles: ["Bedrock Guardrails must be enabled before production deployment.", "Safety controls must reduce harmful content generation risk.", "High-risk AI use cases require human oversight.", "Responsible AI requirements are checked before deployment approval."],
        enforcedBy: ["RAI-001"],
        enforcement: "OPA blocks Bedrock deployments when Guardrails are disabled."
      },
      { id: "Data Privacy Policy", tier: "corporate", category: "Data Privacy", title: "Data Privacy Policy", owner: "Chief Data Officer", iso: "ISO/IEC 42001:2023 A.6.2", review: "Annual", description: "AI data must be encrypted, public access must be prohibited, and sensitive data must be protected throughout the AI lifecycle.", principles: ["S3 buckets storing AI data must use customer-managed KMS keys.", "Public access must be blocked for AI data stores.", "Sensitive AI data must be protected before training or inference.", "Encryption evidence must be available for audit review."], enforcedBy: ["DG-001"], enforcement: "OPA blocks S3 buckets that do not use customer-managed KMS encryption." },
      { id: "Transparency Policy", tier: "corporate", category: "Transparency", title: "Transparency Policy", owner: "Chief Compliance Officer", iso: "ISO/IEC 42001:2023 A.7.2", review: "Annual", description: "AI interactions must be auditable. Logging is required so prompts, responses, and model invocation metadata can be reviewed.", principles: ["Bedrock invocation logging must be enabled.", "Audit evidence must be generated for AI interactions.", "Logs must be available for compliance reporting.", "Transparency controls must run before deployment approval."], enforcedBy: ["TR-001"], enforcement: "OPA blocks Bedrock deployments when invocation logging is disabled." },
      { id: "AI Security Policy", tier: "corporate", category: "AI Security", title: "AI Security Policy", owner: "CISO", iso: "Security Control", review: "Annual", description: "AI workloads must follow least privilege access, avoid wildcard permissions, and support security monitoring.", principles: ["IAM wildcard permissions are not allowed.", "AI execution roles must be scoped to approved permissions.", "Security review is required before deployment.", "Non-compliant IAM policies are blocked in CI/CD."], enforcedBy: ["SEC-001"], enforcement: "OPA blocks IAM roles with wildcard permissions." },
      { id: "Data Governance", tier: "operational", category: "Data Governance", title: "Data Governance Operational Controls", owner: "VP of Data Engineering", iso: "ISO/IEC 42001:2023 A.6.2", review: "Semi-Annual", description: "Operational controls enforce encryption at rest, encryption in transit, data classification, and data retention for AI data stores.", principles: ["Encryption at rest is required.", "Encryption in transit is required.", "Data classification and retention must be documented.", "S3 data stores must meet customer-managed KMS requirements."], enforcedBy: ["DG-001"], enforcement: "OPA evaluates AI data storage encryption during the deployment gate." },
      { id: "Model Governance", tier: "operational", category: "Model Governance", title: "Model Governance Operational Controls", owner: "Head of MLOps", iso: "Lifecycle Control", review: "Semi-Annual", description: "Operational controls require approved models, version tracking, and model approval process evidence.", principles: ["Approved models only.", "Version tracking is required.", "Model approval process must be documented.", "Lifecycle dashboard tracks model governance stage status."], enforcedBy: [], enforcement: "Model governance is represented in the AI Lifecycle PaC view." },
      { id: "Deployment Governance", tier: "operational", category: "Deployment Governance", title: "Deployment Governance Operational Controls", owner: "VP of AI Platform", iso: "ISO/IEC 42001:2023 A.7.2, A.8.4", review: "Semi-Annual", description: "Deployment controls require logging enabled, Guardrails enabled, and security review complete before release.", principles: ["Bedrock invocation logging must be enabled.", "Bedrock Guardrails must be enabled.", "IAM wildcard permissions must be blocked.", "Deployment is blocked when OPA violations exist."], enforcedBy: ["TR-001", "RAI-001", "SEC-001"], enforcement: "GitHub Actions runs OPA and blocks non-compliant deployments." },
      { id: "Monitoring Governance", tier: "operational", category: "Monitoring Governance", title: "Monitoring Governance Operational Controls", owner: "VP of AI Platform", iso: "Monitoring Control", review: "Semi-Annual", description: "Operational monitoring controls require continuous compliance monitoring, audit logging, and incident detection.", principles: ["Continuous compliance monitoring is required.", "Audit logging must be enabled.", "Incident detection must be configured.", "Compliance evidence is uploaded by GitHub Actions."], enforcedBy: ["TR-001"], enforcement: "Logging evidence from TR-001 supports audit reporting." }
    ];
    const corporateCount = frameworkPolicies.filter((policy) => policy.tier === "corporate").length;
    const operationalCount = frameworkPolicies.filter((policy) => policy.tier === "operational").length;
    const visiblePolicies = frameworkPolicies.filter((policy) => policyFilter === "all" || policy.tier === policyFilter);

    return (
      <>
        <header className="framework-header"><div><h1>AI Policy Framework</h1><p>Corporate & Operational AI Governance Policies — ISO/IEC 42001:2023</p></div></header>

        <section className="framework-kpis">
          <article><span>Total Policies</span><strong>{frameworkPolicies.length}</strong><p>Across both tiers</p><i>▤</i></article>
          <article><span>Corporate</span><strong>{corporateCount}</strong><p>Board-level mandates</p><i>▧</i></article>
          <article><span>Operational</span><strong>{operationalCount}</strong><p>Engineering standards</p><i>⚙</i></article>
        </section>

        <section className="framework-filters" aria-label="Policy filters">
          {[
            ["all", "All Policies"],
            ["corporate", `Corporate (${corporateCount})`],
            ["operational", `Operational (${operationalCount})`]
          ].map(([key, label]) => <button className={policyFilter === key ? "active" : ""} key={key} onClick={() => setPolicyFilter(key as typeof policyFilter)}>{label}</button>)}
        </section>

        <section className="framework-list">
          {visiblePolicies.map((policy) => {
            const expanded = expandedPolicyId === policy.id;
            return (
              <article className={`framework-policy ${expanded ? "expanded" : ""}`} key={policy.id}>
                <button className="framework-policy-head" onClick={() => setExpandedPolicyId(expanded ? "" : policy.id)}>
                  <span className="policy-id-badge">{policy.tier === "corporate" ? "Corporate" : "Operational"}</span>
                  <div>
                    <div className="framework-tags"><span className={policy.tier === "corporate" ? "corporate-tag" : "operational-tag"}>{policy.tier === "corporate" ? "Corporate Policy" : "Operational Policy"}</span><span>{policy.category}</span></div>
                    <h2>{policy.title}</h2>
                    <p>Owner: {policy.owner} · {policy.iso} · Review: {policy.review}</p>
                  </div>
                  <b>{expanded ? "⌃" : "⌄"}</b>
                </button>

                {expanded && (
                  <div className="framework-policy-body">
                    <p className="policy-description-block">{policy.description}</p>
                    <h3>Policy Principles</h3>
                    <ul>{policy.principles.map((principle) => <li key={principle}>{principle}</li>)}</ul>
                    <div className="enforcement-note"><strong>Enforcement:</strong> {policy.enforcement}</div>
                  </div>
                )}
              </article>
            );
          })}
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
            <pre>{JSON.stringify(scenario.rawInput, null, 2)}</pre>
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
    const governanceGateIds = ["GOV-001", "GOV-002", "GOV-003"];
    const governanceGates = results.filter((rule) => governanceGateIds.includes(rule.id));
    const pipelineFacts = [
      ["Impact Assessment", scenario.input.impact_assessment.completed ? scenario.input.impact_assessment.assessment_id : "Missing", "Confirms the AI use case, affected users, data sensitivity, and control obligations before code can ship."],
      ["Risk Rating", `${scenario.input.risk.rating.toUpperCase()} (${scenario.input.risk.score})`, "Makes deployment risk visible in CI/CD and blocks unaccepted critical risk before production exposure."],
      ["Production Approval", scenario.input.production_approval.approved ? `${scenario.input.production_approval.approver} · ${scenario.input.production_approval.ticket}` : "Missing", "Creates accountable release evidence so production changes are approved before the gate passes."]
    ];

    return (
      <>
        <header className="topbar"><div><h1>CI/CD Pipeline</h1><p>GitHub Actions AI governance Policy-as-Code deployment gate</p></div></header>

        <section className="content-grid middle-content">
          <article className="panel rule-detail">
            <h2>Complete CI/CD Flow</h2>
            <div className="pipeline-steps">
              {[
                ["Developer pushes to GitHub", "Infrastructure or mock AWS configuration is modified."],
                ["GitHub Actions Triggered", ".github/workflows/ai-governance-gate.yml starts on push, pull request, or manual dispatch."],
                ["Stage 1-3: Setup", "Checkout repository, setup Node.js, install OPA, and validate Terraform."],
                ["Stage 4: Technical Controls", "OPA evaluates S3 encryption, Bedrock logging, Bedrock Guardrails, and IAM wildcard permissions."],
                ["Stage 5: Impact Assessment", "OPA checks impact_assessment.completed and requires assessment evidence."],
                ["Stage 6: Risk Rating", "OPA blocks critical AI risk unless the risk is formally accepted."],
                ["Stage 7: Production Approval", "OPA requires production_approval.approved with release evidence."],
                ["Stage 8: Gate Decision", "scripts/pac-deployment-check.mjs blocks deployment when any policy violation exists."]
              ].map(([title, detail]) => <div className="pipeline-step" key={title}><strong>{title}</strong><span>{detail}</span></div>)}
            </div>
          </article>

          <article className="panel rule-detail">
            <h2>Governance Gate Status <span>{scenario.label}</span></h2>
            <div className="pipeline-steps">
              {governanceGates.map((gate) => (
                <div className="pipeline-step" key={gate.id}>
                  <strong><span className={gate.passed ? "pass" : "fail"}>{gate.passed ? "✓" : "×"}</span> {gate.id} · {gate.domain}</strong>
                  <span>{gate.passed ? "Passing scenario evidence is present." : gate.findings[0]?.issue}</span>
                </div>
              ))}
            </div>
          </article>

          <article className="panel input-panel">
            <h2>Why This Matters</h2>
            <div className="pipeline-steps">
              {pipelineFacts.map(([title, value, why]) => (
                <div className="pipeline-step" key={title}>
                  <strong>{title}: {value}</strong>
                  <span>{why}</span>
                </div>
              ))}
            </div>
          </article>
        </section>
      </>
    );
  }

  const failedControls = results.filter((rule) => !rule.passed);
  const scannedResources =
    scenario.input.s3_buckets.length +
    scenario.input.bedrock_models.length +
    scenario.input.iam_roles.length;
  const compliantResources =
    scenario.input.s3_buckets.filter((bucket) => bucket.kms_key_type === "CUSTOMER_MANAGED" && !bucket.public_access).length +
    scenario.input.bedrock_models.filter((model) => model.invocation_logging_enabled && model.guardrails_enabled).length +
    scenario.input.iam_roles.filter((role) => !role.wildcard_permissions).length;
  const reportControls = results;
  const auditTrail = {
    scan_id: "scan-abc12345xyz",
    timestamp: "2026-06-07 10:32:15 UTC",
    environment: scenario.label === "Failed Example" ? "staging" : "production",
    region: scenario.input.region,
    account_id: scenario.input.account_id,
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
        <article className="panel report-status"><span>Controls Evaluated</span><strong>{reportControls.length}</strong><p>Technical and governance gates</p></article>
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
                const expected = control.id === "DG-001" ? "Customer Managed KMS Key ARN" : control.id === "TR-001" ? "enabled with valid S3 destination" : control.id === "RAI-001" ? "enabled with valid guardrail_id and version" : control.id === "GOV-001" ? "completed impact assessment ID" : control.id === "GOV-002" ? "non-critical rating or accepted critical risk" : control.id === "GOV-003" ? "approved production change ticket" : "compliant value";
                const current = finding.currentValue;
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
    ...scenario.input.s3_buckets.map((bucket) => ({
      icon: "▤",
      name: bucket.name,
      subtitle: "S3 Bucket",
      highlighted: failed.some((rule) => rule.findings.some((finding) => finding.name === bucket.name)),
      checks: [
        { label: "Encryption", passed: bucket.kms_key_type === "CUSTOMER_MANAGED" },
        { label: "Public Access Block", passed: !bucket.public_access }
      ]
    })),
    ...scenario.input.bedrock_models.map((app) => ({
      icon: "◌",
      name: app.name,
      subtitle: app.model_id,
      highlighted: failed.some((rule) => rule.findings.some((finding) => finding.name === app.name)),
      checks: [
        { label: "Logging", passed: app.invocation_logging_enabled },
        { label: "Guardrails", passed: app.guardrails_enabled }
      ]
    })),
    ...scenario.input.iam_roles.map((role) => ({
      icon: "▣",
      name: role.name,
      subtitle: "IAM Role",
      highlighted: failed.some((rule) => rule.findings.some((finding) => finding.name === role.name)),
      checks: [
        { label: "Least Privilege", passed: !role.wildcard_permissions },
        { label: "No Wildcards", passed: !role.wildcard_permissions }
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
          <article className="panel input-panel"><h2>Evaluated Mock Infrastructure</h2><pre>{JSON.stringify(scenario.rawInput, null, 2)}</pre></article>
          <article className={`panel input-panel ${evidenceFocus ? "evidence-focus" : ""}`}><h2>{selectedRule.passed ? "Audit Evidence" : "Violation + Remediation"}</h2>{selectedRule.passed ? <pre>{JSON.stringify({ result: "allow", evidence: `${selectedRule.id} passed for ${scenario.filename}` }, null, 2)}</pre> : <div className="finding-list">{affectedResources.map((finding) => <div className="finding-card" key={`${finding.type}-${finding.name}-${finding.field}`}><strong>{finding.name}</strong><span>{finding.type}</span><p>{finding.issue}</p><code>{finding.field}: {finding.currentValue}</code></div>)}<pre>{JSON.stringify({ violation: selectedRule.violation, recommendation: selectedRule.recommendation }, null, 2)}</pre></div>}</article>
        </section>

        <section className="content-grid bottom-content">
          <article className="panel infra aws-infra-panel"><div className="aws-infra-header"><div><h2>AWS Infrastructure</h2><span>{scenario.input.region} · {scenario.input.account_id}</span></div></div><div className="aws-infra-list">{infrastructureRows.map((resource) => <div className={`aws-infra-row ${resource.highlighted ? "highlighted" : ""}`} key={`${resource.subtitle}-${resource.name}`}><div className="aws-resource-icon">{resource.icon}</div><div className="aws-resource-name"><strong>{resource.name}</strong><span>{resource.subtitle}</span></div><div className="aws-resource-checks">{resource.checks.map((check) => <span className={check.passed ? "check-pass" : "check-fail"} key={check.label}><i />{check.label}</span>)}</div></div>)}</div></article>
          <article className="panel actions"><h2>Quick Actions</h2><button className="action-button" onClick={() => { setScenarioKey(scenarioKey === "failed" ? "passed" : "failed"); setEvidenceFocus(false); }}><span className="icon-box blue">▶</span><div><strong>Toggle Scenario</strong><small>Switch pass/fail input</small></div></button><button className="action-button" onClick={() => { setSelectedRuleId(failed[0]?.id ?? results[0].id); setEvidenceFocus(true); }}><span className="icon-box amber">⌬</span><div><strong>View Evidence</strong><small>Show named failing resources</small></div></button></article>
        </section>
          </>
        )}
      </main>
    </div>
  );
}

export default App;
