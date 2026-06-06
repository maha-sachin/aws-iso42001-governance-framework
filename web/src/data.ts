export const compliance = {
  score: 0,
  riskLevel: "High",
  deploymentStatus: "Blocked",
  violations: 4
};

export const corporatePolicies = [
  {
    name: "Responsible AI",
    requirements: ["AI systems must use safety controls", "Harmful content generation must be mitigated", "Human oversight required for high-risk use cases"],
    mapping: ["Amazon Bedrock Guardrails"]
  },
  {
    name: "Data Privacy",
    requirements: ["Data must be encrypted", "Public access prohibited", "Sensitive data protected"],
    mapping: ["Amazon S3", "AWS KMS"]
  },
  {
    name: "Transparency",
    requirements: ["AI interactions must be auditable", "Logging required"],
    mapping: ["Bedrock Invocation Logging", "CloudWatch Logs"]
  },
  {
    name: "AI Security",
    requirements: ["Least privilege access", "No wildcard permissions", "Security monitoring required"],
    mapping: ["IAM", "CloudTrail", "Security Hub"]
  }
];

export const lifecycleStages = ["Scoping", "Data Collection", "Training", "Validation", "Deployment", "Monitoring", "Retirement"];

export const policyEngineControls = [
  { id: "DG-001", iso: "ISO A.6.2", engine: "OPA/Rego", rule: "S3 buckets must use encryption", status: "Fail" },
  { id: "TR-001", iso: "ISO A.7.2", engine: "OPA/Rego", rule: "Bedrock invocation logging must be enabled", status: "Fail" },
  { id: "RAI-001", iso: "ISO A.8.4", engine: "OPA/Rego", rule: "Bedrock Guardrails must be enabled", status: "Fail" },
  { id: "SEC-001", iso: "Security Control", engine: "OPA/Rego", rule: "IAM policies cannot use wildcard permissions", status: "Fail" }
];

export const remediationItems = [
  "Enable S3 default encryption with AWS KMS.",
  "Enable Bedrock invocation logging to CloudWatch Logs.",
  "Attach an approved Bedrock Guardrail before deployment.",
  "Replace wildcard permissions with scoped least-privilege IAM statements."
];
