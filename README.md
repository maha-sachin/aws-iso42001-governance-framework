# AWS ISO 42001 AI Governance Framework

### Policy-as-Code | Terraform | AWS

> A production-grade Infrastructure-as-Code framework implementing **ISO/IEC 42001:2023** — the international standard for AI Management Systems — on AWS.

---

## 🎯 What This Framework Does

This Terraform codebase enforces AI governance, safety, and compliance controls across your AWS environment using native AWS services. Every ISO 42001 control domain is mapped to real infrastructure policy code.

| ISO 42001 Domain               | AWS Services Used                         | Module                |
| ------------------------------ | ----------------------------------------- | --------------------- |
| AI Governance & Accountability | AWS Organizations, SCPs, IAM              | `ai-governance`       |
| AI Risk Management             | AWS Config, Security Hub, GuardDuty       | `risk-management`     |
| AI Safety Controls             | SageMaker Model Cards, Bedrock Guardrails | `ai-safety`           |
| Data Privacy & Lineage         | Macie, Lake Formation, Glue               | `data-privacy`        |
| Compliance Monitoring          | CloudWatch, EventBridge, SNS              | `monitoring`          |
| Audit & Evidence               | CloudTrail, S3, Athena                    | `compliance-controls` |

---

## 📁 Project Structure

```
aws-iso42001-governance-framework/
├── terraform/                     # Terraform backend and governance controls
│   ├── main.tf                    # Root orchestration
│   ├── variables.tf               # Global variables
│   ├── outputs.tf                 # Framework outputs
│   ├── versions.tf                # Provider constraints
│   ├── pac_lifecycle.tf           # Terraform-native PaC lifecycle gates
│   ├── policy_framework.tf        # Corporate and operational policies
│   ├── terraform.tfvars.example   # Example configuration
│   └── modules/
│       ├── ai-governance/         # ISO 42001 §6 — Planning & Governance
│       ├── ai-safety/             # ISO 42001 §8 — Operation & Safety
│       ├── risk-management/       # ISO 42001 §6.1 — Risk Assessment
│       ├── data-privacy/          # ISO 42001 §8.4 — Data for AI
│       ├── monitoring/            # ISO 42001 §9 — Performance & Monitoring
│       └── compliance-controls/   # ISO 42001 §9.1 — Audit & Evidence
├── policies/                      # OPA/Rego and AWS policy documents
├── mock-infra/                    # Pass/fail input examples for OPA
├── scripts/                       # Compliance report generation
├── web/                           # React dashboard
└── docs/                          # Governance documentation
```

---

## 🚀 Quick Start

```bash
# 1. Clone and configure
git clone https://github.com/yourname/aws-iso42001-governance-framework
cd aws-iso42001-governance-framework
cp terraform/terraform.tfvars.example terraform/terraform.tfvars

# 2. Edit your org settings
vim terraform/terraform.tfvars

# 3. Initialize and deploy
cd terraform
terraform init
terraform plan -out=governance.tfplan
terraform apply governance.tfplan
```

---

## 🔐 ISO 42001 Control Mapping

### Clause 6 — Planning

- **6.1.2** AI Risk Assessment → `terraform/modules/risk-management/config_rules.tf`
- **6.2** AI Objectives → `terraform/modules/ai-governance/iam_roles.tf`

### Clause 8 — Operation

- **8.2** AI System Impact Assessment → `terraform/modules/ai-safety/sagemaker_controls.tf`
- **8.4** Data Acquisition & Preparation → `terraform/modules/data-privacy/macie_config.tf`
- **8.5** AI System Design → `terraform/modules/ai-safety/bedrock_guardrails.tf`
- **8.6** AI System Verification → `terraform/modules/monitoring/cloudwatch_alarms.tf`

### Clause 9 — Performance Evaluation

- **9.1** Monitoring & Measurement → `terraform/modules/monitoring/`
- **9.2** Internal Audit → `terraform/modules/compliance-controls/cloudtrail.tf`
- **9.3** Management Review → `terraform/modules/compliance-controls/athena_queries.tf`

---

## 👤 Author

Built to demonstrate practical **Policy-as-Code** expertise in AI governance frameworks aligned to ISO/IEC 42001:2023.

# aws-iso42001-governance-framework

A production-grade Infrastructure-as-Code framework implementing ISO/IEC 42001:2023 — the international standard for AI Management Systems — on AWS.


## AI Policy-as-Code Lifecycle Implementation

This repository now includes a mock AWS AI lifecycle governance implementation that does not require a real AWS account. Terraform defines:

- Corporate AI policies for responsible AI, data privacy, transparency, and AI security.
- Operational policies for data governance, model governance, deployment governance, and monitoring governance.
- AI lifecycle stages from data collection through monitoring.
- Policy-as-Code controls that evaluate mock AWS infrastructure posture.
- Compliance outputs including violations, recommendations, score, risk level, and deployment gate decision.

Key files:

- `terraform/policy_framework.tf` defines corporate and operational AI policies.
- `terraform/pac_lifecycle.tf` implements lifecycle stage gates and Terraform-native PaC evaluation.
- `policies/ai-lifecycle-governance.rego` contains the equivalent OPA/Rego controls.
- `mock-infra/failed-example.json` and `mock-infra/passed-example.json` provide demo input postures.
- `docs/ai-policy-as-code-lifecycle.md` documents the governance lifecycle.

Run:

```bash
cd terraform
terraform fmt -recursive
terraform validate
terraform plan
```

By default, the mock infrastructure is intentionally non-compliant, so the plan outputs a failed deployment gate and remediation recommendations. Override `mock_aws_ai_infrastructure` in `terraform/terraform.tfvars` to simulate a passing environment.

## Run OPA Policy Checks

This project includes Open Policy Agent policies in `policies/ai-lifecycle-governance.rego`. These Rego rules evaluate mock AWS AI infrastructure definitions in `mock-infra/`.

### 1. Verify OPA is installed

```bash
opa version
```

This project was tested with OPA `1.17.0` using Rego v1 syntax.

### 2. Evaluate the failing example

```bash
opa eval --format pretty \
  --data policies/ai-lifecycle-governance.rego \
  --input mock-infra/failed-example.json \
  "data.ai.lifecycle.governance.deny"
```

Expected result: OPA returns four policy violations:

- `DG-001`: S3 buckets must use encryption.
- `TR-001`: Bedrock invocation logging must be enabled.
- `RAI-001`: Bedrock Guardrails must be enabled.
- `SEC-001`: IAM policies cannot use wildcard permissions.

### 3. Evaluate the passing example

```bash
opa eval --format pretty \
  --data policies/ai-lifecycle-governance.rego \
  --input mock-infra/passed-example.json \
  "data.ai.lifecycle.governance.allow"
```

Expected result:

```text
true
```

### 4. Check the deployment gate directly

```bash
opa eval --format pretty \
  --data policies/ai-lifecycle-governance.rego \
  --input mock-infra/failed-example.json \
  "data.ai.lifecycle.governance.allow"
```

Expected result for the failing example:

```text
false
```

Use `deny` when you want the detailed compliance findings. Use `allow` when you only need the pass/fail deployment gate decision.



## Three-Layer Delivery Roadmap

This project is organized as the enterprise AI governance platform hiring managers expect for Cloud Governance, DevSecOps, AI Governance, MLOps, and AWS AI/Bedrock roles.

### Week 1 - Visualization Layer

- React Dashboard: `web/`
- Policy Pages: dashboard corporate governance cards and policy docs
- AI Lifecycle Page: dashboard lifecycle module and `docs/visualization-layer.md`

Run the dashboard:

```bash
npm install
npm run dashboard
```

### Week 2 - Enforcement and Reporting Layer

- Real OPA/Rego evaluation: `policies/ai-lifecycle-governance.rego`
- Compliance report generation: `scripts/generate-compliance-report.mjs`

Generate a compliance report:

```bash
npm run report
```

Reports are written to:

- `reports/compliance-report.md`
- `reports/compliance-report.json`

### Week 3 - CI/CD Governance Gate

- GitHub Actions pipeline: `.github/workflows/ai-governance-gate.yml`
- Pass/fail deployment simulation using `mock-infra/failed-example.json` and `mock-infra/passed-example.json`
- Deployment approval gate using `data.ai.lifecycle.governance.allow`

## Platform Modules

| Module | Capability | Implementation |
| --- | --- | --- |
| Module 1 | Dashboard: compliance score, violations, deployment status, risk level | `web/src/App.tsx` |
| Module 2 | Corporate AI Governance: Responsible AI, Data Privacy, Transparency, AI Security | `terraform/policy_framework.tf`, `web/src/data.ts` |
| Module 3 | AI Lifecycle Governance: scoping, data collection, training, validation, deployment, monitoring, retirement | `terraform/pac_lifecycle.tf`, `web/src/data.ts` |
| Module 4 | Policy Engine: OPA, Rego, ISO 42001 controls | `policies/ai-lifecycle-governance.rego` |
| Module 5 | CI/CD Governance Gate: GitHub Actions, policy evaluation, deployment approval | `.github/workflows/ai-governance-gate.yml` |
| Module 6 | Compliance Reports: violations, remediation, audit evidence | `scripts/generate-compliance-report.mjs` |
