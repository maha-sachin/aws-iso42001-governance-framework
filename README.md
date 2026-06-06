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
├── main.tf                        # Root orchestration
├── variables.tf                   # Global variables
├── outputs.tf                     # Framework outputs
├── versions.tf                    # Provider constraints
├── terraform.tfvars.example       # Example configuration
│
├── modules/
│   ├── ai-governance/             # ISO 42001 §6 — Planning & Governance
│   │   ├── main.tf
│   │   ├── scp_policies.tf        # Service Control Policies
│   │   ├── iam_roles.tf           # AI Officer / Reviewer roles
│   │   └── variables.tf
│   │
│   ├── ai-safety/                 # ISO 42001 §8 — Operation & Safety
│   │   ├── main.tf
│   │   ├── bedrock_guardrails.tf  # Content & topic filtering
│   │   ├── sagemaker_controls.tf  # Model card enforcement
│   │   └── variables.tf
│   │
│   ├── risk-management/           # ISO 42001 §6.1 — Risk Assessment
│   │   ├── main.tf
│   │   ├── config_rules.tf        # AWS Config custom rules
│   │   ├── security_hub.tf        # Security Hub standards
│   │   └── variables.tf
│   │
│   ├── data-privacy/              # ISO 42001 §8.4 — Data for AI
│   │   ├── main.tf
│   │   ├── macie_config.tf        # PII detection in training data
│   │   ├── lake_formation.tf      # Fine-grained data access
│   │   └── variables.tf
│   │
│   ├── monitoring/                # ISO 42001 §9 — Performance & Monitoring
│   │   ├── main.tf
│   │   ├── cloudwatch_alarms.tf   # AI system drift alarms
│   │   ├── eventbridge_rules.tf   # Compliance event routing
│   │   └── variables.tf
│   │
│   └── compliance-controls/       # ISO 42001 §9.1 — Audit & Evidence
│       ├── main.tf
│       ├── cloudtrail.tf          # Immutable audit trail
│       ├── athena_queries.tf      # Compliance reporting
│       └── variables.tf
│
├── policies/
│   ├── scp-ai-governance.json     # SCP: Restrict unapproved AI services
│   ├── scp-data-boundary.json     # SCP: Data residency enforcement
│   └── iam-ai-least-privilege.json
│
└── docs/
	├── iso42001-control-mapping.md
	└── deployment-guide.md
```

---

## 🚀 Quick Start

```bash
# 1. Clone and configure
git clone https://github.com/yourname/aws-iso42001-governance-framework
cd aws-iso42001-governance-framework
cp terraform.tfvars.example terraform.tfvars

# 2. Edit your org settings
vim terraform.tfvars

# 3. Initialize and deploy
terraform init
terraform plan -out=governance.tfplan
terraform apply governance.tfplan
```

---

## 🔐 ISO 42001 Control Mapping

### Clause 6 — Planning

- **6.1.2** AI Risk Assessment → `modules/risk-management/config_rules.tf`
- **6.2** AI Objectives → `modules/ai-governance/iam_roles.tf`

### Clause 8 — Operation

- **8.2** AI System Impact Assessment → `modules/ai-safety/sagemaker_controls.tf`
- **8.4** Data Acquisition & Preparation → `modules/data-privacy/macie_config.tf`
- **8.5** AI System Design → `modules/ai-safety/bedrock_guardrails.tf`
- **8.6** AI System Verification → `modules/monitoring/cloudwatch_alarms.tf`

### Clause 9 — Performance Evaluation

- **9.1** Monitoring & Measurement → `modules/monitoring/`
- **9.2** Internal Audit → `modules/compliance-controls/cloudtrail.tf`
- **9.3** Management Review → `modules/compliance-controls/athena_queries.tf`

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

- `policy_framework.tf` defines corporate and operational AI policies.
- `pac_lifecycle.tf` implements lifecycle stage gates and Terraform-native PaC evaluation.
- `policies/ai-lifecycle-governance.rego` contains the equivalent OPA/Rego controls.
- `mock-infra/failed-example.json` and `mock-infra/passed-example.json` provide demo input postures.
- `docs/ai-policy-as-code-lifecycle.md` documents the governance lifecycle.

Run:

```bash
terraform fmt -recursive
terraform validate
terraform plan
```

By default, the mock infrastructure is intentionally non-compliant, so the plan outputs a failed deployment gate and remediation recommendations. Override `mock_aws_ai_infrastructure` in `terraform.tfvars` to simulate a passing environment.
