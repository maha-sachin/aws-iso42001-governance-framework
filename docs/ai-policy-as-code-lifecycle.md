# AI Policy-as-Code Lifecycle

This framework translates corporate AI governance policies into operational controls and then into Policy-as-Code checks across the AWS AI lifecycle.

The shared policy model is stored in `policies/ai-governance-policy-model.json`. Terraform and the dashboard both read this file for corporate policies, operational policies, and lifecycle stage definitions.

## Corporate AI Policies

| Policy | Requirements | AWS Mapping |
| --- | --- | --- |
| Responsible AI Policy | Safety controls, harmful content mitigation, human oversight | Amazon Bedrock Guardrails, SageMaker Model Cards |
| Data Privacy Policy | Encryption, public access prohibition, sensitive data protection | Amazon S3, AWS KMS, Macie, Lake Formation |
| Transparency Policy | Auditable AI interactions and logging | Bedrock Invocation Logging, CloudWatch Logs, CloudTrail, Athena |
| AI Security Policy | Least privilege, no wildcard permissions, security monitoring | IAM, SCPs, Security Hub, CloudTrail |
| AI Impact Assessment Policy | Impact assessment evidence before deployment | AWS Audit Manager, S3 Evidence Repository |
| AI Risk Management Policy | Risk rating and critical risk acceptance | AWS Config, Security Hub, Audit Manager |
| Production Approval Policy | Approved production change before release | CodePipeline, CodeBuild, Systems Manager Change Manager |

## Operational Policies

- Data Governance: encryption at rest, encryption in transit, data classification, data retention.
- Model Governance: approved models only, version tracking, model approval process.
- Deployment Governance: logging enabled, guardrails enabled, security review complete.
- Monitoring Governance: continuous compliance monitoring, audit logging, incident detection.
- Impact Assessment Governance: completed assessment, named owner, review date.
- Risk Governance: risk rating assigned, critical risk accepted, risk score captured.

## AWS AI Lifecycle Enforcement

```text
Data Collection -> Data Preparation -> Model Development -> Model Validation -> Deployment -> Monitoring
```

Each stage is represented by Terraform `null_resource` controls so the framework can demonstrate governance enforcement without creating real AWS infrastructure.

## Policy-as-Code Rules

The Terraform implementation computes policy violations in `terraform/pac_lifecycle.tf`. The equivalent OPA/Rego rules are stored in `policies/ai-lifecycle-governance.rego`.

Controls enforced:

- `DG-001`: S3 buckets used for AI data must use customer-managed KMS keys.
- `TR-001`: Bedrock invocation logging must be enabled.
- `RAI-001`: Bedrock Guardrails must be enabled.
- `SEC-001`: IAM policies cannot use wildcard permissions.
- `GOV-001`: AI impact assessment must be completed.
- `GOV-002`: Critical AI risk must be accepted before deployment.
- `GOV-003`: Production approval is required.

The deployment gate returns `PASS` only when all controls pass. Otherwise, the framework reports violations, recommendations, compliance score, and risk level.


See `docs/policy-as-code.md` for the full Layer 3 Rego implementation.
