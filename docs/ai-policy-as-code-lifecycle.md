# AI Policy-as-Code Lifecycle

This framework translates corporate AI governance policies into operational controls and then into Policy-as-Code checks across the AWS AI lifecycle.

## Corporate AI Policies

| Policy | Requirements | AWS Mapping |
| --- | --- | --- |
| Responsible AI Policy | Safety controls, harmful content mitigation, human oversight | Amazon Bedrock Guardrails, SageMaker Model Cards |
| Data Privacy Policy | Encryption, public access prohibition, sensitive data protection | Amazon S3, AWS KMS, Macie, Lake Formation |
| Transparency Policy | Auditable AI interactions and logging | Bedrock Invocation Logging, CloudWatch Logs, CloudTrail, Athena |
| AI Security Policy | Least privilege, no wildcard permissions, security monitoring | IAM, SCPs, Security Hub, CloudTrail |

## Operational Policies

- Data Governance: encryption at rest, encryption in transit, data classification, data retention, public access block.
- Model Governance: approved models only, version tracking, model approval, human oversight.
- Deployment Governance: logging enabled, guardrails enabled, security review complete, PaC gate passed.
- Monitoring Governance: continuous compliance monitoring, audit logging, incident detection, evidence reporting.

## AWS AI Lifecycle Enforcement

```text
Data Collection -> Data Preparation -> Model Development -> Model Validation -> Deployment -> Monitoring
```

Each stage is represented by Terraform `null_resource` controls so the framework can demonstrate governance enforcement without creating real AWS infrastructure.

## Policy-as-Code Rules

The Terraform implementation computes policy violations in `pac_lifecycle.tf`. The equivalent OPA/Rego rules are stored in `policies/ai-lifecycle-governance.rego`.

Controls enforced:

- `DG-001`: S3 buckets used for AI data must use encryption.
- `DG-002`: AI data stores must block public access.
- `TR-001`: Bedrock invocation logging must be enabled.
- `RAI-001`: Bedrock Guardrails must be enabled.
- `SEC-001`: IAM policies cannot use wildcard permissions.

The deployment gate returns `PASS` only when all controls pass. Otherwise, the framework reports violations, recommendations, compliance score, and risk level.
