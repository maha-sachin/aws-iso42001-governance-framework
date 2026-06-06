# Layer 3 - Policy-as-Code

Layer 3 implements Open Policy Agent policies using Rego. These rules translate the corporate and operational AI governance requirements into deployment gates over mock AWS AI infrastructure.

Policy file:

- `policies/ai-lifecycle-governance.rego`

Mock inputs:

- `mock-infra/failed-example.json`
- `mock-infra/passed-example.json`

## OPA Package

```rego
package ai.lifecycle.governance
```

The deployment is allowed only when no `deny` rule is returned:

```rego
default allow := false

allow if {
  count(deny) == 0
}
```

## ISO A.6.2 Data Governance

Rule: S3 buckets must use encryption.

Example violation:

```json
{
  "encryption": false
}
```

Project mock input shape:

```json
{
  "s3": {
    "encryption": false
  }
}
```

Rego control:

```rego
deny contains msg if {
  input.s3.encryption == false
  msg := {
    "id": "DG-001",
    "iso": "ISO/IEC 42001 A.6.2",
    "domain": "Data Governance",
    "policy": "Data Privacy Policy",
    "rule": "S3 buckets must use encryption.",
    "violation": {"s3": {"encryption": false}},
    "recommendation": "Enable S3 default encryption with AWS KMS."
  }
}
```

## ISO A.7.2 Transparency

Rule: Bedrock invocation logging must be enabled.

Example violation:

```json
{
  "bedrock": {
    "logging": false
  }
}
```

## ISO A.8.4 Responsible AI

Rule: Bedrock Guardrails must be enabled.

Example violation:

```json
{
  "bedrock": {
    "guardrails": false
  }
}
```

## Security Control

Rule: IAM policies cannot use wildcard permissions.

Example violation:

```json
{
  "iam": {
    "policy": "*"
  }
}
```

## Evaluation Commands

```bash
opa eval --format pretty \
  --data policies/ai-lifecycle-governance.rego \
  --input mock-infra/failed-example.json \
  "data.ai.lifecycle.governance.deny"
```

```bash
opa eval --format pretty \
  --data policies/ai-lifecycle-governance.rego \
  --input mock-infra/passed-example.json \
  "data.ai.lifecycle.governance.allow"
```

## Terraform Integration

`terraform/pac_lifecycle.tf` mirrors these same four controls as Terraform-native computed policy checks. The `deployment_gate` resource and `compliance_summary` output expose pass/fail state, failed controls, compliance score, risk level, and recommendations.
