# Layer 2 - Operational AI Policies

Operational policies convert corporate AI governance requirements into concrete controls that can be evaluated during the AWS AI lifecycle.

## Data Governance

Controls:

- Encryption at Rest
- Encryption in Transit
- Data Classification
- Data Retention

AWS lifecycle coverage:

- Data Collection
- Data Preparation

## Model Governance

Controls:

- Approved Models Only
- Version Tracking
- Model Approval Process

AWS lifecycle coverage:

- Model Development
- Model Validation

## Deployment Governance

Controls:

- Logging Enabled
- Guardrails Enabled
- Security Review Complete

AWS lifecycle coverage:

- Deployment

## Monitoring Governance

Controls:

- Continuous Compliance Monitoring
- Audit Logging
- Incident Detection

AWS lifecycle coverage:

- Monitoring

## Terraform Implementation

These operational policies are implemented in `terraform/policy_framework.tf` as `local.operational_ai_policies` and materialized as `null_resource.operational_ai_policy` resources. The policies are exposed through the `operational_ai_policies` Terraform output.

The Policy-as-Code enforcement layer in `terraform/pac_lifecycle.tf` maps these operational controls to concrete deployment gates and compliance findings.
