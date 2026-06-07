package ai.lifecycle.governance

default allow := false

allow if {
  count(deny) == 0
}

deny contains finding if {
  bucket := input.s3_buckets[_]
  bucket.kms_key_type != "CUSTOMER_MANAGED"

  finding := {
    "id": "DG-001",
    "iso_control": "A.6.2",
    "title": "S3 buckets must use customer-managed KMS keys",
    "resource_type": "S3 Bucket",
    "resource_name": bucket.name,
    "severity": "critical",
    "reason": sprintf("Bucket %s uses %s KMS instead of CUSTOMER_MANAGED", [bucket.name, bucket.kms_key_type]),
    "recommendation": "Use customer-managed KMS keys for every evaluated S3 bucket."
  }
}

deny contains finding if {
  model := input.bedrock_models[_]
  model.invocation_logging_enabled == false

  finding := {
    "id": "TR-001",
    "iso_control": "A.7.2",
    "title": "Bedrock invocation logging must be enabled",
    "resource_type": "Bedrock Model",
    "resource_name": model.name,
    "severity": "high",
    "reason": sprintf("Model %s has invocation logging disabled", [model.name]),
    "recommendation": "Enable Bedrock invocation logging for every evaluated model."
  }
}

deny contains finding if {
  model := input.bedrock_models[_]
  model.guardrails_enabled == false

  finding := {
    "id": "RAI-001",
    "iso_control": "A.8.4",
    "title": "Bedrock Guardrails must be enabled",
    "resource_type": "Bedrock Model",
    "resource_name": model.name,
    "severity": "high",
    "reason": sprintf("Model %s does not have guardrails enabled", [model.name]),
    "recommendation": "Enable Bedrock Guardrails for every evaluated model."
  }
}

deny contains finding if {
  role := input.iam_roles[_]
  role.wildcard_permissions == true

  finding := {
    "id": "SEC-001",
    "iso_control": "AI Security",
    "title": "IAM wildcard permissions are not allowed",
    "resource_type": "IAM Role",
    "resource_name": role.name,
    "severity": "critical",
    "reason": sprintf("IAM role %s contains wildcard permissions", [role.name]),
    "recommendation": "Replace wildcard permissions with scoped least-privilege IAM statements."
  }
}

deny contains finding if {
  not input.impact_assessment.completed

  finding := {
    "id": "GOV-001",
    "iso_control": "A.5.2",
    "title": "AI impact assessment must be completed",
    "resource_type": "Governance Evidence",
    "resource_name": input.application,
    "severity": "high",
    "reason": "Impact assessment evidence is missing or incomplete",
    "recommendation": "Complete the AI impact assessment and attach the assessment ID before CI/CD deployment."
  }
}

deny contains finding if {
  input.risk.rating == "critical"
  not input.risk.accepted

  finding := {
    "id": "GOV-002",
    "iso_control": "A.5.3",
    "title": "Critical AI risk must be accepted before deployment",
    "resource_type": "Risk Record",
    "resource_name": input.application,
    "severity": "critical",
    "reason": sprintf("Risk rating is %s with score %v and has not been accepted", [input.risk.rating, input.risk.score]),
    "recommendation": "Reduce the AI risk rating or document formal risk acceptance before the deployment gate can pass."
  }
}

deny contains finding if {
  not input.production_approval.approved

  finding := {
    "id": "GOV-003",
    "iso_control": "A.6.1",
    "title": "Production approval is required",
    "resource_type": "Approval Evidence",
    "resource_name": input.application,
    "severity": "high",
    "reason": "Production approval evidence is missing",
    "recommendation": "Capture production approval with an approver and change ticket before release."
  }
}
