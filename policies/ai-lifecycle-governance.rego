package ai.lifecycle.governance

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
    "reason": sprintf("Bucket %s uses %s KMS instead of CUSTOMER_MANAGED", [bucket.name, bucket.kms_key_type])
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
    "reason": sprintf("Model %s has invocation logging disabled", [model.name])
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
    "reason": sprintf("Model %s does not have guardrails enabled", [model.name])
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
    "reason": sprintf("IAM role %s contains wildcard permissions", [role.name])
  }
}
