package ai.lifecycle.governance

default allow := false

allow {
  count(deny) == 0
}

deny[msg] {
  input.s3.encryption == false
  msg := {
    "id": "DG-001",
    "iso": "ISO/IEC 42001 A.6.2",
    "policy": "Data Privacy Policy",
    "message": "S3 buckets used for AI data must use encryption.",
    "recommendation": "Enable S3 default encryption with AWS KMS."
  }
}

deny[msg] {
  input.s3.public_access == true
  msg := {
    "id": "DG-002",
    "iso": "ISO/IEC 42001 A.6.2",
    "policy": "Data Privacy Policy",
    "message": "AI data stores must block public access.",
    "recommendation": "Enable S3 Block Public Access for AI data buckets."
  }
}

deny[msg] {
  input.bedrock.logging == false
  msg := {
    "id": "TR-001",
    "iso": "ISO/IEC 42001 A.7.2",
    "policy": "Transparency Policy",
    "message": "Bedrock invocation logging must be enabled.",
    "recommendation": "Enable Bedrock invocation logging to CloudWatch Logs."
  }
}

deny[msg] {
  input.bedrock.guardrails == false
  msg := {
    "id": "RAI-001",
    "iso": "ISO/IEC 42001 A.8.4",
    "policy": "Responsible AI Policy",
    "message": "Bedrock Guardrails must be enabled for generative AI workloads.",
    "recommendation": "Attach an approved Bedrock Guardrail before deployment."
  }
}

deny[msg] {
  input.iam.policy == "*"
  msg := {
    "id": "SEC-001",
    "iso": "Security Control",
    "policy": "AI Security Policy",
    "message": "IAM policies cannot use wildcard permissions.",
    "recommendation": "Replace wildcard permissions with scoped least-privilege IAM statements."
  }
}
