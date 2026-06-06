package ai.lifecycle.governance

default allow := false

allow if {
  count(deny) == 0
}

# ISO A.6.2 Data Governance
# Rule: S3 buckets must use encryption.
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

# ISO A.7.2 Transparency
# Rule: Bedrock invocation logging must be enabled.
deny contains msg if {
  input.bedrock.logging == false
  msg := {
    "id": "TR-001",
    "iso": "ISO/IEC 42001 A.7.2",
    "domain": "Transparency",
    "policy": "Transparency Policy",
    "rule": "Bedrock invocation logging must be enabled.",
    "violation": {"bedrock": {"logging": false}},
    "recommendation": "Enable Bedrock invocation logging to CloudWatch Logs."
  }
}

# ISO A.8.4 Responsible AI
# Rule: Bedrock Guardrails must be enabled.
deny contains msg if {
  input.bedrock.guardrails == false
  msg := {
    "id": "RAI-001",
    "iso": "ISO/IEC 42001 A.8.4",
    "domain": "Responsible AI",
    "policy": "Responsible AI Policy",
    "rule": "Bedrock Guardrails must be enabled.",
    "violation": {"bedrock": {"guardrails": false}},
    "recommendation": "Attach an approved Bedrock Guardrail before deployment."
  }
}

# Security Control
# Rule: IAM policies cannot use wildcard permissions.
deny contains msg if {
  input.iam.policy == "*"
  msg := {
    "id": "SEC-001",
    "iso": "Security Control",
    "domain": "AI Security",
    "policy": "AI Security Policy",
    "rule": "IAM policies cannot use wildcard permissions.",
    "violation": {"iam": {"policy": "*"}},
    "recommendation": "Replace wildcard permissions with scoped least-privilege IAM statements."
  }
}
