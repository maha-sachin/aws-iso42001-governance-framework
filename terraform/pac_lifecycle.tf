locals {
  ai_lifecycle_stages = {
    data_collection = {
      name           = "Data Collection"
      aws_components = ["S3 training data bucket", "Macie sensitive data discovery"]
      controls       = ["Data classification", "Public access block", "Encryption at rest"]
    }

    data_preparation = {
      name           = "Data Preparation"
      aws_components = ["Lake Formation governed table", "KMS key"]
      controls       = ["Encryption in transit", "Data retention", "Fine-grained access"]
    }

    model_development = {
      name           = "Model Development"
      aws_components = ["SageMaker model package", "Model card"]
      controls       = ["Approved models only", "Version tracking", "Model owner assignment"]
    }

    model_validation = {
      name           = "Model Validation"
      aws_components = ["SageMaker model card review", "Human approval workflow"]
      controls       = ["Human oversight", "Bias and safety review", "Approval evidence"]
    }

    deployment = {
      name           = "Deployment"
      aws_components = ["Amazon Bedrock application", "IAM execution role"]
      controls       = ["Bedrock Guardrails", "Least privilege IAM", "Security review"]
    }

    monitoring = {
      name           = "Monitoring"
      aws_components = ["CloudWatch Logs", "CloudTrail", "Security Hub"]
      controls       = ["Invocation logging", "Incident detection", "Continuous compliance"]
    }
  }

  pac_rules = {
    data_encryption = {
      id             = "DG-001"
      iso            = "ISO/IEC 42001 A.6.2"
      policy         = "Data Privacy Policy"
      rule           = "S3 buckets used for AI data must use encryption."
      passed         = var.mock_aws_ai_infrastructure.s3.encryption
      violation      = "s3.encryption is false"
      recommendation = "Enable S3 default encryption with AWS KMS."
    }

    invocation_logging = {
      id             = "TR-001"
      iso            = "ISO/IEC 42001 A.7.2"
      policy         = "Transparency Policy"
      rule           = "Bedrock invocation logging must be enabled."
      passed         = var.mock_aws_ai_infrastructure.bedrock.logging
      violation      = "bedrock.logging is false"
      recommendation = "Enable Bedrock invocation logging to CloudWatch Logs."
    }

    guardrails_enabled = {
      id             = "RAI-001"
      iso            = "ISO/IEC 42001 A.8.4"
      policy         = "Responsible AI Policy"
      rule           = "Bedrock Guardrails must be enabled for generative AI workloads."
      passed         = var.mock_aws_ai_infrastructure.bedrock.guardrails
      violation      = "bedrock.guardrails is false"
      recommendation = "Attach an approved Bedrock Guardrail before deployment."
    }

    least_privilege_iam = {
      id             = "SEC-001"
      iso            = "Security Control"
      policy         = "AI Security Policy"
      rule           = "IAM policies cannot use wildcard permissions."
      passed         = var.mock_aws_ai_infrastructure.iam.policy != "*"
      violation      = "iam.policy is *"
      recommendation = "Replace wildcard permissions with scoped least-privilege IAM statements."
    }
  }

  pac_violations = {
    for key, rule in local.pac_rules : key => {
      id             = rule.id
      iso            = rule.iso
      policy         = rule.policy
      rule           = rule.rule
      violation      = rule.violation
      recommendation = rule.recommendation
    } if !rule.passed
  }

  total_controls   = length(local.pac_rules)
  failed_controls  = length(local.pac_violations)
  passed_controls  = local.total_controls - local.failed_controls
  compliance_score = floor((local.passed_controls / local.total_controls) * 100)
  risk_level       = local.compliance_score >= 90 ? "Low" : local.compliance_score >= 70 ? "Medium" : "High"
  gate_decision    = local.failed_controls == 0 ? "PASS" : "FAIL"
}

resource "null_resource" "ai_lifecycle_stage" {
  for_each = local.ai_lifecycle_stages

  triggers = {
    stage          = each.value.name
    aws_components = jsonencode(each.value.aws_components)
    controls       = jsonencode(each.value.controls)
    gate_decision  = local.gate_decision
  }
}

resource "null_resource" "pac_control" {
  for_each = local.pac_rules

  triggers = {
    id             = each.value.id
    iso            = each.value.iso
    policy         = each.value.policy
    rule           = each.value.rule
    status         = each.value.passed ? "PASS" : "FAIL"
    violation      = each.value.passed ? "" : each.value.violation
    recommendation = each.value.recommendation
  }
}

resource "null_resource" "deployment_gate" {
  triggers = {
    decision         = local.gate_decision
    compliance_score = tostring(local.compliance_score)
    risk_level       = local.risk_level
    violations       = jsonencode(local.pac_violations)
  }
}
