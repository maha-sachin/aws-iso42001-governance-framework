locals {
  ai_lifecycle_stages = {
    for stage in local.ai_governance_policy_model.ai_lifecycle_stages : stage.key => stage
  }

  pac_rules = {
    data_encryption = {
      id             = "DG-001"
      iso            = "ISO/IEC 42001 A.6.2"
      policy         = "Data Privacy Policy"
      rule           = "S3 buckets used for AI data must use customer-managed KMS keys."
      passed         = var.mock_aws_ai_infrastructure.s3.kms_key_type == "CUSTOMER_MANAGED"
      violation      = "s3.kms_key_type is not CUSTOMER_MANAGED"
      recommendation = "Use customer-managed KMS keys for every evaluated S3 bucket."
    }

    invocation_logging = {
      id             = "TR-001"
      iso            = "ISO/IEC 42001 A.7.2"
      policy         = "Transparency Policy"
      rule           = "Bedrock invocation logging must be enabled."
      passed         = var.mock_aws_ai_infrastructure.bedrock.invocation_logging_enabled
      violation      = "bedrock.invocation_logging_enabled is false"
      recommendation = "Enable Bedrock invocation logging for every evaluated model."
    }

    guardrails_enabled = {
      id             = "RAI-001"
      iso            = "ISO/IEC 42001 A.8.4"
      policy         = "Responsible AI Policy"
      rule           = "Bedrock Guardrails must be enabled for generative AI workloads."
      passed         = var.mock_aws_ai_infrastructure.bedrock.guardrails_enabled
      violation      = "bedrock.guardrails_enabled is false"
      recommendation = "Enable Bedrock Guardrails for every evaluated model."
    }

    least_privilege_iam = {
      id             = "SEC-001"
      iso            = "Security Control"
      policy         = "AI Security Policy"
      rule           = "IAM policies cannot use wildcard permissions."
      passed         = !var.mock_aws_ai_infrastructure.iam.wildcard_permissions
      violation      = "iam.wildcard_permissions is true"
      recommendation = "Replace wildcard permissions with scoped least-privilege IAM statements."
    }

    impact_assessment = {
      id             = "GOV-001"
      iso            = "ISO/IEC 42001 A.5.2"
      policy         = "AI Impact Assessment Policy"
      rule           = "AI impact assessment must be completed."
      passed         = var.mock_aws_ai_infrastructure.impact_assessment.completed
      violation      = "impact_assessment.completed is false"
      recommendation = "Complete the AI impact assessment and attach the assessment ID before CI/CD deployment."
    }

    risk_rating = {
      id             = "GOV-002"
      iso            = "ISO/IEC 42001 A.5.3"
      policy         = "AI Risk Management Policy"
      rule           = "Critical AI risk must be accepted before deployment."
      passed         = var.mock_aws_ai_infrastructure.risk.rating != "critical" || var.mock_aws_ai_infrastructure.risk.accepted
      violation      = "risk.rating is critical and risk.accepted is false"
      recommendation = "Reduce the AI risk rating or document formal risk acceptance before the deployment gate can pass."
    }

    production_approval = {
      id             = "GOV-003"
      iso            = "ISO/IEC 42001 A.6.1"
      policy         = "Production Approval Policy"
      rule           = "Production approval is required."
      passed         = var.mock_aws_ai_infrastructure.production_approval.approved
      violation      = "production_approval.approved is false"
      recommendation = "Capture production approval with an approver and change ticket before release."
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
    stage          = each.value.stage
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
