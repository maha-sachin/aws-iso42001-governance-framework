variable "aws_region" {
  description = "AWS region to deploy into"
  type        = string
  default     = "us-east-1"
}

variable "organization_id" {
  description = "AWS Organization ID"
  type        = string
  default     = ""
}


variable "mock_aws_ai_infrastructure" {
  description = "Mock AWS AI infrastructure posture evaluated by policy-as-code controls."
  type = object({
    s3 = object({
      kms_key_type  = string
      public_access = bool
    })
    bedrock = object({
      invocation_logging_enabled = bool
      guardrails_enabled         = bool
    })
    iam = object({
      wildcard_permissions = bool
    })
    impact_assessment = object({
      completed     = bool
      assessment_id = string
      owner         = string
      reviewed_at   = string
    })
    risk = object({
      rating   = string
      score    = number
      accepted = bool
    })
    production_approval = object({
      approved = bool
      approver = string
      ticket   = string
    })
  })
  default = {
    s3 = {
      kms_key_type  = "AWS_MANAGED"
      public_access = true
    }
    bedrock = {
      invocation_logging_enabled = false
      guardrails_enabled         = false
    }
    iam = {
      wildcard_permissions = true
    }
    impact_assessment = {
      completed     = false
      assessment_id = ""
      owner         = ""
      reviewed_at   = ""
    }
    risk = {
      rating   = "critical"
      score    = 92
      accepted = false
    }
    production_approval = {
      approved = false
      approver = ""
      ticket   = ""
    }
  }
}
