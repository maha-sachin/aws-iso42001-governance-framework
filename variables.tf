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
      encryption    = bool
      public_access = bool
    })
    bedrock = object({
      logging    = bool
      guardrails = bool
    })
    iam = object({
      policy = string
    })
  })
  default = {
    s3 = {
      encryption    = false
      public_access = true
    }
    bedrock = {
      logging    = false
      guardrails = false
    }
    iam = {
      policy = "*"
    }
  }
}
