output "framework_root" {
  description = "Path to framework root"
  value       = path.cwd
}

output "corporate_ai_policies" {
  description = "Corporate AI governance policies mapped to ISO 42001 and AWS services."
  value       = local.corporate_ai_policies
}

output "operational_ai_policies" {
  description = "Operational AI governance controls used by lifecycle gates."
  value       = local.operational_ai_policies
}

output "ai_lifecycle_stages" {
  description = "AWS AI lifecycle stages and governance controls."
  value       = local.ai_lifecycle_stages
}

output "policy_as_code_controls" {
  description = "Policy-as-Code controls evaluated against mock AWS AI infrastructure."
  value       = local.pac_rules
}

output "policy_violations" {
  description = "Failed Policy-as-Code controls with recommendations."
  value       = local.pac_violations
}

output "compliance_summary" {
  description = "AI governance compliance score and deployment gate decision."
  value = {
    total_controls     = local.total_controls
    passed_controls    = local.passed_controls
    failed_controls    = local.failed_controls
    compliance_score   = local.compliance_score
    risk_level         = local.risk_level
    deployment_gate    = local.gate_decision
    blocked_deployment = local.gate_decision == "FAIL"
  }
}
