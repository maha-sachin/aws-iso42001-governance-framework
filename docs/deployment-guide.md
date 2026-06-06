# Deployment Guide (minimal)

1. Copy `terraform.tfvars.example` to `terraform.tfvars` and fill values.
2. Run `terraform init` then `terraform plan` and `terraform apply`.
3. Enable modules incrementally and review SCP/IAM JSON before applying to organizations.
