# EKS OIDC / IRSA support for IAM roles
# Allows Kubernetes service accounts to assume this IAM role

variable "eks_oidc_provider_enabled" {
  type        = bool
  description = "Enable EKS OIDC provider for IRSA (IAM Roles for Service Accounts)"
  default     = false
}

variable "eks_oidc_provider_arn" {
  type        = string
  description = <<-EOT
    ARN of the EKS OIDC provider. Required when eks_oidc_provider_enabled is true.
    Format: arn:aws:iam::<account-id>:oidc-provider/oidc.eks.<region>.amazonaws.com/id/<cluster-id>
    EOT
  default     = ""

  validation {
    condition     = !var.eks_oidc_provider_enabled || var.eks_oidc_provider_arn != ""
    error_message = "eks_oidc_provider_arn must be set if EKS OIDC provider is enabled"
  }
}

variable "eks_oidc_issuer_url" {
  type        = string
  description = <<-EOT
    The OIDC issuer URL from the EKS cluster (without https:// prefix).
    Format: oidc.eks.<region>.amazonaws.com/id/<cluster-id>
    If not specified, it will be derived from eks_oidc_provider_arn.
    EOT
  default     = ""
}

variable "service_account_name" {
  type        = string
  description = <<-EOT
    The name of the Kubernetes service account allowed to assume this role.
    Use '*' to allow any service account in the namespace.
    Defaults to module.this.name if not specified.
    EOT
  default     = null
}

variable "service_account_namespace" {
  type        = string
  description = <<-EOT
    The Kubernetes namespace of the service account allowed to assume this role.
    Defaults to module.this.name if not specified.
    EOT
  default     = null
}

locals {
  eks_oidc_enabled = local.enabled && var.eks_oidc_provider_enabled

  # Default service account namespace and name to the component name if not specified
  # Use try() to handle the case when module.this.name is empty (e.g., when enabled=false)
  service_account_namespace = local.eks_oidc_enabled ? coalesce(var.service_account_namespace, module.this.name) : ""
  service_account_name      = local.eks_oidc_enabled ? coalesce(var.service_account_name, module.this.name) : ""

  # Extract OIDC issuer URL from ARN if not explicitly provided
  # ARN format: arn:aws:iam::<account-id>:oidc-provider/<issuer-url>
  eks_oidc_issuer_url = local.eks_oidc_enabled ? coalesce(
    var.eks_oidc_issuer_url,
    try(regex("oidc-provider/(.+)$", var.eks_oidc_provider_arn)[0], "")
  ) : ""

  # Construct the subject claim for the service account
  # Format: system:serviceaccount:<namespace>:<service-account-name>
  eks_service_account_subject = local.eks_oidc_enabled ? "system:serviceaccount:${local.service_account_namespace}:${local.service_account_name}" : ""
}

data "aws_iam_policy_document" "eks_oidc_provider_assume" {
  count = local.eks_oidc_enabled ? 1 : 0

  statement {
    sid = "EksOidcProviderAssume"
    actions = [
      "sts:AssumeRoleWithWebIdentity",
      "sts:TagSession",
    ]

    principals {
      type        = "Federated"
      identifiers = [var.eks_oidc_provider_arn]
    }

    # Verify the audience is AWS STS
    condition {
      test     = "StringEquals"
      variable = "${local.eks_oidc_issuer_url}:aud"
      values   = ["sts.amazonaws.com"]
    }

    # Restrict to specific namespace and service account
    # Use StringLike to support wildcards in service account name
    condition {
      test     = local.service_account_name == "*" ? "StringLike" : "StringEquals"
      variable = "${local.eks_oidc_issuer_url}:sub"
      values   = [local.eks_service_account_subject]
    }
  }
}

output "eks_assume_role_policy" {
  value       = local.eks_oidc_enabled ? one(data.aws_iam_policy_document.eks_oidc_provider_assume[*].json) : null
  description = "JSON encoded string representing the EKS OIDC \"Assume Role\" policy"
}

output "eks_oidc_provider_arn" {
  value       = local.eks_oidc_enabled ? var.eks_oidc_provider_arn : null
  description = "ARN of the EKS OIDC provider (pass-through for reference)"
}

output "eks_service_account_subject" {
  value       = local.eks_service_account_subject
  description = "The service account subject claim used in the trust policy"
}
