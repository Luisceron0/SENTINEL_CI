# File Purpose:
# - Define Terraform input variables for Sentinel CI infrastructure provisioning.
#
# Key Security Considerations:
# - Separates secret-bearing values from code and enforces explicit input declarations.
#
# OWASP 2025 Categories Addressed:
# - A02, A03, A08

variable "vercel_api_token" {
  description = "Vercel API token used by Terraform provider."
  type        = string
  sensitive   = true
}

variable "vercel_team_id" {
  description = "Vercel team identifier (optional for personal scope)."
  type        = string
  default     = null
}

variable "vercel_project_name" {
  description = "Vercel project name for Sentinel CI deployments."
  type        = string
}

variable "vercel_git_repository" {
  description = "Git repository in owner/repo format connected to Vercel project."
  type        = string
}

variable "supabase_access_token" {
  description = "Supabase access token used by Terraform provider."
  type        = string
  sensitive   = true
}

variable "supabase_organization_id" {
  description = "Supabase organization ID where the project will be created."
  type        = string
}

variable "supabase_project_name" {
  description = "Supabase project name for Sentinel CI data and auth."
  type        = string
}

variable "supabase_region" {
  description = "Supabase region code for project provisioning."
  type        = string
  default     = "us-east-1"
}

variable "database_password" {
  description = "Initial database password for Supabase project."
  type        = string
  sensitive   = true
}

variable "github_oauth_client_id" {
  description = "GitHub OAuth client ID configured in Supabase Auth."
  type        = string
}

variable "github_oauth_client_secret" {
  description = "GitHub OAuth client secret configured in Supabase Auth."
  type        = string
  sensitive   = true
}

variable "defectdojo_url" {
  description = "DefectDojo base URL used by Sentinel API integration."
  type        = string
}

variable "defectdojo_api_key" {
  description = "DefectDojo API key used by Sentinel API integration."
  type        = string
  sensitive   = true
}

variable "sentinel_webhook_secret" {
  description = "Default HMAC secret for GitHub webhook verification in Sentinel API."
  type        = string
  sensitive   = true
}
