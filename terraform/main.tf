# File Purpose:
# - Provision Sentinel CI cloud resources in Supabase and Vercel.
#
# Key Security Considerations:
# - Secrets are injected as sensitive variables and platform environment variables.
# - Project-level settings avoid hardcoded credentials and keep server-only keys private.
#
# OWASP 2025 Categories Addressed:
# - A02, A03, A08

terraform {
  required_version = ">= 1.7.0"

  required_providers {
    vercel = {
      source  = "vercel/vercel"
      version = "~> 2.0"
    }
    supabase = {
      source  = "supabase/supabase"
      version = "~> 1.0"
    }
  }
}

provider "vercel" {
  api_token = var.vercel_api_token
  team      = var.vercel_team_id
}

provider "supabase" {
  access_token = var.supabase_access_token
}

resource "supabase_project" "sentinel" {
  organization_id   = var.supabase_organization_id
  name              = var.supabase_project_name
  region            = var.supabase_region
  database_password = var.database_password
}

resource "supabase_auth_external_github" "github" {
  project_ref   = supabase_project.sentinel.id
  enabled       = true
  client_id     = var.github_oauth_client_id
  client_secret = var.github_oauth_client_secret
}

resource "vercel_project" "sentinel" {
  name      = var.vercel_project_name
  framework = "other"

  git_repository = {
    type = "github"
    repo = var.vercel_git_repository
  }
}

resource "vercel_project_environment_variable" "supabase_url" {
  project_id = vercel_project.sentinel.id
  key        = "SUPABASE_URL"
  value      = supabase_project.sentinel.api_url
  target     = ["production", "preview", "development"]
}

resource "vercel_project_environment_variable" "supabase_anon_key" {
  project_id = vercel_project.sentinel.id
  key        = "SUPABASE_ANON_KEY"
  value      = supabase_project.sentinel.anon_key
  target     = ["production", "preview", "development"]
}

resource "vercel_project_environment_variable" "supabase_service_role_key" {
  project_id = vercel_project.sentinel.id
  key        = "SUPABASE_SERVICE_ROLE_KEY"
  value      = supabase_project.sentinel.service_role_key
  target     = ["production", "preview", "development"]
}

resource "vercel_project_environment_variable" "github_oauth_client_id" {
  project_id = vercel_project.sentinel.id
  key        = "GITHUB_OAUTH_CLIENT_ID"
  value      = var.github_oauth_client_id
  target     = ["production", "preview", "development"]
}

resource "vercel_project_environment_variable" "github_oauth_client_secret" {
  project_id = vercel_project.sentinel.id
  key        = "GITHUB_OAUTH_CLIENT_SECRET"
  value      = var.github_oauth_client_secret
  target     = ["production", "preview", "development"]
}

resource "vercel_project_environment_variable" "defectdojo_url" {
  project_id = vercel_project.sentinel.id
  key        = "DEFECTDOJO_URL"
  value      = var.defectdojo_url
  target     = ["production", "preview", "development"]
}

resource "vercel_project_environment_variable" "defectdojo_api_key" {
  project_id = vercel_project.sentinel.id
  key        = "DEFECTDOJO_API_KEY"
  value      = var.defectdojo_api_key
  target     = ["production", "preview", "development"]
}

resource "vercel_project_environment_variable" "sentinel_webhook_secret" {
  project_id = vercel_project.sentinel.id
  key        = "SENTINEL_WEBHOOK_SECRET"
  value      = var.sentinel_webhook_secret
  target     = ["production", "preview", "development"]
}
