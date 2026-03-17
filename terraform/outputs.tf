# File Purpose:
# - Expose non-secret infrastructure outputs needed for integration and deployment wiring.
#
# Key Security Considerations:
# - Avoids leaking secret values via Terraform outputs.
#
# OWASP 2025 Categories Addressed:
# - A02, A08

output "supabase_project_ref" {
  description = "Supabase project reference identifier."
  value       = supabase_project.sentinel.id
}

output "supabase_project_url" {
  description = "Supabase API URL."
  value       = supabase_project.sentinel.api_url
}

output "supabase_db_host" {
  description = "Supabase database host."
  value       = supabase_project.sentinel.db_host
}

output "vercel_project_id" {
  description = "Vercel project identifier."
  value       = vercel_project.sentinel.id
}

output "vercel_project_name" {
  description = "Vercel project name."
  value       = vercel_project.sentinel.name
}

output "vercel_project_url" {
  description = "Primary Vercel project URL."
  value       = vercel_project.sentinel.url
}
