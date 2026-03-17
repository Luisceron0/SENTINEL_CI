<!--
File Purpose:
- Define contribution workflow and mandatory security requirements for pull requests.

Key Security Considerations:
- Requires security tests and static checks before merge.

OWASP 2025 Categories Addressed:
- A03, A06, A09, A10
-->

# Contributing to Sentinel CI

## Pull Request Requirements
1. No secrets in code, comments, or fixtures.
2. All new files include security comment block and OWASP mapping.
3. Security-sensitive changes include test coverage.
4. Conventional commit messages required.

## Required Local Checks
1. ruff check .
2. mypy api/
3. pytest tests/
4. eslint dashboard/src/
5. bash tests/action/test_scripts_exist.sh
6. bash tests/action/test_aggregate_contract.sh

## Security Rules
1. Use validate_webhook_url for all webhook URL paths.
2. Use verify_api_key as single API key verification source.
3. Do not use raw SQL string composition.
4. Do not use MD5/SHA1 or custom crypto.
5. Preserve fail-secure behavior on scanner/API errors.

## Review Process
1. Open PR with scope and risk summary.
2. Attach validation command output.
3. Address review findings and re-run checks before merge.
