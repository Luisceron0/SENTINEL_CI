#!/bin/bash
# Pre-deployment verification checklist for Sentinel CI
# Run this before pushing to Vercel

set -e

echo "🔍 Sentinel CI Pre-Deployment Verification"
echo "=========================================="
echo ""

# Color codes
GREEN='\033[0;32m'
RED='\033[0;31m'
YELLOW='\033[1;33m'
NC='\033[0m' # No Color

# Counters
PASSED=0
FAILED=0

# Helper function
check() {
  local name=$1
  local cmd=$2
  
  if eval "$cmd" &>/dev/null; then
    echo -e "${GREEN}✓${NC} $name"
    ((PASSED++))
  else
    echo -e "${RED}✗${NC} $name"
    ((FAILED++))
  fi
}

echo "📦 Dependencies:"
check "Python 3.12+" "python3 --version | grep -E '3\.1[2-9]|3\.[2-9][0-9]'"
check "Node.js installed" "node --version"
check "npm installed" "npm --version"
check "git installed" "git --version"
echo ""

echo "📋 Project Structure:"
check "dashboard/package.json exists" "[ -f dashboard/package.json ]"
check "dashboard/astro.config.mjs exists" "[ -f dashboard/astro.config.mjs ]"
check "api/main.py exists" "[ -f api/main.py ]"
check "pyproject.toml exists" "[ -f pyproject.toml ]"
check "vercel.json exists" "[ -f vercel.json ]"
check ".env.example exists" "[ -f .env.example ]"
echo ""

echo "🧪 Tests & Linting:"
check "Python tests pass" "cd /workspaces/SENTINEL_CI && pytest tests/ -q"
check "ruff passes" "cd /workspaces/SENTINEL_CI && ruff check . &>/dev/null"
check "mypy passes" "cd /workspaces/SENTINEL_CI && mypy api/ &>/dev/null"
check "eslint passes" "npm run lint:dashboard &>/dev/null"
echo ""

echo "📝 Security:"
check "No secrets in .env.example" "! grep -E 'ghp_|sk-|^[A-Za-z0-9_-]{40,}' .env.example"
check "No hardcoded secrets in code" "! grep -r 'password.*=' api/ dashboard/ --include='*.py' --include='*.ts' --include='*.tsx' | grep -v 'schema\\|example\\|test'"
echo ""

echo "🔗 Git Status:"
check "Working directory clean" "[ -z \"\$(git status --porcelain)\" ]"
check "main branch active" "[ \"$(git rev-parse --abbrev-ref HEAD)\" = \"main\" ]"
check "No merge conflicts" "! grep -r '^<<<<<<' . --include='*.py' --include='*.json' --include='*.toml' --include='*.ts' --include='*.tsx'"
echo ""

echo "=========================================="
echo ""
echo -e "Results: ${GREEN}$PASSED passed${NC}, ${RED}$FAILED failed${NC}"
echo ""

if [ $FAILED -gt 0 ]; then
  echo -e "${RED}❌ Pre-deployment verification FAILED${NC}"
  echo "   Please fix the issues above before deploying to Vercel."
  exit 1
else
  echo -e "${GREEN}✅ Pre-deployment verification PASSED${NC}"
  echo ""
  echo "📋 Next Steps:"
  echo "   1. Configure environment variables in Vercel project settings"
  echo "   2. Connect GitHub repository to Vercel"
  echo "   3. Vercel will auto-detect dashboard/ and build automatically"
  echo "   4. Monitor deployment at https://vercel.com/dashboard"
  echo ""
  echo "🚀 Ready to deploy!"
  exit 0
fi
