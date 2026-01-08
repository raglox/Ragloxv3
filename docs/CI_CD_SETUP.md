# 🔄 CI/CD Setup Guide

## Overview
This guide explains how to set up the GitHub Actions CI/CD pipeline for RAGLOX V3 production testing.

## ⚠️ Important Note

Due to GitHub security restrictions, workflow files (`.github/workflows/*.yml`) require special `workflows` permissions that may not be available to all GitHub Apps or tokens. If you encounter permission errors when pushing workflow files, follow the manual setup instructions below.

## 📦 Workflow File

The complete workflow configuration is available in `.github/workflows/production-tests.yml.template`.

### Manual Setup Steps

1. **Navigate to your GitHub repository**:
   ```
   https://github.com/HosamN-ALI/Ragloxv3
   ```

2. **Create the workflow file manually**:
   - Go to **Actions** tab
   - Click **"New workflow"** or **"Set up a workflow yourself"**
   - Name the file: `production-tests.yml`
   - Copy content from `.github/workflows/production-tests.yml.template`
   - Commit directly to your branch

3. **Configure Secrets**:
   Go to **Settings → Secrets and variables → Actions** and add:
   
   ```
   DATABASE_URL: postgresql://raglox_test:test_password@localhost:5432/raglox_test
   REDIS_URL: redis://localhost:6379/0
   SECRET_KEY: <generate-secure-random-key>
   JWT_SECRET_KEY: <generate-secure-jwt-key>
   SLACK_WEBHOOK_URL: <your-slack-webhook-url> (optional)
   ```

   Generate secure keys:
   ```bash
   python -c "import secrets; print(secrets.token_urlsafe(32))"
   ```

4. **Enable Actions**:
   - Go to **Settings → Actions → General**
   - Ensure **"Allow all actions"** is selected
   - Enable **"Read and write permissions"** for GITHUB_TOKEN

## 🚀 Workflow Features

### Triggers
- **Push**: Runs on `main`, `develop`, `genspark_ai_developer` branches
- **Pull Request**: Runs on all PRs
- **Schedule**: Daily at 02:00 UTC
- **Manual**: Via workflow_dispatch

### Test Stages
1. **Integration Tests** (40 tests)
   - Database operations
   - Redis caching
   - API endpoints
   - Service layer

2. **E2E Tests** (13 tests)
   - Mission lifecycle
   - Chat & HITL
   - Vulnerability discovery
   - Knowledge base

3. **Performance Tests** (5 tests)
   - Concurrent operations
   - Load testing
   - Database/Redis performance

4. **Security Tests** (11 tests)
   - Authentication
   - Authorization
   - Injection prevention
   - Input validation

5. **Chaos Tests** (10 tests)
   - Network failures
   - Service degradation
   - Resource exhaustion
   - Recovery

### Services
- **PostgreSQL 13**: Test database
- **Redis 7**: Cache service

### Artifacts
- Test results (JUnit XML)
- Coverage reports
- Test logs

## 🔧 Local Testing

Test the workflow locally using [act](https://github.com/nektos/act):

```bash
# Install act
brew install act  # macOS
# or
curl https://raw.githubusercontent.com/nektos/act/master/install.sh | sudo bash

# Run workflow
act -j test

# Run specific job
act -j integration-tests
```

## 📊 Monitoring

### GitHub Actions UI
- View workflow runs: **Actions** tab
- Check test results in each run
- Download artifacts for detailed logs

### Slack Notifications (Optional)
Configure `SLACK_WEBHOOK_URL` secret to receive:
- ✅ Success notifications
- ❌ Failure alerts
- 📊 Test statistics

## 🐛 Troubleshooting

### Workflow Not Running
- Check branch triggers in workflow file
- Verify Actions are enabled in repository settings
- Ensure workflow file syntax is valid (YAML)

### Test Failures
- Review logs in Actions tab
- Check service container status
- Verify environment variables
- Run tests locally to reproduce

### Permission Errors
- Ensure GITHUB_TOKEN has correct permissions
- Check repository settings for Actions permissions
- Verify secrets are configured correctly

## 📚 Related Documentation
- [Production Testing Guide](./PRODUCTION_TESTING_GUIDE.md)
- [Deployment Checklist](./DEPLOYMENT_CHECKLIST.md)
- [Operations Guide](./OPERATIONS_GUIDE.md)

---

**Last Updated**: 2026-01-08  
**Version**: 1.0
