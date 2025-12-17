# AI Pentesting Setup Guide 🤖

**Complete guide to setting up AI-powered penetration testing**

---

## Quick Setup (2 Minutes) - FREE Option

### Option 1: GitHub Models (Recommended - FREE!)

**No credit card required!**

```bash
# 1. Get FREE GitHub token
# Visit: https://github.com/settings/tokens
# Click: "Generate new token (classic)"
# Select scopes: "repo" (that's it!)
# Generate and copy token (starts with ghp_)

# 2. Set environment variable
export SCORPION_AI_API_KEY='ghp_your_token_here'

# 3. Use AI pentest immediately
scorpion ai-pentest -t example.com
```

**Done!** No payment, no credit card, no limits for reasonable use.

---

## All AI Provider Options

### Option 2: OpenAI (GPT-4)

```bash
# 1. Get API key: https://platform.openai.com/api-keys
# 2. Set environment variable
export SCORPION_AI_API_KEY='sk-proj-...'

# 3. Use AI pentest
scorpion ai-pentest -t example.com
```

**Cost:** ~$0.01-0.10 per scan (pay-as-you-go)

### Option 3: Anthropic (Claude)

```bash
# 1. Get API key: https://console.anthropic.com/
# 2. Set environment variable
export SCORPION_AI_API_KEY='sk-ant-...'

# 3. Use AI pentest
scorpion ai-pentest -t example.com
```

**Cost:** ~$0.01-0.10 per scan (pay-as-you-go)

---

## Environment Variable Setup

### Persistent Setup (Recommended)

#### Linux/macOS

```bash
# Add to ~/.bashrc or ~/.zshrc
echo 'export SCORPION_AI_API_KEY="ghp_your_token"' >> ~/.bashrc
source ~/.bashrc

# Or create .env file in project root
echo 'SCORPION_AI_API_KEY=ghp_your_token' > .env
```

#### Windows (PowerShell)

```powershell
# Add to PowerShell profile
echo '$env:SCORPION_AI_API_KEY="ghp_your_token"' >> $PROFILE
. $PROFILE

# Or set system environment variable
[System.Environment]::SetEnvironmentVariable('SCORPION_AI_API_KEY', 'ghp_your_token', 'User')
```

### Temporary Setup (Current Session Only)

```bash
# Linux/macOS
export SCORPION_AI_API_KEY='ghp_your_token'

# Windows PowerShell
$env:SCORPION_AI_API_KEY='ghp_your_token'
```

---

## Using AI Pentest

### Basic Usage

```bash
# Simple scan
scorpion ai-pentest -t example.com

# With custom instructions
scorpion ai-pentest -t example.com -i "Focus on API security and test for IDOR"

# Specific goal
scorpion ai-pentest -t example.com -g web_exploitation -r medium

# Time-limited scan
scorpion ai-pentest -t example.com --time-limit 30
```

### Custom Instructions Examples

```bash
# Focus on specific vulnerabilities
scorpion ai-pentest -t example.com -i "Test for SQL injection and XSS only"

# Technology-specific testing
scorpion ai-pentest -t example.com -i "Focus on GraphQL API security"

# Authentication testing
scorpion ai-pentest -t example.com -i "Test authentication and authorization bypasses"

# Stealth mode
scorpion ai-pentest -t example.com -i "Use slow, stealthy techniques"
```

### Available Goals

- `web_exploitation` - OWASP Top 10, web vulnerabilities
- `api_security_testing` - REST/GraphQL API testing
- `infrastructure_assessment` - Network and infrastructure
- `cloud_security_audit` - Cloud misconfigurations
- `comprehensive_assessment` - Full security assessment

---

## Provider Comparison

| Provider | Cost | Speed | Quality | Setup |
|----------|------|-------|---------|-------|
| **GitHub Models** | FREE | Fast | Good | 2 min |
| OpenAI GPT-4 | $$ | Very Fast | Excellent | 5 min |
| Anthropic Claude | $$ | Fast | Excellent | 5 min |

**Recommendation:** Start with GitHub Models (FREE), upgrade if needed.

---

## Troubleshooting

### "API key not found"
```bash
# Check if variable is set
echo $SCORPION_AI_API_KEY  # Linux/macOS
echo $env:SCORPION_AI_API_KEY  # Windows

# If empty, set it
export SCORPION_AI_API_KEY='your_key'
```

### "Invalid API key"
- Verify key format (ghp_ for GitHub, sk-proj- for OpenAI, sk-ant- for Anthropic)
- Check key hasn't expired
- Ensure key has correct permissions

### "Rate limit exceeded"
- GitHub Models: Wait a few minutes
- OpenAI/Anthropic: Check billing and limits

---

## Security Best Practices

1. **Never commit API keys to Git**
   ```bash
   # Add to .gitignore
   echo '.env' >> .gitignore
   ```

2. **Use environment variables**
   - Don't hardcode keys in scripts

3. **Rotate keys regularly**
   - Generate new keys every 90 days

4. **Use project-specific keys**
   - Don't reuse keys across projects

---

## Next Steps

- **AI Guide:** [AI_PENTEST_GUIDE.md](AI_PENTEST_GUIDE.md)
- **Commands:** [COMMANDS.md](COMMANDS.md)
- **Getting Started:** [GETTING_STARTED.md](GETTING_STARTED.md)

---

**Setup complete! Start AI pentesting now** 🤖🦂
