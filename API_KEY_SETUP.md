# API Key Setup Guide

Complete guide for configuring API keys in Scorpion CLI.

---

## 🔑 Quick Setup (3 Minutes)

### Step 1: Create .env File

```bash
# Copy the example file
cp .env.example .env
```

### Step 2: Add Your OpenAI API Key

Edit `.env` file and add your key:

```bash
SCORPION_AI_API_KEY=sk-proj-your-actual-key-here
```

### Step 3: Verify Setup

```bash
# Test that the key is loaded
scorpion ai-pentest --help

# Run a test scan (replace with your target)
scorpion ai-pentest -t example.com
```

✅ **Done!** Your API key is now configured.

---

## 📋 Detailed Setup Instructions

### Method 1: Using .env File (Recommended) ⭐

**Pros:** Permanent, automatic, works across sessions

**Setup:**

1. Create `.env` file in project root:
   ```bash
   cd /path/to/Scorpion
   nano .env  # or use any text editor
   ```

2. Add your API key:
   ```env
   SCORPION_AI_API_KEY=sk-proj-your-actual-key-here
   ```

3. Save and close. The key is automatically loaded when you run Scorpion.

**Security:** `.env` is already in `.gitignore` - it won't be committed to git.

---

### Method 2: Environment Variable (Session-Based)

**Pros:** Works immediately, no files needed  
**Cons:** Resets when you close terminal

#### Linux / macOS:

```bash
# Set for current session
export SCORPION_AI_API_KEY='sk-proj-your-actual-key-here'

# Make it permanent (add to ~/.bashrc or ~/.zshrc)
echo "export SCORPION_AI_API_KEY='sk-proj-your-actual-key-here'" >> ~/.bashrc
source ~/.bashrc
```

---

### Method 3: Command-Line Flag (One-Time Use)

**Pros:** Quick testing, no configuration  
**Cons:** Must type every time, visible in command history

```bash
scorpion ai-pentest -t example.com --api-key sk-proj-your-actual-key-here
```

⚠️ **Warning:** Command-line flags are visible in shell history!

---

## 🔐 Getting API Keys

### OpenAI (Required for AI Pentesting)

1. Go to https://platform.openai.com/api-keys
2. Click "Create new secret key"
3. Copy the key (starts with `sk-proj-...`)
4. Add to `.env` as `SCORPION_AI_API_KEY`

**Pricing:** Pay-as-you-go, ~$0.01-0.10 per scan depending on model

### Anthropic (Alternative AI Provider)

1. Go to https://console.anthropic.com/settings/keys
2. Create API key
3. Use with: `--ai-provider anthropic --api-key sk-ant-...`

### Other Optional APIs (Optional)

#### VirusTotal (Malware/URL Scanning)
- Get key: https://www.virustotal.com/gui/my-apikey
- Add to `.env`: `VIRUSTOTAL_API_KEY=your-key`

#### AbuseIPDB (IP Reputation)
- Get key: https://www.abuseipdb.com/account/api
- Add to `.env`: `ABUSEIPDB_API_KEY=your-key`

#### Shodan (Internet-Wide Scanning)
- Get key: https://account.shodan.io/
- Add to `.env`: `SHODAN_API_KEY=your-key`

---

## ✅ Verify Your Setup

### Test 1: Check Environment Variable

```bash
# Linux/macOS:
echo $SCORPION_AI_API_KEY
```

**Expected:** Should show your API key (or at least first few characters)

### Test 2: Run Help Command

```bash
scorpion ai-pentest --help
```

**Expected:** Should show help without error about missing API key

### Test 3: Test Scan (with authorization!)

```bash
# Test on authorized target only!
scorpion ai-pentest -t example.com --mode passive
```

**Expected:** Should start scanning without API key error

---

## 🔧 Troubleshooting

### Error: "AI API key required"

**Cause:** Environment variable not set or `.env` file not created

**Solutions:**

1. **Check .env file exists:**
   ```bash
   ls -la .env
   ```

2. **Verify .env content:**
   ```bash
   cat .env
   ```

3. **Check for typos:**
   - Variable name: `SCORPION_AI_API_KEY` (exact spelling)
   - No spaces around `=`
   - API key format: `sk-proj-...` or `sk-...`

4. **Reload environment:**
   ```bash
   # Close and reopen terminal, OR:
   source .env
   ```

### Error: "Invalid API key"

**Causes:**
- API key is incorrect or expired
- Extra spaces/quotes in key
- Key is disabled in OpenAI dashboard

**Solutions:**

1. **Regenerate key:** https://platform.openai.com/api-keys
2. **Check for extra characters:** Remove quotes if they exist
3. **Test key directly:**
   ```bash
   curl https://api.openai.com/v1/models \
     -H "Authorization: Bearer YOUR_API_KEY"
   ```

### .env File Not Loading

**Cause:** Not in correct directory

**Solution:** Ensure `.env` is in project root:

```bash
cd /path/to/Scorpion
pwd  # Should show Scorpion project directory
ls .env  # Should exist here
```

### Windows PowerShell Profile Not Found

```powershell
# Create profile if it doesn't exist
if (!(Test-Path -Path $PROFILE)) {
    New-Item -ItemType File -Path $PROFILE -Force
}
notepad $PROFILE
```

---

## 🛡️ Security Best Practices

### ✅ DO:
- ✅ Use `.env` file (already in `.gitignore`)
- ✅ Rotate API keys regularly (monthly recommended)
- ✅ Use different keys for dev/prod environments
- ✅ Set spending limits in OpenAI dashboard
- ✅ Monitor API usage regularly
- ✅ Revoke unused keys immediately

### ❌ DON'T:
- ❌ Commit API keys to git
- ❌ Share API keys in chat/email/screenshots
- ❌ Use production keys for testing
- ❌ Store keys in code files
- ❌ Use command-line flags in production
- ❌ Share API keys across projects/teams

### 🔒 If Your Key Is Exposed:

1. **Immediately revoke it:** https://platform.openai.com/api-keys
2. **Generate a new key**
3. **Update your `.env` file**
4. **Check for unauthorized usage**
5. **Review git history** (if accidentally committed)

---

## 📦 For Repository Maintainers

When cloning/forking Scorpion:

1. **Don't commit `.env`** - It's already in `.gitignore`
2. **Keep `.env.example`** - Users need this template
3. **Document custom keys** - Add new API keys to `.env.example`
4. **Update this guide** - When adding new integrations

---

## 🎯 Examples

### Example 1: Full Setup

```bash
# 1. Clone repository
git clone https://github.com/Prince12sam/Scorpion.git
cd Scorpion

# 2. Install
pip install -e tools/python_scorpion

# 3. Configure API key
cp .env.example .env
nano .env  # Add: SCORPION_AI_API_KEY=sk-proj-...

# 4. Test
scorpion ai-pentest -t example.com --mode passive

# ✅ Done!
```

### Example 2: CI/CD Environment

```yaml
# GitHub Actions example
env:
  SCORPION_AI_API_KEY: ${{ secrets.OPENAI_API_KEY }}

# GitLab CI example
variables:
  SCORPION_AI_API_KEY: $OPENAI_API_KEY

# Jenkins example
environment {
  SCORPION_AI_API_KEY = credentials('openai-api-key')
}
```

### Example 3: Docker

```dockerfile
# Dockerfile
ENV SCORPION_AI_API_KEY=""

# docker run
docker run -e SCORPION_AI_API_KEY='sk-proj-...' scorpion ai-pentest -t example.com
```

---

## 📚 Additional Resources

- **OpenAI API Documentation:** https://platform.openai.com/docs
- **Anthropic API Documentation:** https://docs.anthropic.com/
- **Scorpion Documentation:** [README.md](README.md)
- **Command Reference:** [COMMANDS.md](COMMANDS.md)

---

## 🆘 Need Help?

- **GitHub Issues:** https://github.com/Prince12sam/Scorpion/issues
- **Discussions:** https://github.com/Prince12sam/Scorpion/discussions
- **Documentation:** Check [GETTING_STARTED.md](GETTING_STARTED.md)

---

**Last Updated:** December 12, 2025  
**Version:** 2.0.1
