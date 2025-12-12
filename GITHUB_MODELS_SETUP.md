# GitHub Models Setup Guide - FREE AI for Scorpion

**GitHub Models is COMPLETELY FREE** and provides access to multiple AI models including GPT-4o, GPT-4o-mini, Llama, and more!

---

## 🚀 Quick Setup (2 Minutes)

### Step 1: Get Your GitHub Token

1. Go to: https://github.com/marketplace/models
2. Sign in with your GitHub account
3. Click on any model (e.g., "GPT-4o-mini")
4. Click "Get started" or "Use this model"
5. You'll get a personal access token that starts with `ghp_` or `github_pat_`

### Step 2: Add to Scorpion

```bash
# Option 1: Add to .env file (recommended)
nano .env
```

Add this line:
```env
SCORPION_AI_API_KEY=ghp_your_token_here
```

```bash
# Option 2: Export as environment variable
export SCORPION_AI_API_KEY='ghp_your_token_here'
```

### Step 3: Run AI Pentest

```bash
# Using GitHub Models (FREE!)
scorpion ai-pentest -t example.com --ai-provider github --model gpt-4o-mini

# Or with environment variable set:
scorpion ai-pentest -t example.com --ai-provider github --model gpt-4o-mini
```

---

## 🎯 Available Models (All FREE!)

### OpenAI Models
- **gpt-4o** - Most capable, best for complex security analysis
- **gpt-4o-mini** - Fast and efficient, perfect for pentesting
- **gpt-4-turbo** - Balanced performance

### Meta Llama Models
- **Llama-3.2-90B-Vision-Instruct** - Large, powerful model
- **Llama-3.1-405B-Instruct** - Massive reasoning capabilities
- **Llama-3.1-70B-Instruct** - Great balance

### Microsoft Models
- **Phi-3.5-mini-instruct** - Fast, lightweight
- **Phi-3.5-MoE-instruct** - Mixture of experts

### Mistral Models
- **Mistral-large** - Strong performance
- **Mistral-large-2407** - Latest version
- **Mistral-Nemo** - Efficient

---

## 📋 Usage Examples

### Basic Pentest (Recommended)
```bash
scorpion ai-pentest -t example.com \
  --ai-provider github \
  --model gpt-4o-mini \
  --api-key ghp_your_token
```

### Comprehensive Assessment
```bash
scorpion ai-pentest -t example.com \
  --ai-provider github \
  --model gpt-4o \
  --goal comprehensive_assessment \
  --stealth-level moderate
```

### Web Exploitation Focus
```bash
scorpion ai-pentest -t example.com \
  --ai-provider github \
  --model Llama-3.1-70B-Instruct \
  --goal web_exploitation
```

### API Security Testing
```bash
scorpion ai-pentest -t api.example.com \
  --ai-provider github \
  --model gpt-4o-mini \
  --goal api_security_testing
```

---

## 💡 Tips & Best Practices

### Choose the Right Model
- **Fast scans**: Use `gpt-4o-mini` or `Phi-3.5-mini-instruct`
- **Deep analysis**: Use `gpt-4o` or `Llama-3.1-70B-Instruct`
- **Complex targets**: Use `gpt-4o` or `Mistral-large`

### Rate Limits
GitHub Models has generous free rate limits:
- **Requests per minute**: 15-60 (depending on model)
- **Tokens per minute**: 150,000 - 450,000
- **No daily cap** for most models

### Cost Comparison
| Provider | Cost | GitHub Models |
|----------|------|---------------|
| OpenAI GPT-4 | $30-60/1M tokens | **FREE** ✅ |
| Anthropic Claude | $15-75/1M tokens | **FREE** ✅ |
| Local LLM | Hardware cost | **FREE** ✅ |

---

## 🔧 Troubleshooting

### Error: "401 Unauthorized"
**Cause:** Invalid or expired GitHub token

**Solution:**
1. Regenerate token at https://github.com/settings/tokens
2. Make sure you selected the right scopes
3. Update `.env` file

### Error: "404 Not Found"
**Cause:** Model name is incorrect

**Solution:** Check available models at https://github.com/marketplace/models

### Error: "429 Rate Limit Exceeded"
**Cause:** Too many requests

**Solution:**
- Wait 1 minute
- Reduce `--time-limit` parameter
- Use `--stealth-level high` to slow down requests

### Token Not Loading
**Cause:** Environment variable not set

**Solution:**
```bash
# Reload environment
source .env

# Or export directly
export SCORPION_AI_API_KEY='ghp_your_token'

# Verify it's loaded
echo $SCORPION_AI_API_KEY
```

---

## 🆚 GitHub Models vs OpenAI

| Feature | GitHub Models | OpenAI Direct |
|---------|---------------|---------------|
| **Cost** | FREE ✅ | $5-50+ |
| **Rate Limits** | Generous | Pay as you go |
| **Models** | GPT-4o, Llama, Phi, Mistral | GPT-4, GPT-3.5 |
| **Setup** | GitHub account only | Credit card required |
| **Best For** | Testing, learning | Production use |

---

## 📚 Additional Resources

- **GitHub Models Marketplace**: https://github.com/marketplace/models
- **API Documentation**: https://github.com/marketplace/models/openai/gpt-4o
- **Rate Limits**: https://docs.github.com/en/github-models/prototyping-with-ai-models#rate-limits
- **Model Comparison**: https://github.com/marketplace/models

---

## 🎓 Example Workflow

### Complete Security Assessment (FREE)

```bash
# 1. Set up GitHub token
export SCORPION_AI_API_KEY='ghp_your_token'

# 2. Run comprehensive pentest
scorpion ai-pentest -t example.com \
  --ai-provider github \
  --model gpt-4o-mini \
  --goal comprehensive_assessment \
  --stealth-level moderate \
  --output-dir results/

# 3. Review results
ls -lh results/
cat results/ai_pentest_example.com_*.json
```

---

## ✅ Why GitHub Models is Best for Testing

1. ✅ **Completely FREE** - No credit card
2. ✅ **Multiple models** - GPT-4o, Llama, Phi, Mistral
3. ✅ **Generous limits** - Enough for extensive testing
4. ✅ **Easy setup** - Just your GitHub account
5. ✅ **No commitment** - Use as much or as little as you want
6. ✅ **Latest models** - Access to newest AI models
7. ✅ **Fast** - Low latency, high performance

---

**Happy (ethical) hacking with FREE AI! 🦂🤖**

---

**Last Updated:** December 12, 2025  
**Version:** 2.0.1
