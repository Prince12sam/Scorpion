# 🦂 Scorpion New Features - Quick Reference Card

## ⚡ Installation/Update
```bash
cd ~/Downloads/Scorpion
deactivate && source .venv/bin/activate
pip install -e tools/python_scorpion --force-reinstall --no-deps
pip install pyjwt
```

## 🆕 New Commands

### 1. API Security Testing
```bash
scorpion api-security -t https://api.example.com
scorpion api-security -t https://api.example.com --jwt TOKEN
scorpion api-security -t https://api.example.com --spec /openapi.json -o results.json
```
**Tests:** JWT, IDOR, GraphQL, mass assignment, rate limiting

### 2. Database Penetration
```bash
scorpion db-pentest -t "https://site.com/page?id=1"
scorpion db-pentest -t "https://site.com/login" --method POST
scorpion db-pentest -t "https://site.com/api?id=1" --db-type mysql -o sqli.json
```
**Tests:** SQL/NoSQL injection, blind SQLi, database fingerprinting

### 3. Post-Exploitation
```bash
scorpion post-exploit --os linux
scorpion post-exploit --os darwin --output macos-privesc.json
scorpion post-exploit --execute  # ⚠️ AUTHORIZED ONLY
```
**Provides:** Privesc checks, credential harvesting, persistence, lateral movement (Linux/macOS)

### 4. CI/CD Integration
```bash
scorpion ci-scan --input api-results.json --fail-on-critical
scorpion ci-scan --input api-results.json --sarif-output scorpion.sarif
scorpion ci-scan --generate-workflow github > .github/workflows/security.yml
```
**Generates:** SARIF (GitHub Security), JUnit XML, workflow files

### 5. AI Custom Instructions
```bash
scorpion ai-pentest -t example.com -i "Focus on API endpoints and IDOR"
scorpion ai-pentest -t example.com -i "Test GraphQL for injection"
scorpion ai-pentest -t example.com -i "Prioritize authentication bypass"
```
**Control:** Guide AI testing strategy with custom prompts

## 🎯 Quick Test Workflow

### Web App Security
```bash
# 1. Scan ports
scorpion scan -t example.com --web

# 2. Test API
scorpion api-security -t https://api.example.com -o api.json

# 3. Test database
scorpion db-pentest -t "https://example.com/product?id=1" -o db.json

# 4. AI pentest
scorpion ai-pentest -t example.com -i "Focus on OWASP Top 10" -o ai.json

# 5. CI check
scorpion ci-scan --input api.json --fail-on-critical
```

### Post-Compromise
```bash
# 1. Enumerate system
scorpion post-exploit --os linux -o enum.json

# 2. Review critical findings
cat enum.json | jq '.privilege_escalation[] | select(.severity=="critical")'

# 3. Test specific commands
# (Copy commands from JSON output and execute manually)
```

## 📊 Output Formats

| Command | Default Output | Optional Formats |
|---------|---------------|------------------|
| api-security | Terminal + JSON | JSON with -o |
| db-pentest | Terminal + JSON | JSON with -o |
| post-exploit | Terminal + JSON | JSON with -o |
| ci-scan | Terminal | SARIF, JUnit XML |
| ai-pentest | Terminal + JSON | JSON with -o |

## 🔥 Pro Tips

1. **Always update after git pull:**
   ```bash
   pip install -e tools/python_scorpion --force-reinstall --no-deps
   ```

2. **Chain commands:**
   ```bash
   scorpion api-security -t https://api.example.com -o api.json && \
   scorpion ci-scan --input api.json --sarif-output results.sarif
   ```

3. **Use AI instructions for focus:**
   ```bash
   scorpion ai-pentest -t example.com -i "Only test authentication endpoints"
   ```

4. **Automate in CI/CD:**
   ```yaml
   - run: scorpion api-security --target $API_URL -o api.json
   - run: scorpion ci-scan --input api.json --fail-on-critical --sarif-output scorpion.sarif
   - uses: github/codeql-action/upload-sarif@v3
     with:
       sarif_file: scorpion.sarif
   ```

## ⚠️ Critical Reminders

- ✅ Only test authorized systems
- ✅ Document permission/authorization
- ✅ Use `--os` flag for post-exploit (don't execute blindly)
- ✅ Review findings before exploitation
- ❌ Never use on production without approval
- ❌ Never use --execute flag without authorization

## 📚 Documentation

- Full docs: [ENHANCEMENTS_SUMMARY.md](ENHANCEMENTS_SUMMARY.md)
- Commands: [COMMANDS.md](COMMANDS.md)
- AI pentest: [AI_PENTEST_GUIDE.md](AI_PENTEST_GUIDE.md)

## 🆘 Troubleshooting

**Issue:** `-i` flag not recognized
**Fix:**
```bash
deactivate
source .venv/bin/activate
pip install -e tools/python_scorpion --force-reinstall --no-deps
```

**Issue:** JWT errors
**Fix:**
```bash
pip install pyjwt
```

**Issue:** Import errors
**Fix:**
```bash
pip install -e tools/python_scorpion --force-reinstall
```

---

**🎉 You now have 5 powerful new features! Happy (ethical) hacking! 🦂**
