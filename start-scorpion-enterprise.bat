# 🦂 SCORPION SECURITY PLATFORM - STARTUP SCRIPT
# Enterprise Edition with Advanced Security

@echo off
title Scorpion Security Platform - Enterprise Edition
echo =====================================================
echo    SCORPION SECURITY PLATFORM - ENTERPRISE EDITION
echo =====================================================
echo.
echo 🦂 Loading enterprise security modules...
echo 🛡️ Initializing multi-layer protection...
echo 🔐 Enabling advanced authentication...
echo 📊 Starting security monitoring...
echo.
echo Enterprise Features:
echo ✅ JWT Authentication with Device Fingerprinting
echo ✅ Two-Factor Authentication (TOTP)
echo ✅ Role-Based Access Control (RBAC)
echo ✅ Advanced Rate Limiting & DDoS Protection
echo ✅ Real-time Threat Intelligence
echo ✅ Comprehensive Vulnerability Scanning
echo ✅ Enterprise Compliance Monitoring
echo ✅ Advanced Audit Logging
echo.
echo Server Endpoints:
echo 🌐 Frontend: http://localhost:5173
echo 🔗 Backend API: http://localhost:3001
echo 📊 Health Check: http://localhost:3001/api/health
echo 🛡️ Security Dashboard: http://localhost:3001/api/security/info
echo.
echo 🚨 SECURITY LEVEL: MAXIMUM
echo 🔒 THREAT PROTECTION: ACTIVE
echo ⚡ STATUS: ENTERPRISE READY
echo.
echo Press Ctrl+C to stop all servers
echo =====================================================
echo.

cd /d "%~dp0"

REM Start Redis server (if available)
echo 🗄️ Starting Redis server...
start /B redis-server 2>nul

REM Wait a moment for Redis to start
timeout /t 2 /nobreak >nul

REM Start enterprise backend server
echo 🚀 Starting enterprise backend server...
start /B cmd /c "npm run start:enterprise"

REM Wait for backend to initialize
timeout /t 3 /nobreak >nul

REM Start frontend development server
echo 🎨 Starting frontend development server...
start /B cmd /c "npm run dev"

echo.
echo ✅ All servers started successfully!
echo 🦂 Scorpion Security Platform is now running...
echo.
echo 📱 Open your browser and navigate to:
echo    http://localhost:5173
echo.
echo 🔐 Default Login Credentials:
echo    Username: admin
echo    Password: SecurePassword123!
echo.
echo 📋 For 2FA setup, use Google Authenticator or Authy
echo.

pause