@echo off
echo 🔐 PKI Simulation - Quick Start
echo ================================

REM Check if Node.js is installed
where node >nul 2>nul
if errorlevel 1 (
    echo ❌ Node.js is not installed. Please install Node.js first.
    exit /b 1
)

REM Install dependencies
echo 📦 Installing dependencies...
call npm install

REM Initialize PKI
echo 🔐 Initializing PKI hierarchy...
call node src/cli.js init

echo.
echo 🚀 Starting PKI Simulation Server...
echo.
echo 📋 Available on:
echo    • API Server: http://localhost:3000
echo    • HTTPS Demo: https://localhost:8443
echo    • HTTP Redirect: http://localhost:8080
echo.
echo ⚠️  Note: Your browser will show a security warning for HTTPS
echo    This is expected - you're using a custom Certificate Authority
echo    Import the Root CA certificate to fix this: .\certs\root\root-ca.crt
echo.
echo Press Ctrl+C to stop all servers
echo.

REM Start servers
start "PKI Server" node src/server.js
timeout /t 2 /nobreak >nul
start "HTTPS Demo" node -e "const HTTPSDemo = require('./src/demo/HTTPSDemo'); const demo = new HTTPSDemo(); demo.startAll();"

echo.
pause