@echo off
setlocal enabledelayedexpansion

echo.
echo ================================================================
echo           PKI Simulation Toolkit - Quick Start
echo ================================================================
echo.

REM ================================================================
REM Step 1: Check Prerequisites
REM ================================================================
echo [1/6] Checking prerequisites...
echo.

REM Check if Node.js is installed
where node >nul 2>nul
if errorlevel 1 (
    echo [ERROR] Node.js is not installed or not in PATH.
    echo.
    echo Please install Node.js 16.x or higher from:
    echo https://nodejs.org/
    echo.
    pause
    exit /b 1
)

REM Check if npm is installed
where npm >nul 2>nul
if errorlevel 1 (
    echo [ERROR] npm is not installed or not in PATH.
    echo.
    pause
    exit /b 1
)

REM Check Node.js version
for /f "tokens=*" %%i in ('node --version') do set NODE_VERSION=%%i
echo [OK] Node.js found: %NODE_VERSION%

REM Check npm version
for /f "tokens=*" %%i in ('npm --version') do set NPM_VERSION=%%i
echo [OK] npm found: %NPM_VERSION%
echo.

REM ================================================================
REM Step 2: Create Required Directories
REM ================================================================
echo [2/6] Creating required directories...
if not exist "certs" mkdir certs
if not exist "keys" mkdir keys
if not exist "crl" mkdir crl
if not exist "node_modules" (
    echo [OK] Directories created
) else (
    echo [OK] Directories already exist
)
echo.

REM ================================================================
REM Step 3: Install Dependencies
REM ================================================================
echo [3/6] Installing dependencies...
echo This may take a few moments...
echo.

if not exist "node_modules" (
    call npm install
    if errorlevel 1 (
        echo [ERROR] Failed to install dependencies.
        echo.
        pause
        exit /b 1
    )
    echo [OK] Dependencies installed successfully
) else (
    echo [OK] Dependencies already installed (skipping)
)
echo.

REM ================================================================
REM Step 4: Check if PKI is Already Initialized
REM ================================================================
echo [4/6] Checking PKI initialization status...
set PKI_INITIALIZED=0

if exist "certs\root\root-ca.crt" (
    if exist "certs\intermediate\intermediate-ca.crt" (
        if exist "certs\server\localhost.crt" (
            set PKI_INITIALIZED=1
            echo [OK] PKI hierarchy already initialized
        )
    )
)

if %PKI_INITIALIZED%==0 (
    echo [INFO] PKI not initialized - will initialize after server starts
)
echo.

REM ================================================================
REM Step 5: Start API Server
REM ================================================================
echo [5/6] Starting API Server...
echo.

REM Check if server is already running
netstat -an | findstr ":3000" >nul 2>nul
if not errorlevel 1 (
    echo [WARNING] Port 3000 is already in use.
    echo [INFO] Attempting to use existing server...
    set SERVER_RUNNING=1
) else (
    set SERVER_RUNNING=0
    start "PKI API Server" /min node src/server.js
    echo [OK] API Server starting in background...
    echo [INFO] Waiting for server to be ready...
    
    REM Wait for server to start (max 30 seconds)
    set /a COUNTER=0
    :WAIT_FOR_SERVER
    timeout /t 2 /nobreak >nul
    set /a COUNTER+=2
    powershell -Command "try { $response = Invoke-WebRequest -Uri 'http://localhost:3000/' -TimeoutSec 2 -UseBasicParsing; exit 0 } catch { exit 1 }" >nul 2>nul
    if errorlevel 1 (
        if !COUNTER! LSS 30 (
            goto WAIT_FOR_SERVER
        ) else (
            echo [ERROR] Server failed to start within 30 seconds
            echo [INFO] Please check for errors and try again
            pause
            exit /b 1
        )
    ) else (
        echo [OK] API Server is ready!
    )
)
echo.

REM ================================================================
REM Step 6: Initialize PKI (if needed)
REM ================================================================
if %PKI_INITIALIZED%==0 (
    echo [6/6] Initializing PKI hierarchy...
    echo [INFO] This will create Root CA, Intermediate CA, and server certificates...
    echo.
    
    REM Initialize PKI via API
    powershell -Command "$body = @{organization='PKI Demo Academy';country='US'} | ConvertTo-Json; try { $response = Invoke-RestMethod -Uri 'http://localhost:3000/api/pki/initialize' -Method POST -ContentType 'application/json' -Body $body -TimeoutSec 30; Write-Host '[OK] PKI initialized successfully!' } catch { Write-Host '[ERROR] Failed to initialize PKI:'; Write-Host $_.Exception.Message; exit 1 }" 2>nul
    
    if errorlevel 1 (
        echo [WARNING] PKI initialization failed or timed out
        echo [INFO] You can initialize it manually by visiting:
        echo        http://localhost:3000/api/pki/initialize
        echo        Or use: POST http://localhost:3000/api/pki/initialize
    ) else (
        echo [OK] PKI hierarchy created successfully!
        echo [INFO] Certificates saved in: certs\
    )
    echo.
) else (
    echo [6/6] PKI already initialized - skipping
    echo.
)

REM ================================================================
REM Step 7: Start HTTPS Demo Server
REM ================================================================
echo [7/7] Starting HTTPS Demo Server...
echo.

REM Check if HTTPS port is already in use
netstat -an | findstr ":8443" >nul 2>nul
if not errorlevel 1 (
    echo [WARNING] Port 8443 is already in use.
    echo [INFO] HTTPS demo may already be running
) else (
    REM Start HTTPS demo via API
    powershell -Command "try { $response = Invoke-RestMethod -Uri 'http://localhost:3000/api/https/start' -Method GET -TimeoutSec 10; Write-Host '[OK] HTTPS Demo Server started!' } catch { Write-Host '[WARNING] Could not start HTTPS demo automatically'; Write-Host '[INFO] You can start it manually by visiting:'; Write-Host '       http://localhost:3000/api/https/start' }" 2>nul
    timeout /t 2 /nobreak >nul
)
echo.

REM ================================================================
REM Display Final Information
REM ================================================================
echo.
echo ================================================================
echo                    Setup Complete!
echo ================================================================
echo.
echo [AVAILABLE SERVICES]
echo.
echo   API Server:        http://localhost:3000
echo   API Documentation: http://localhost:3000/
echo   HTTPS Demo:        https://localhost:8443
echo   HTTP Redirect:     http://localhost:8080
echo.
echo [QUICK LINKS]
echo.
echo   PKI Status:        http://localhost:3000/api/pki/status
echo   PKI Hierarchy:     http://localhost:3000/api/pki/hierarchy
echo   System Stats:      http://localhost:3000/api/system/stats
echo.
echo [DEMO APPLICATIONS]
echo.
echo   Code Signing:      http://localhost:3000/api/codesign/demo
echo   Email Encryption:  http://localhost:3000/api/email/demo
echo.
echo [IMPORTANT NOTES]
echo.
echo   ⚠️  Your browser will show a security warning for HTTPS
echo      This is EXPECTED - you're using a custom Certificate Authority
echo.
echo   📋 To fix the security warning:
echo      1. Open: certs\root\root-ca.crt
echo      2. Install it as a trusted root certificate
echo      3. Restart your browser
echo.
echo   🔐 Certificate files are located in:
echo      - Root CA:        certs\root\root-ca.crt
echo      - Intermediate:   certs\intermediate\intermediate-ca.crt
echo      - Server Cert:    certs\server\localhost.crt
echo      - Certificate Chain: certs\server\localhost-chain.pem
echo.
echo [NEXT STEPS]
echo.
echo   1. Open your browser and visit: http://localhost:3000
echo   2. Explore the API documentation
echo   3. Try the HTTPS demo: https://localhost:8443
echo   4. Run demos via API endpoints
echo.
echo ================================================================
echo.
echo [SERVER STATUS]
echo   The API server is running in the background.
echo   To stop the server, close the "PKI API Server" window
echo   or press Ctrl+C in that window.
echo.
echo   Press any key to open the API documentation in your browser...
pause >nul

REM Open browser to API documentation
start http://localhost:3000/

echo.
echo [INFO] Browser opened to API documentation
echo [INFO] Server will continue running in the background
echo.
echo Press any key to exit this window (server will keep running)...
pause >nul

endlocal
