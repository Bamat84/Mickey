@echo off
title Mickey - Legal Intelligence

echo.
echo  Mickey - Legal Intelligence
echo  --------------------------------
echo.

echo  Installing dependencies...
pip install flask anthropic openai pypdf python-docx numpy bcrypt cryptography waitress --quiet
echo  Ready.
echo.

if not exist "C:\Mickey" mkdir "C:\Mickey"
if not exist "C:\Mickey\data" mkdir "C:\Mickey\data"
if not exist "C:\Mickey\shared_library" mkdir "C:\Mickey\shared_library"
if not exist "C:\Mickey\shared_library\embeddings" mkdir "C:\Mickey\shared_library\embeddings"
if not exist "C:\Mickey\usage" mkdir "C:\Mickey\usage"
if not exist "C:\Mickey\logs" mkdir "C:\Mickey\logs"

set MICKEY_DATA=C:\Mickey
set MICKEY_HTTPS=false
set MICKEY_RATE_LIMIT=60

if "%MICKEY_SECRET%"=="" set MICKEY_SECRET=mickey-change-before-production-use

echo  Starting Mickey at http://localhost:5000
echo.
echo  First time? After the browser opens:
echo    1. Create your account (first account = admin)
echo    2. Go to Admin and enter your Anthropic API key
echo    3. Optionally enter your OpenAI key for semantic search
echo.
echo  NOTE: If API keys need to be re-entered after update,
echo  this is expected - Fernet encryption replaced old XOR format.
echo.
echo  Press Ctrl+C to stop.
echo.

start "" /b cmd /c "timeout /t 2 /nobreak > nul && start http://localhost:5000"

cd /d "%~dp0"
python server.py

pause
