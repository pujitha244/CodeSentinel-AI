@echo off
echo ========================================================
echo   CodeSentinel AI - Autonomous Security Intelligence
echo   Starting Backend & Frontend Development Servers
echo ========================================================

start "CodeSentinel Backend" cmd /k ".\backend\venv\Scripts\python.exe -m uvicorn backend.app.main:app --reload --port 8000"
start "CodeSentinel Frontend" cmd /k "cd frontend && npm run dev"

echo.
echo [OK] Backend running at http://127.0.0.1:8000 (API Docs at http://127.0.0.1:8000/api/docs)
echo [OK] Frontend running at http://localhost:5173
echo.
