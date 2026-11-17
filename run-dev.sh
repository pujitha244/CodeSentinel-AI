#!/usr/bin/env bash
echo "========================================================"
echo "  CodeSentinel AI - Autonomous Security Intelligence"
echo "  Starting Backend & Frontend Development Servers"
echo "========================================================"

# Start backend in background
./backend/venv/bin/uvicorn backend.app.main:app --reload --port 8000 &
BACKEND_PID=$!

# Start frontend
cd frontend && npm run dev &
FRONTEND_PID=$!

trap "kill $BACKEND_PID $FRONTEND_PID" EXIT

echo "[OK] Backend running at http://127.0.0.1:8000/api/docs"
echo "[OK] Frontend running at http://localhost:5173"

wait
