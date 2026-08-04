#!/bin/bash
# SecureOS — Quick Start
# Run from project root: bash start.sh

echo ""
echo "  SECURE OS v4 MASTER"
echo "  Consent-Gated Ethical Pentest Platform"
echo ""

# Check Ollama
if ! command -v ollama &> /dev/null; then
  echo "  [!] Ollama not found — install: https://ollama.ai"
else
  echo "  [+] Starting Ollama..."
  ollama serve &>/dev/null &
  sleep 2
  ollama pull mistral 2>/dev/null
  echo "  [+] Mistral model ready"
fi

# Start FastAPI
echo "  [+] Starting FastAPI backend on :8000"
cd backend
pip install -r requirements.txt -q --break-system-packages
uvicorn main:app --reload --host 0.0.0.0 --port 8000 &

echo ""
echo "  Dashboard: open dashboard/index.html in browser"
echo "  API:       http://localhost:8000"
echo "  API Docs:  http://localhost:8000/docs"
echo ""
