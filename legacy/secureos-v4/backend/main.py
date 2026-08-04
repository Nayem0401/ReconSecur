"""
SecureOS — FastAPI Backend (v4 MASTER)
Consent-Gated Ethical Pentesting Platform

Start: uvicorn main:app --reload --host 0.0.0.0 --port 8000
"""

from fastapi import FastAPI, HTTPException, WebSocket, WebSocketDisconnect, Depends
from fastapi.middleware.cors import CORSMiddleware
from fastapi.staticfiles import StaticFiles
from pydantic import BaseModel
from pathlib import Path
from typing import Optional
import httpx
import asyncio
import json
import subprocess
import datetime
import uuid

# ── Config ────────────────────────────────────────────────────────────────────

OLLAMA_URL = "http://localhost:11434"
OLLAMA_MODEL = "mistral"
SYSTEM_PROMPT = Path("../prompts/secureos_agent_directive.md").read_text()

app = FastAPI(title="SecureOS API", version="4.0")

app.add_middleware(
    CORSMiddleware,
    allow_origins=["http://localhost:3000", "app://.", "http://localhost:*"],
    allow_methods=["*"],
    allow_headers=["*"],
)

# ── Models ────────────────────────────────────────────────────────────────────

class ConsentVerifyRequest(BaseModel):
    domain: str
    method: str  # "dns" | "snippet" | "contract"
    token: str

class AnalysisRequest(BaseModel):
    input: str
    tier: int
    scope: str
    consent_token: str
    phase: Optional[int] = 1

class ScanRequest(BaseModel):
    target: str
    phase: int
    tier: int
    tools: list[str]
    consent_token: str

class PhaseGateRequest(BaseModel):
    current_phase: int
    next_phase: int
    engagement_id: str
    admin_present: Optional[bool] = False

# ── Consent Gate ──────────────────────────────────────────────────────────────

def verify_consent(token: str, scope: str) -> bool:
    """
    Prüft ob gültiges Consent-Token für diesen Scope vorliegt.
    TODO: Echte DNS-TXT Lookup Implementierung mit dnspython
    """
    if not token or not scope:
        return False
    # Placeholder — ersetzen mit:
    # import dns.resolver
    # answers = dns.resolver.resolve(scope, 'TXT')
    # for rdata in answers:
    #     if f"secureos-verify={token}" in str(rdata):
    #         return True
    return token.startswith("consent-") and len(token) > 16

def check_tier_permission(tier: int, phase: int) -> bool:
    """Prüft ob Tier die angeforderte Phase freischaltet."""
    tier_phase_map = {1: 2, 2: 4, 3: 5, 4: 8}
    return phase <= tier_phase_map.get(tier, 0)

def log_action(action: str, target: str, tool: str, result: str, severity: str = "INFO"):
    """Loggt jede Aktion mit Timestamp."""
    entry = {
        "timestamp": datetime.datetime.utcnow().isoformat() + "Z",
        "action": action,
        "target": target,
        "tool": tool,
        "severity": severity,
        "result_preview": result[:500] if result else ""
    }
    log_path = Path("logs/actions.jsonl")
    log_path.parent.mkdir(exist_ok=True)
    with open(log_path, "a") as f:
        f.write(json.dumps(entry) + "\n")
    return entry

# ── AI Analysis ───────────────────────────────────────────────────────────────

@app.post("/api/analyze")
async def analyze_finding(req: AnalysisRequest):
    """AI-gestützte Analyse von Findings, Code-Snippets, Tool-Output."""

    # Consent Gate
    if not verify_consent(req.consent_token, req.scope):
        raise HTTPException(403, "Consent not verified — operation blocked by SecureOS")

    # Tier Gate
    if not check_tier_permission(req.tier, req.phase):
        raise HTTPException(403, f"Tier {req.tier} does not unlock Phase {req.phase}")

    tier_context = f"""
[SESSION CONTEXT]
Active Tier: {req.tier}
Unlocked Phases: 1-{[2,4,5,8][min(req.tier-1,3)]}
Current Phase: {req.phase}
Scope: {req.scope}
Consent: VERIFIED
"""

    try:
        async with httpx.AsyncClient(timeout=120.0) as client:
            response = await client.post(
                f"{OLLAMA_URL}/api/generate",
                json={
                    "model": OLLAMA_MODEL,
                    "system": SYSTEM_PROMPT + tier_context,
                    "prompt": req.input,
                    "stream": False,
                    "options": {
                        "temperature": 0.1,
                        "top_p": 0.9,
                        "num_ctx": 8192
                    }
                }
            )
        result = response.json()
        analysis = result.get("response", "")

        log_action("AI_ANALYSIS", req.scope, "ollama/mistral", analysis, "INFO")

        return {
            "analysis": analysis,
            "model": OLLAMA_MODEL,
            "tier": req.tier,
            "phase": req.phase,
            "tokens": result.get("eval_count", 0)
        }

    except httpx.ConnectError:
        raise HTTPException(503, "Ollama not running — start with: ollama serve")

# ── WebSocket: Live Scan Streaming ────────────────────────────────────────────

@app.websocket("/ws/scan")
async def scan_stream(websocket: WebSocket):
    """
    WebSocket für Live-Scan-Output Streaming zum Dashboard.
    Schickt Tool-Output Zeile für Zeile in Echtzeit.
    """
    await websocket.accept()

    try:
        data = await websocket.receive_json()
        target = data.get("target")
        tool = data.get("tool")
        consent_token = data.get("consent_token")
        tier = data.get("tier", 1)

        # Consent Gate
        if not verify_consent(consent_token, target):
            await websocket.send_json({
                "type": "error",
                "message": "CONSENT NOT VERIFIED — scan blocked"
            })
            await websocket.close()
            return

        # Tool-Command Mapping (Tier-geprüft)
        tool_commands = {
            # Phase 1 — Tier 1+
            "subfinder": ["subfinder", "-d", target, "-silent"],
            "dnsx": ["dnsx", "-silent"],
            "whatweb": ["whatweb", target, "--log-brief=-"],
            "wafw00f": ["wafw00f", target],
            # Phase 3 — Tier 2+
            "gobuster": ["gobuster", "dir", "-u", f"https://{target}", "-w",
                         "/usr/share/wordlists/dirbuster/directory-list-2.3-small.txt",
                         "-q", "--no-error"],
            "gospider": ["gospider", "-s", f"https://{target}", "-q"],
            # Phase 4 — Tier 2+
            "nuclei": ["nuclei", "-u", f"https://{target}", "-silent",
                       "-severity", "medium,high,critical"],
            "nikto": ["nikto", "-h", target, "-Format", "txt"],
        }

        if tool not in tool_commands:
            await websocket.send_json({"type": "error", "message": f"Unknown tool: {tool}"})
            return

        cmd = tool_commands[tool]

        await websocket.send_json({
            "type": "start",
            "tool": tool,
            "target": target,
            "timestamp": datetime.datetime.utcnow().isoformat() + "Z"
        })

        # Stream subprocess output
        process = await asyncio.create_subprocess_exec(
            *cmd,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.STDOUT
        )

        line_count = 0
        async for line in process.stdout:
            decoded = line.decode("utf-8", errors="replace").rstrip()
            if decoded:
                line_count += 1
                await websocket.send_json({
                    "type": "output",
                    "line": decoded,
                    "count": line_count
                })

        await process.wait()
        await websocket.send_json({
            "type": "complete",
            "tool": tool,
            "lines": line_count,
            "timestamp": datetime.datetime.utcnow().isoformat() + "Z"
        })

        log_action("SCAN", target, tool, f"{line_count} lines output", "INFO")

    except WebSocketDisconnect:
        pass
    except Exception as e:
        await websocket.send_json({"type": "error", "message": str(e)})

# ── Consent Verification ──────────────────────────────────────────────────────

@app.post("/api/consent/verify")
async def verify_consent_endpoint(req: ConsentVerifyRequest):
    """Verifiziert Consent für ein Engagement."""
    verified = verify_consent(req.token, req.domain)
    if verified:
        log_action("CONSENT_VERIFIED", req.domain, "consent-gate", req.method)
        return {"verified": True, "domain": req.domain, "method": req.method}
    raise HTTPException(403, "Consent verification failed")

# ── Phase Gate ────────────────────────────────────────────────────────────────

@app.post("/api/phase/advance")
async def advance_phase(req: PhaseGateRequest):
    """Schaltet nächste Phase frei nach expliziter Bestätigung."""
    if req.next_phase in [6, 7, 8] and not req.admin_present:
        raise HTTPException(403, f"Phase {req.next_phase} requires admin presence")
    if req.next_phase > req.current_phase + 1:
        raise HTTPException(400, "Cannot skip phases")

    log_action("PHASE_ADVANCE", req.engagement_id, "phase-gate",
               f"Phase {req.current_phase} → {req.next_phase}")
    return {
        "phase": req.next_phase,
        "unlocked": True,
        "admin_required": req.next_phase >= 6
    }

# ── Health ────────────────────────────────────────────────────────────────────

@app.get("/api/health")
async def health():
    # Prüfe ob Ollama läuft
    try:
        async with httpx.AsyncClient(timeout=3.0) as client:
            r = await client.get(f"{OLLAMA_URL}/api/tags")
        ollama_ok = r.status_code == 200
    except:
        ollama_ok = False

    return {
        "status": "ok",
        "ollama": ollama_ok,
        "model": OLLAMA_MODEL,
        "version": "4.0"
    }
