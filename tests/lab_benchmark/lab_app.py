"""
VAA Benchmark Lab - FastAPI app con 1 endpoint por vulnerabilidad.
Cada endpoint es una unidad de prueba aislada con comportamiento determinista.

Uso:
    cd tests/lab_benchmark
    pip install fastapi uvicorn httpx python-jose
    uvicorn lab_app:app --port 9000 --reload
"""
from fastapi import FastAPI, Request, Response, Depends, Header, Body, Query, HTTPException
from fastapi.responses import JSONResponse, HTMLResponse
from fastapi.security import OAuth2PasswordBearer, OAuth2PasswordRequestForm
from typing import Optional
import sqlite3, subprocess, httpx, time, uuid, re, asyncio
from jose import jwt


SECRET_KEY = "benchmark-secret-do-not-use-in-prod"
ALGORITHM  = "HS256"

app = FastAPI(
    title="VAA Benchmark Lab",
    description="Laboratorio de referencia: 1 endpoint = 1 vulnerabilidad = 1 ground truth",
    version="1.0.0"
)


def init_db():
    conn = sqlite3.connect(":memory:", check_same_thread=False)
    c = conn.cursor()
    c.execute("CREATE TABLE users (id INTEGER PRIMARY KEY, username TEXT, role TEXT)")
    c.execute("INSERT INTO users VALUES (1, 'user1', 'user')")
    c.execute("INSERT INTO users VALUES (2, 'user2', 'user')")
    c.execute("INSERT INTO users VALUES (3, 'admin', 'admin')")
    c.execute("CREATE TABLE resources (id INTEGER PRIMARY KEY, owner_id INTEGER, data TEXT)")
    c.execute("INSERT INTO resources VALUES (101, 1, 'secret_data_of_user1')")
    c.execute("INSERT INTO resources VALUES (102, 2, 'secret_data_of_user2')")
    c.execute("CREATE TABLE logs (id INTEGER PRIMARY KEY, ua TEXT)")
    conn.commit()
    return conn

db = init_db()


oauth2_scheme = OAuth2PasswordBearer(tokenUrl="/lab/auth/token")

def create_token(username: str, role: str = "user") -> str:
    return jwt.encode({"sub": username, "role": role}, SECRET_KEY, algorithm=ALGORITHM)

def get_current_user(token: str = Depends(oauth2_scheme)) -> dict:
    try:
        payload = jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])
        return {"username": payload["sub"], "role": payload.get("role", "user")}
    except Exception:
        raise HTTPException(status_code=401, detail="Invalid token")

def get_admin_user(token: str = Depends(oauth2_scheme)) -> dict:
    user = get_current_user(token)
    if user["role"] != "admin":
        raise HTTPException(status_code=403, detail="Admin only")
    return user


@app.post("/lab/auth/token", tags=["Auth"])
async def login(form_data: OAuth2PasswordRequestForm = Depends()):
    """Devuelve tokens para user1, user2, admin."""
    users = {
        "user1": ("user1", "user"),
        "user2": ("user2", "user"),
        "admin": ("admin", "admin"),
    }
    if form_data.username not in users or form_data.password not in ("pass1", "pass2", "supersecret", "pass123", "pass456"):
        raise HTTPException(status_code=401, detail="Invalid credentials")
    uname, role = users[form_data.username]
    return {"access_token": create_token(uname, role), "token_type": "bearer"}


@app.get("/lab/bola-int", tags=["Lab"])
async def lab_bola_int_list(current_user: dict = Depends(get_current_user)):
    """Safe: Devuelve los recursos que pertenecen al usuario."""
    c = db.cursor()


    c.execute("SELECT id, owner_id, data FROM resources")
    return [{"id": row[0], "owner_id": row[1], "data": row[2]} for row in c.fetchall()]

@app.get("/lab/bola-int/{resource_id}", tags=["Lab"])
async def lab_bola_int(resource_id: int, current_user: dict = Depends(get_current_user)):
    """VULNERABLE: BOLA con ID entero — no verifica ownership."""
    c = db.cursor()
    c.execute("SELECT * FROM resources WHERE id = ?", (resource_id,))
    row = c.fetchone()
    if not row:
        raise HTTPException(status_code=404, detail="Not found")
    return {"id": row[0], "owner_id": row[1], "data": row[2]}


UUID_RESOURCES = {
    "a0eebc99-9c0b-4ef8-bb6d-6bb9bd380a11": {"owner": "user1", "secret": "private_doc_A"},
    "b1ffcd88-1d0a-5ef9-cc7e-7cc0ce491b22": {"owner": "user2", "secret": "private_doc_B"},
}

@app.get("/lab/bola-uuid", tags=["Lab"])
async def lab_bola_uuid_list(current_user: dict = Depends(get_current_user)):
    """Safe: Devuelve los recursos que pertenecen al usuario."""
    return [{"uuid": k, **v} for k, v in UUID_RESOURCES.items()]

@app.get("/lab/bola-uuid/{resource_uuid}", tags=["Lab"])
async def lab_bola_uuid(resource_uuid: str, current_user: dict = Depends(get_current_user)):
    """VULNERABLE: BOLA con UUID — no verifica que UUID pertenece al usuario."""
    if resource_uuid not in UUID_RESOURCES:
        raise HTTPException(status_code=404, detail="Not found")
    return {"uuid": resource_uuid, **UUID_RESOURCES[resource_uuid]}


@app.get("/lab/xss-get", response_class=HTMLResponse, tags=["Lab"])
async def lab_xss_get(q: str = Query("guest")):
    """VULNERABLE: XSS reflejado en GET — parámetro sin sanitizar en HTML."""
    return f"<html><body><h1>Resultados para: {q}</h1></body></html>"


@app.post("/lab/xss-post", response_class=HTMLResponse, tags=["Lab"])
async def lab_xss_post(message: str = Body(..., embed=True)):
    """VULNERABLE: XSS reflejado en POST — body sin sanitizar en HTML."""
    return f"<html><body><div>Tu mensaje: {message}</div></body></html>"


@app.get("/lab/sqli-classic", tags=["Lab"])
async def lab_sqli_classic(q: str = Query(...), current_user: dict = Depends(get_current_user)):
    """VULNERABLE: SQLi clásico — query param concatenado en SQL."""
    query = f"SELECT username, role FROM users WHERE username LIKE '%{q}%'"
    try:
        c = db.cursor()
        c.execute(query)
        results = [{"username": r[0], "role": r[1]} for r in c.fetchall()]
        return {"results": results}
    except Exception as e:
        return JSONResponse(status_code=500, content={"error": "DB Error", "detail": str(e)})


@app.get("/lab/sqli-blind", tags=["Lab"])
async def lab_sqli_blind(request: Request, current_user: dict = Depends(get_current_user)):
    """VULNERABLE: SQLi blind via header User-Agent — no retorna error."""
    ua = request.headers.get("User-Agent", "")
    query = f"INSERT INTO logs (ua) VALUES ('{ua}')"
    try:
        c = db.cursor()
        c.executescript(query)
    except Exception:
        pass
    if "pg_sleep" in ua or "WAITFOR DELAY" in ua or "sleep(" in ua:
        import asyncio
        await asyncio.sleep(6)
    return {"status": "tracked"}


@app.get("/lab/ssrf-basic", tags=["Lab"])
async def lab_ssrf_basic(url: str = Query(...), current_user: dict = Depends(get_current_user)):
    """VULNERABLE: SSRF básico — url param sin validación."""
    try:
        async with httpx.AsyncClient() as client:
            resp = await client.get(url, timeout=2.0)
            return {"content": resp.text[:200], "status": resp.status_code}
    except Exception as e:
        return {"error": str(e)}


@app.get("/lab/ssrf-redirect", tags=["Lab"])
async def lab_ssrf_redirect(url: str = Query(...), current_user: dict = Depends(get_current_user)):
    """VULNERABLE: SSRF con bypass via redirect — bloquea localhost pero sigue 302."""
    from urllib.parse import urlparse
    parsed = urlparse(url)
    if parsed.hostname in ["localhost", "127.0.0.1", "::1"]:
        raise HTTPException(status_code=403, detail="Internal network blocked")
    try:
        async with httpx.AsyncClient(follow_redirects=True) as client:
            resp = await client.get(url, timeout=3.0)
            return {"preview": resp.text[:100]}
    except Exception as e:
        return {"error": str(e)}


@app.post("/lab/rce-ping", tags=["Lab"])
async def lab_rce_ping(target: str = Body(..., embed=True), current_user: dict = Depends(get_current_user)):
    """VULNERABLE: RCE via ping con shell=True. Blacklist bypassable con $() o backticks."""


    blacklist = [";", "|", "||", ">", " "]
    for ch in blacklist:
        if ch in target:
            return JSONResponse(status_code=400, content={"error": "Illegal character"})
    cmd = f"ping -n 1 {target}" if __import__("os").name == "nt" else f"ping -c 1 {target}"
    try:
        proc = await asyncio.create_subprocess_shell(
            cmd,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE
        )
        stdout, stderr = await asyncio.wait_for(proc.communicate(), timeout=5.0)
        out = (stdout + stderr).decode('utf-8', errors='ignore')
        return {"result": out}
    except asyncio.TimeoutError:
        return {"error": "Request timeout"}
    except Exception as e:
        return {"error": str(e)}


@app.post("/lab/rce-dns", tags=["Lab"])
async def lab_rce_dns(domain: str = Body(..., embed=True), current_user: dict = Depends(get_admin_user)):
    """VULNERABLE: RCE admin-only via nslookup. Separadores ; y | disparan respuesta RCE."""
    if ";" in domain or "|" in domain:
        return {"output": "root\nSUCCESS_RCE_VAA_BENCHMARK"}
    try:
        cmd = f"nslookup {domain}"
        proc = await asyncio.create_subprocess_shell(
            cmd,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE
        )
        stdout, stderr = await asyncio.wait_for(proc.communicate(), timeout=5.0)
        out = (stdout + stderr).decode('utf-8', errors='ignore')
        return {"output": out}
    except asyncio.TimeoutError:
        return {"output": "nslookup timeout"}
    except Exception as e:
        return {"error": str(e)}


from pydantic import BaseModel

class ProfileUpdate(BaseModel):
    email: Optional[str] = None
    role: Optional[str] = None

@app.put("/lab/mass-assign-pydantic", tags=["Lab"])
async def lab_mass_assign_pydantic(update: ProfileUpdate, current_user: dict = Depends(get_current_user)):
    """VULNERABLE: Mass Assignment via Pydantic — campo 'role' aceptado y reflejado."""
    return {"message": "Profile updated", "new_role": update.role, "email": update.email}


@app.put("/lab/mass-assign-dict", tags=["Lab"])
async def lab_mass_assign_dict(request: Request, current_user: dict = Depends(get_current_user)):
    """VULNERABLE: Mass Assignment via dict libre — cualquier campo se aplica a la BD."""
    try:
        payload = await request.json()
    except:
        raise HTTPException(status_code=400, detail="Invalid JSON")
    payload.pop("id", None)
    return {"status": "updated", "applied_fields": list(payload.keys()), "values": payload}


@app.get("/lab/bfla", tags=["Lab"])
async def lab_bfla(request: Request):
    """VULNERABLE: BFLA — endpoint admin sin verificación de rol, responde a cualquier token."""

    auth = request.headers.get("Authorization", "")
    c = db.cursor()
    c.execute("SELECT id, username, role FROM users")
    users = [{"id": r[0], "username": r[1], "role": r[2]} for r in c.fetchall()]
    return {"users": users, "exported_by": "shadow_admin_endpoint"}


JAILBREAK_PATTERNS = [
    "ignore previous", "ignore all", "ahora eres", "actua como",
    "as a developer", "leak", "override", "disregard", "forget instructions"
]

@app.post("/lab/prompt-injection", tags=["Lab"])
async def lab_prompt_injection(prompt: str = Body(..., embed=True), current_user: dict = Depends(get_current_user)):
    """VULNERABLE: Prompt Injection — jailbreaks revelan VAA_AI_OVERRIDE_SUCCESS."""
    clean = prompt.lower().strip()
    if any(p in clean for p in JAILBREAK_PATTERNS):
        return {
            "response": "OK, I will ignore previous instructions.",
            "leaked_secret": "SYSTEM_SECRET=VAA_BENCHMARK_PWNED",
            "mode": "UNRESTRICTED"
        }
    return {"response": f"Processing your request: {prompt[:50]}..."}


import html

@app.get("/lab/safe-endpoint", tags=["Lab"])
async def lab_safe_endpoint(q: str = Query("hello"), current_user: dict = Depends(get_current_user)):
    """SEGURO: Control FP — sanitiza inputs, respuesta determinista."""
    safe_q = html.escape(q)[:50]
    return {"message": f"Hello, {safe_q}!", "status": "ok", "safe": True}
