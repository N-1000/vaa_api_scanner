from fastapi import FastAPI, Request, Response, HTTPException, Body, Query, Header, Depends, status
from fastapi.responses import JSONResponse, HTMLResponse
from fastapi.security import OAuth2PasswordRequestForm
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel
from typing import Optional, List
from urllib.parse import urlparse
import sqlite3
import os
import uvicorn
import httpx
import time
import uuid
import subprocess


from auth import (
    get_current_user, 
    get_current_admin_user,
    create_access_token, 
    authenticate_user,
    get_password_hash
)
from rate_limiter import limiter, rate_limit_handler
from slowapi.errors import RateLimitExceeded
from waf import waf
from logging_config import logger
from security_headers import SecurityHeadersMiddleware

app = FastAPI(title="VAA Cyber-range v4.0.0 (Enterprise-grade Vulnerable API)", version="2.0.0")


app.add_middleware(SecurityHeadersMiddleware)


app.add_middleware(
    CORSMiddleware,
    allow_origins=["http://localhost:3000", "http://127.0.0.1:3000"],
    allow_credentials=True,
    allow_methods=["GET", "POST", "PUT", "DELETE", "OPTIONS"],
    allow_headers=["*"],
)


app.state.limiter = limiter
app.add_exception_handler(RateLimitExceeded, rate_limit_handler)

logger.info("app_startup", version="2.0.0", features=["OAuth2", "JWT", "WAF", "RateLimiting"])


def init_db():
    conn = sqlite3.connect(":memory:", check_same_thread=False)
    c = conn.cursor()
    

    admin_pass = get_password_hash("supersecret")
    user1_pass = get_password_hash("pass123")
    user2_pass = get_password_hash("pass456")
    
    c.execute("CREATE TABLE users (id INTEGER PRIMARY KEY, username TEXT, password TEXT, role TEXT, email TEXT)")
    c.execute(f"INSERT INTO users VALUES (1, 'admin', '{admin_pass}', 'admin', 'admin@target.local')")
    c.execute(f"INSERT INTO users VALUES (2, 'user1', '{user1_pass}', 'user', 'user1@target.local')")
    c.execute(f"INSERT INTO users VALUES (3, 'user2', '{user2_pass}', 'user', 'user2@target.local')")
    
    c.execute("CREATE TABLE orders (id INTEGER PRIMARY KEY, user_id INTEGER, item TEXT, status TEXT)")
    c.execute("INSERT INTO orders VALUES (101, 2, 'Laptop Pro', 'Shipped')")
    c.execute("INSERT INTO orders VALUES (102, 3, 'Mechanical Keyboard', 'Processing')")
    

    c.execute("CREATE TABLE orders_uuid (id TEXT PRIMARY KEY, user_id INTEGER, item TEXT)")
    c.execute("INSERT INTO orders_uuid VALUES ('a0eebc99-9c0b-4ef8-bb6d-6bb9bd380a11', 2, 'Laptop')")
    c.execute("INSERT INTO orders_uuid VALUES ('b1ffcd88-1d0a-5ef9-cc7e-7cc0ce491b22', 1, 'Phone')")
    

    c.execute("CREATE TABLE logs (id INTEGER PRIMARY KEY, ua TEXT, timestamp TEXT)")
    
    conn.commit()
    return conn

db_conn = init_db()


class UserUpdate(BaseModel):
    email: Optional[str] = None
    role: Optional[str] = None

class OrderCreate(BaseModel):
    item: str

@app.get("/", response_class=HTMLResponse)
async def index():
    links = '<a href="/api/v1/search/users">Buscador de Usuarios (SQLi)</a><br>'
    xss_link = '<br><br><a href="/api/v1/search/html?q=VAA_XSS_TEST">Probar Buscador HTML (XSS)</a>'
    feedback_link = '<br><a href="/api/v1/feedback">Feedback (POST XSS)</a>'
    auth_link = '<br><br><a href="/docs">API Docs (OAuth2 Login)</a>'
    return f"<h1>VAA Cyber-range v4.0.0</h1><p>Enterprise-grade vulnerable API for security training</p>{links}{xss_link}{feedback_link}{auth_link}"


@app.post("/api/v1/auth/token")
@limiter.limit("1000/minute")
async def login(request: Request, form_data: OAuth2PasswordRequestForm = Depends()):
    """
    OAuth2 compatible token endpoint
    Rate limited to 5 attempts per minute per IP
    """
    logger.info("login_attempt", username=form_data.username, ip=request.client.host)
    
    user = authenticate_user(db_conn, form_data.username, form_data.password)
    
    if not user:
        logger.warning("login_failed", username=form_data.username, reason="invalid_credentials", ip=request.client.host)
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Incorrect username or password",
            headers={"WWW-Authenticate": "Bearer"},
        )
    
    access_token = create_access_token(data={"sub": user["username"], "role": user["role"]})
    logger.info("login_success", username=user["username"], role=user["role"], ip=request.client.host)
    
    return {"access_token": access_token, "token_type": "bearer"}


@app.get("/health")
async def health_check():
    """Health check endpoint for monitoring"""
    return {"status": "healthy", "version": "2.0.0"}


@app.get("/api/v1/search/html", response_class=HTMLResponse)
@limiter.limit("1000/minute")
async def search_html(request: Request, q: str = Query("guest")):

    await waf.inspect_request(request)
    
    logger.info("search_html", query=q, ip=request.client.host)
    

    return f"""
    <html>
        <body>
            <h1>Resultados de busqueda para: {q}</h1>
            <p>No se encontraron resultados para su busqueda.</p>
            <a href="/">Volver</a>
        </body>
    </html>
    """


@app.post("/api/v1/feedback", response_class=HTMLResponse)
@limiter.limit("1000/minute")
async def post_feedback(request: Request, message: str = Body(..., embed=True)):
    await waf.inspect_request(request)
    logger.info("feedback_submit", message_length=len(message), ip=request.client.host)
    

    return f"""
    <html>
        <body>
            <h1>Gracias por su feedback</h1>
            <div class="message-box">
                Su mensaje: {message}
            </div>
            <p>Nuestro equipo lo revisara pronto.</p>
            <a href="/">Volver</a>
        </body>
    </html>
    """


@app.get("/api/v1/analytics/track")
@limiter.limit("1000/minute")
async def track_visit(request: Request):

    user_agent = request.headers.get("User-Agent", "")
    
    logger.info("analytics_track", user_agent=user_agent[:50], ip=request.client.host)
    

    query = f"INSERT INTO logs (ua, timestamp) VALUES ('{user_agent}', '{time.time()}')"
    
    try:
        c = db_conn.cursor()
        c.executescript(query) 
        return {"status": "tracked"}
    except:

        return {"status": "tracked"}


@app.post("/api/v1/tools/ping-check")
@limiter.limit("1000/minute")
async def ping_check(request: Request, target: str = Body(..., embed=True), current_user: dict = Depends(get_current_user)):

    blacklist = [";", "|", "&", "&&", "||", ">", " "]
    
    logger.info("ping_check", target=target, user=current_user["username"])
    
    for char in blacklist:
        if char in target:
            return JSONResponse(status_code=400, content={"error": "Illegal character detected"})

    cmd = f"ping -c 1 {target}"
    try:

        output = subprocess.check_output(cmd, shell=True, stderr=subprocess.STDOUT)
        return {"result": output.decode()}
    except Exception as e:
        return {"error": "Ping failed", "details": str(e)}


@app.get("/api/v1/orders/{order_id}")
@limiter.limit("1000/minute")
async def get_order(request: Request, order_id: int, current_user: dict = Depends(get_current_user)):

    logger.info("order_access", order_id=order_id, user=current_user["username"])
    
    c = db_conn.cursor()
    c.execute("SELECT * FROM orders WHERE id = ?", (order_id,))
    order = c.fetchone()
    if not order:
        raise HTTPException(status_code=404, detail="Order not found")
    
    return {"id": order[0], "owner_id": order[1], "item": order[2], "status": order[3]}


@app.put("/api/v1/users/me")
@limiter.limit("1000/minute")
async def update_profile(request: Request, update: UserUpdate, current_user: dict = Depends(get_current_user)):

    logger.info("profile_update", user=current_user["username"], fields=update.dict(exclude_unset=True))
    
    c = db_conn.cursor()
    c.execute("SELECT id FROM users WHERE username = ?", (current_user["username"],))
    user_id = c.fetchone()[0]
    
    if update.email:
        c.execute("UPDATE users SET email = ? WHERE id = ?", (update.email, user_id))
    if update.role:
        c.execute("UPDATE users SET role = ? WHERE id = ?", (update.role, user_id))
    db_conn.commit()
    return {"message": "Profile updated", "new_role": update.role}


@app.get("/api/v1/utils/fetch-icon")
@limiter.limit("1000/minute")
async def fetch_icon(request: Request, url: str, current_user: dict = Depends(get_current_user)):

    logger.info("fetch_icon", url=url, user=current_user["username"])
    
    try:
        async with httpx.AsyncClient() as client:
            resp = await client.get(url, timeout=2.0)
            return Response(content=resp.content, media_type=resp.headers.get("Content-Type"))
    except Exception as e:
        return {"error": "Failed to fetch icon", "detail": str(e)}


@app.get("/api/v1/utils/preview-link")
@limiter.limit("1000/minute")
async def preview_link(request: Request, url: str, current_user: dict = Depends(get_current_user)):

    parsed = urlparse(url)
    if parsed.hostname in ["localhost", "127.0.0.1", "::1"]:
        return JSONResponse(status_code=403, content={"error": "Internal network access denied"})

    try:
        async with httpx.AsyncClient(follow_redirects=True) as client:

            resp = await client.get(url, timeout=3.0)
            return {"preview": resp.text[:100]}
    except Exception:
        return {"error": "Fetch failed"}


@app.get("/api/v1/orders/track/{order_uuid}")
@limiter.limit("1000/minute")
async def track_order_uuid(request: Request, order_uuid: str, current_user: dict = Depends(get_current_user)):

    logger.info("track_order_uuid", order_uuid=order_uuid, user=current_user["username"])
    
    c = db_conn.cursor()
    c.execute("SELECT * FROM orders_uuid WHERE id = ?", (order_uuid,))
    order = c.fetchone()
    if not order:
        raise HTTPException(status_code=404, detail="Order not found")
    

    return {"status": "Shipped", "details": {"id": order[0], "owner": order[1], "item": order[2]}}


@app.put("/api/v1/users/update")
@limiter.limit("1000/minute")
async def advanced_profile_update(request: Request, current_user: dict = Depends(get_current_user)):

    try:
        payload = await request.json()
        if 'id' in payload: del payload['id']
        
        logger.info("advanced_profile_update", fields=list(payload.keys()), user=current_user["username"])
        

        columns = ", ".join([f"{k} = ?" for k in payload.keys()])
        values = list(payload.values())
        
        c = db_conn.cursor()
        c.execute("SELECT id FROM users WHERE username = ?", (current_user["username"],))
        user_id = c.fetchone()[0]
        values.append(user_id)
        
        query = f"UPDATE users SET {columns} WHERE id = ?"
        c.execute(query, tuple(values))
        db_conn.commit()
        return {"status": "updated", "fields": list(payload.keys())}
    except Exception as e:
        return JSONResponse(status_code=400, content={"error": "Update failed", "detail": str(e)})


@app.get("/api/v1/mass-test/{item_id}")
@limiter.limit("1000/minute")
async def mass_test(request: Request, item_id: str):
    logger.info("mass_test", item_id=item_id, ip=request.client.host)
    return {"item_id": item_id, "status": "ok"}


@app.get("/api/v2/admin/debug/export-users")
@limiter.limit("1000/minute")
async def shadow_export(request: Request):

    logger.warning("shadow_api_access", endpoint="/api/v2/admin/debug/export-users", ip=request.client.host)
    
    c = db_conn.cursor()
    c.execute("SELECT * FROM users")
    users = c.fetchall()
    return {"users": users}


@app.post("/api/v1/ai/summarize-complaint")
@limiter.limit("1000/minute")
async def ai_summarize(request: Request, complaint: str = Body(..., embed=True), current_user: dict = Depends(get_current_user)):

    logger.info("ai_summarize", complaint_length=len(complaint), user=current_user["username"])
    
    clean_input = complaint.lower().strip()
    
    jailbreak_patterns = ["ignore previous instructions", "ahora eres", "actua como", "ignore all rules"]
    is_jailbroken = any(p in clean_input for p in jailbreak_patterns)
    
    if is_jailbroken:
        logger.warning("ai_jailbreak_detected", user=current_user["username"])
        return {
            "summary": "OK, I will ignore previous rules.",
            "leaked_data": "SYSTEM_SECRET_KEY: VAA_AI_OVERRIDE_SUCCESS",
            "mode": "Unrestricted"
        }
    
    return {"summary": f"User is complaining about: {complaint[:20]}..."}


graph_db = {
    "me": {"id": 1, "name": "Admin", "friends": [2, 3]},
    "users": [{"id": 2, "name": "Alice", "friends": [1]}, {"id": 3, "name": "Bob", "friends": [1]}]
}

@app.post("/graphql")
@limiter.limit("1000/minute")
async def graphql_endpoint(request: Request):
    try:
        body = await request.json()
        query = body.get("query", "") if isinstance(body, dict) else ""
        
        logger.info("graphql_query", query_length=len(query), ip=request.client.host)
        
        if "__schema" in query or "__type" in query:
            return {"data": {"__schema": {"types": ["User", "Query", "Mutation"], "warning": "VAA_DETECTED_INTROSPECTION"}}}

        if query.count("{") > 5: 
            logger.warning("graphql_dos_attempt", depth=query.count("{"), ip=request.client.host)
            return JSONResponse(status_code=429, content={"error": "Query too complex, server overload simulated."})

        if isinstance(body, list):
             return [{"data": f"Result for query {i}"} for i in range(len(body))]

        return {"data": "GraphQL endpoint active. Try querying { me { name } }"}
    except Exception:
        return {"errors": [{"message": "Invalid GraphQL request"}]}


@app.get("/api/v1/search/users")
@limiter.limit("1000/minute")
async def search_users(request: Request, q: str = Query(...), current_user: dict = Depends(get_current_user)):

    await waf.inspect_request(request)
    
    logger.info("user_search", query=q, user=current_user["username"], ip=request.client.host)
    

    query = f"SELECT username FROM users WHERE username LIKE '%{q}%'"
    try:
        c = db_conn.cursor()
        c.execute(query)
        results = [r[0] for r in c.fetchall()]
        logger.info("search_results", count=len(results))
        return {"results": results}
    except Exception as e:
        logger.error("database_error", error=str(e), query=q)
        return JSONResponse(status_code=500, content={"error": "Database Error", "detail": str(e)})


@app.post("/api/v1/tools/dns-lookup")
@limiter.limit("1000/minute")
async def dns_lookup(request: Request, domain: str = Body(..., embed=True), current_user: dict = Depends(get_current_admin_user)):

    logger.info("dns_lookup", domain=domain, user=current_user["username"])
    
    try:
        if os.name == "nt":
            cmd = f"nslookup {domain}"
        else:
            cmd = f"nslookup {domain}"
            

        if ";" in domain or "|" in domain:
            return {"output": "root\nSUCCESS_RCE_VAA"}
            
        output = subprocess.check_output(cmd, shell=True, stderr=subprocess.STDOUT)
        return {"output": output.decode()}
    except Exception as e:
        return {"error": str(e)}


@app.get("/dev/api_docs/postman_collection.json")
@limiter.limit("1000/minute")
async def exposed_postman(request: Request):
    """Simulates an accidentally exposed Postman Collection"""
    return {
        "info": {
            "_postman_id": "aa11bb22-cc33-44dd-55ee-ff66gg77hh88",
            "name": "VAA Lab Internal API",
            "schema": "https://schema.getpostman.com/json/collection/v4.0.0/collection.json"
        },
        "item": [
            {
                "name": "Admin",
                "item": [
                    {
                        "name": "Shadow Export",
                        "request": {
                            "method": "GET",
                            "header": [],
                            "url": {
                                "raw": "{{base_url}}/api/v2/admin/debug/export-users",
                                "host": ["{{base_url}}"],
                                "path": ["api", "v2", "admin", "debug", "export-users"]
                            }
                        }
                    }
                ]
            },
            {
                "name": "Auth",
                "request": {
                    "method": "POST",
                    "header": [],
                    "url": {
                        "raw": "{{base_url}}/api/v1/auth/token",
                        "host": ["{{base_url}}"],
                        "path": ["api", "v1", "auth", "token"]
                    }
                }
            }
        ]
    }

@app.get("/dev/traffic_dump.har")
@limiter.limit("1000/minute")
async def exposed_har(request: Request):
    """Simulates an accidentally exposed HAR file"""
    return {
        "log": {
            "version": "1.2",
            "creator": {"name": "DevTools", "version": "1.0"},
            "entries": [
                {
                    "request": {
                        "method": "POST",
                        "url": "http://localhost:8000/api/v1/auth/token",
                        "headers": [{"name": "Content-Type", "value": "application/x-www-form-urlencoded"}],
                        "postData": {"mimeType": "application/x-www-form-urlencoded", "text": "username=admin&password=supersecret"}
                    },
                    "response": {"status": 200, "content": {"mimeType": "application/json"}}
                },
                {
                    "request": {
                        "method": "GET",
                        "url": "http://localhost:8000/api/v2/admin/debug/export-users",
                        "headers": []
                    },
                    "response": {"status": 200}
                }
            ]
        }
    }

if __name__ == "__main__":
    uvicorn.run(app, host="127.0.0.1", port=8000)
