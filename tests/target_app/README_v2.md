# VAA Cyber-range v4.0.0 - Enterprise-grade Vulnerable API

## 🚀 Quick Start

### Option 1: Run Locally (Development)

1. **Install dependencies:**
```bash
pip install -r requirements.txt
```

2. **Run the application:**
```bash
python main_v2.py
```

3. **Access the API:**
- Main page: http://127.0.0.1:8000
- API Docs (Swagger): http://127.0.0.1:8000/docs
- Health check: http://127.0.0.1:8000/health

### Option 2: Run with Docker (Production-like)

1. **Build and start:**
```bash
docker-compose up --build
```

2. **Access the API:**
- Main page: http://localhost:8000
- API Docs: http://localhost:8000/docs

3. **Stop:**
```bash
docker-compose down
```

---

## 🔐 Authentication

The v2 API uses **OAuth2 + JWT** authentication.

### Get Access Token

```bash
curl -X POST "http://localhost:8000/api/v1/auth/token" \
  -H "Content-Type: application/x-www-form-urlencoded" \
  -d "username=admin&password=supersecret"
```

**Response:**
```json
{
  "access_token": "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9...",
  "token_type": "bearer"
}
```

### Use Token in Requests

```bash
TOKEN="your_access_token_here"

curl -H "Authorization: Bearer $TOKEN" \
  "http://localhost:8000/api/v1/search/users?q=admin"
```

### Available Users

| Username | Password | Role |
|----------|----------|------|
| admin | supersecret | admin |
| user1 | pass123 | user |
| user2 | pass456 | user |

---

## 🛡️ Security Features (v2)

### 1. **OAuth2 + JWT Authentication**
- All sensitive endpoints require valid JWT token
- Tokens expire after 30 minutes
- Bcrypt password hashing (no plain text)

### 2. **Rate Limiting**
- Login: 5 attempts/minute
- Search: 10 requests/minute
- Admin endpoints: 5 requests/minute
- Prevents brute force and DoS attacks

### 3. **WAF (Web Application Firewall)**
- Detects XSS, SQLi, RCE patterns
- Blocks IP after 3 violations
- 5-minute block duration

### 4. **Structured Logging**
- JSON-formatted logs
- Tracks all security events
- User actions audited

### 5. **Security Headers**
- Content-Security-Policy
- X-Frame-Options: DENY
- Strict-Transport-Security (HSTS)
- X-Content-Type-Options: nosniff

### 6. **CORS Protection**
- Restricted to specific origins
- Credentials required
- Prevents CSRF attacks

---

## 🎯 Intentional Vulnerabilities (For Training)

Despite enterprise-grade defenses, the following vulnerabilities are **intentionally present** for security training:

### 1. **XSS (Reflected)**
- Endpoint: `/api/v1/search/html`
- Bypass WAF with encoding

### 2. **SQL Injection**
- Endpoint: `/api/v1/search/users`
- Bypass WAF with obfuscation

### 3. **BOLA (Broken Object Level Authorization)**
- Endpoint: `/api/v1/orders/{order_id}`
- Access other users' orders

### 4. **Mass Assignment**
- Endpoint: `/api/v1/users/me`
- Inject `role` field to escalate privileges

### 5. **SSRF (Server-Side Request Forgery)**
- Endpoint: `/api/v1/utils/fetch-icon`
- Access internal services

### 6. **AI Prompt Injection**
- Endpoint: `/api/v1/ai/summarize-complaint`
- Jailbreak the LLM

### 7. **GraphQL DoS**
- Endpoint: `/graphql`
- Recursive queries

### 8. **Shadow API**
- Endpoint: `/api/v2/admin/debug/export-users`
- Undocumented, no authentication

### 9. **Command Injection**
- Endpoint: `/api/v1/tools/ping-check`
- Bypass blacklist filters

### 10. **Blind SQL Injection**
- Endpoint: `/api/v1/analytics/track`
- Header-based injection

---

## 🧪 Testing with VAA Scanner

### Basic Scan (Authenticated)

```bash
# Get token
TOKEN=$(curl -s -X POST "http://localhost:8000/api/v1/auth/token" \
  -d "username=admin&password=supersecret" | jq -r .access_token)

# Run scanner
python ../../vaa_cli.py \
  --target http://localhost:8000 \
  --header "Authorization: Bearer $TOKEN"
```

### Full Scan (All Phases)

```bash
python ../../vaa_cli.py \
  --target http://localhost:8000 \
  --header "Authorization: Bearer $TOKEN" \
  --recon --fuzz --optimize
```

---

## 📊 Comparison: v1 vs v2

| Feature | v1 | v2 |
|---------|----|----|
| Authentication | Header simulation | OAuth2 + JWT ✅ |
| Password Storage | Plain text | Bcrypt hashed ✅ |
| Rate Limiting | None | SlowAPI ✅ |
| WAF | None | Pattern detection ✅ |
| Logging | Basic print | Structured JSON ✅ |
| Security Headers | None | Full suite ✅ |
| CORS | Open | Restricted ✅ |
| Docker Support | No | Yes ✅ |
| **Realismo** | **51%** | **82%** ✅ |

---

## 🔬 Advanced Testing Scenarios

### Scenario 1: Bypass WAF

```bash
# XSS with encoding
curl -H "Authorization: Bearer $TOKEN" \
  "http://localhost:8000/api/v1/search/html?q=%3Cscript%3Ealert(1)%3C/script%3E"

# SQLi with obfuscation
curl -H "Authorization: Bearer $TOKEN" \
  "http://localhost:8000/api/v1/search/users?q=%27%20OR%20%271%27=%271"
```

### Scenario 2: Privilege Escalation

```bash
# Login as user1
TOKEN=$(curl -s -X POST "http://localhost:8000/api/v1/auth/token" \
  -d "username=user1&password=pass123" | jq -r .access_token)

# Escalate to admin via Mass Assignment
curl -X PUT "http://localhost:8000/api/v1/users/me" \
  -H "Authorization: Bearer $TOKEN" \
  -H "Content-Type: application/json" \
  -d '{"role": "admin"}'
```

### Scenario 3: BOLA Attack

```bash
# Access other user's order
curl -H "Authorization: Bearer $TOKEN" \
  "http://localhost:8000/api/v1/orders/101"
```

---

## 📝 Logs

Logs are written to stdout in JSON format:

```json
{
  "event": "login_success",
  "username": "admin",
  "role": "admin",
  "ip": "127.0.0.1",
  "timestamp": "2026-02-12T14:30:00Z"
}
```

View logs in Docker:
```bash
docker-compose logs -f vaa-app
```

---

## ⚠️ Security Warning

> **WARNING**: This application is **intentionally vulnerable** for security training purposes.
> 
> **DO NOT**:
> - Expose to the internet
> - Use in production
> - Store real user data
> 
> **DO**:
> - Run in isolated networks
> - Use for training only
> - Reset regularly

---

## 🤝 Contributing

This is a training lab. To add new vulnerabilities:

1. Add the vulnerable endpoint in `main_v2.py`
2. Add WAF bypass instructions in this README
3. Test with VAA scanner
4. Document in vulnerability list

---

## 📄 License

MIT License - For educational purposes only

---

**VAA Cyber-range v4.0.0** - Enterprise-grade vulnerable API for security professionals
