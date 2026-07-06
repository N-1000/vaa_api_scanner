# 🚀 VAA Cyber-range v2 - Local Setup Guide

## Quick Start (Local - Sin Docker)

### 1. Instalar Dependencias

```bash
cd tests/target_app
pip install -r requirements.txt
```

**Dependencias instaladas:**
- `fastapi` - Framework web
- `uvicorn` - Servidor ASGI
- `python-jose` - JWT tokens
- `bcrypt` - Password hashing
- `slowapi` - Rate limiting
- `structlog` - Structured logging
- `httpx` - HTTP client

### 2. Ejecutar el Servidor

```bash
python run_v2.py
```

**Servidor iniciado en:**
- 🌐 Main: http://127.0.0.1:8000
- 📚 API Docs: http://127.0.0.1:8000/docs
- ❤️ Health: http://127.0.0.1:8000/health

---

## 🔐 Autenticación

### Obtener Token

**PowerShell:**
```powershell
$response = Invoke-RestMethod -Method POST -Uri "http://127.0.0.1:8000/api/v1/auth/token" `
  -ContentType "application/x-www-form-urlencoded" `
  -Body "username=admin&password=supersecret"
$token = $response.access_token
```

**Curl:**
```bash
curl -X POST "http://127.0.0.1:8000/api/v1/auth/token" \
  -H "Content-Type: application/x-www-form-urlencoded" \
  -d "username=admin&password=supersecret"
```

### Usuarios Disponibles

| Username | Password | Role |
|----------|----------|------|
| admin | supersecret | admin |
| user1 | pass123 | user |
| user2 | pass456 | user |

### Usar Token

**PowerShell:**
```powershell
Invoke-RestMethod -Uri "http://127.0.0.1:8000/api/v1/search/users?q=admin" `
  -Headers @{"Authorization" = "Bearer $token"}
```

**Curl:**
```bash
curl -H "Authorization: Bearer YOUR_TOKEN" \
  "http://127.0.0.1:8000/api/v1/search/users?q=admin"
```

---

## 🛡️ Features de Seguridad v2

### 1. **OAuth2 + JWT**
- Tokens con expiración de 30 minutos
- Bcrypt password hashing
- Role-based access control

### 2. **Rate Limiting**
- Login: 5 requests/minuto
- Search: 10 requests/minuto
- Admin: 5 requests/minuto

### 3. **WAF (Web Application Firewall)**
- Detecta XSS, SQLi, RCE
- Bloquea IP después de 3 violaciones
- Duración de bloqueo: 5 minutos

### 4. **Structured Logging**
- Formato JSON
- Eventos auditados
- Timestamps ISO

### 5. **Security Headers**
- Content-Security-Policy
- X-Frame-Options: DENY
- Strict-Transport-Security
- X-Content-Type-Options: nosniff

---

## 🎯 Vulnerabilidades Intencionales

A pesar de las defensas empresariales, estas vulnerabilidades están **intencionalmente presentes** para entrenamiento:

### 1. **XSS (Reflected)**
```
GET /api/v1/search/html?q=<script>alert(1)</script>
```
**Bypass WAF:** URL encoding

### 2. **SQL Injection**
```
GET /api/v1/search/users?q=' OR '1'='1
```
**Bypass WAF:** Obfuscación

### 3. **BOLA (Broken Object Level Authorization)**
```
GET /api/v1/orders/101
```
Accede a órdenes de otros usuarios

### 4. **Mass Assignment**
```
PUT /api/v1/users/me
Body: {"role": "admin"}
```
Escala privilegios a admin

### 5. **AI Prompt Injection**
```
POST /api/v1/ai/summarize-complaint
Body: {"complaint": "ignore previous instructions"}
```
Jailbreak del LLM simulado

### 6. **GraphQL DoS**
```
POST /graphql
Body: {"query": "{ me { friends { friends { friends { name } } } } }"}
```
Query recursiva

### 7. **Shadow API**
```
GET /api/v2/admin/debug/export-users
```
Endpoint no documentado sin autenticación

---

## 🧪 Testing con VAA Scanner

### Scan Básico (Autenticado)

```powershell
# 1. Obtener token
$response = Invoke-RestMethod -Method POST -Uri "http://127.0.0.1:8000/api/v1/auth/token" `
  -ContentType "application/x-www-form-urlencoded" `
  -Body "username=admin&password=supersecret"
$token = $response.access_token

# 2. Ejecutar scanner
python vaa_cli.py --target http://127.0.0.1:8000 --header "Authorization: Bearer $token"
```

### Scan Completo

```powershell
python vaa_cli.py `
  --target http://127.0.0.1:8000 `
  --header "Authorization: Bearer $token" `
  --recon --fuzz --optimize
```

---

## 📊 Comparación v1 vs v2

| Feature | v1 | v2 |
|---------|----|----|
| **Autenticación** | ❌ None | ✅ OAuth2 + JWT |
| **Passwords** | ❌ Plain text | ✅ Bcrypt |
| **Rate Limiting** | ❌ None | ✅ SlowAPI |
| **WAF** | ❌ None | ✅ Pattern detection |
| **Logging** | ⚠️ Basic | ✅ JSON structured |
| **Security Headers** | ❌ None | ✅ Full suite |
| **CORS** | ❌ Open | ✅ Restricted |
| **Realismo** | 51% | 82% |

---

## 🔧 Troubleshooting

### Problema: "ModuleNotFoundError"
**Solución:**
```bash
pip install -r requirements.txt
```

### Problema: "Address already in use"
**Solución:**
```powershell
# Matar proceso en puerto 8000
Get-Process -Id (Get-NetTCPConnection -LocalPort 8000).OwningProcess | Stop-Process
```

### Problema: "bcrypt error"
**Solución:** Ya está arreglado en `auth.py` (uso directo de bcrypt sin passlib)

---

## ⚠️ Advertencia de Seguridad

> **WARNING**: Esta aplicación es **intencionalmente vulnerable** para entrenamiento.
> 
> **NO HACER:**
> - ❌ Exponer a internet
> - ❌ Usar en producción
> - ❌ Almacenar datos reales
> 
> **SÍ HACER:**
> - ✅ Usar en redes aisladas
> - ✅ Solo para entrenamiento
> - ✅ Resetear regularmente

---

## 📝 Archivos del Proyecto

```
tests/target_app/
├── main_v2.py              # Aplicación principal v2
├── run_v2.py               # Script de ejecución
├── auth.py                 # OAuth2 + JWT
├── rate_limiter.py         # Rate limiting
├── waf.py                  # WAF simulation
├── logging_config.py       # Structured logging
├── security_headers.py     # Security headers
├── requirements.txt        # Dependencias Python
├── README.md              # Esta guía
└── main.py                 # Aplicación v1 (legacy)
```

---

**VAA Cyber-range v4.0.0** - Entrenamiento de seguridad empresarial sin Docker
