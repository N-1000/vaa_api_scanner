# 🔐 Estándar de Pentesting — IDOR (Insecure Direct Object Reference)

> **Versión:** 1.0  
> **Clasificación:** Uso interno — LokiTrace Tools  
> **Referencia:** OWASP TOP 10 – A01:2021 Broken Access Control  
> **Autor:** LokiTrace Security Team  
> **Última revisión:** 2026-05-18

---

## 📌 Índice

1. [¿Qué es IDOR?](#1-qué-es-idor)
2. [Impacto y severidad](#2-impacto-y-severidad)
3. [Prerrequisitos y alcance](#3-prerrequisitos-y-alcance)
4. [Fase 1 — Reconocimiento y mapeo](#4-fase-1--reconocimiento-y-mapeo)
5. [Fase 2 — Identificación de puntos de ataque](#5-fase-2--identificación-de-puntos-de-ataque)
6. [Fase 3 — Pruebas activas](#6-fase-3--pruebas-activas)
7. [Fase 4 — Escalación y variantes avanzadas](#7-fase-4--escalación-y-variantes-avanzadas)
8. [Fase 5 — Documentación del hallazgo](#8-fase-5--documentación-del-hallazgo)
9. [Checklist de ejecución](#9-checklist-de-ejecución)
10. [Referencias](#10-referencias)

---

## 1. ¿Qué es IDOR?

**IDOR** ocurre cuando una aplicación expone referencias directas a objetos internos (IDs de usuarios, registros, archivos, etc.) **sin validar que el solicitante tiene permiso** de acceder a ese objeto.

### Ejemplo básico

```
GET /api/facturas/1043   → devuelve la factura del usuario A
GET /api/facturas/1044   → devuelve la factura del usuario B (❌ sin autorización)
```

El problema no es que el ID sea predecible, sino que **la autorización no se verifica en el servidor**.

---

## 2. Impacto y severidad

| Tipo de IDOR              | Severidad potencial | Descripción                                         |
|---------------------------|---------------------|-----------------------------------------------------|
| Lectura de datos ajenos   | 🔴 Alto / Crítico   | Acceso a PII, datos financieros, historial médico   |
| Modificación de registros | 🔴 Crítico          | Cambiar datos de otro usuario                       |
| Eliminación de recursos   | 🔴 Crítico          | Borrar cuentas, archivos o registros de otros       |
| Escalación de privilegios | 🟣 Crítico          | Acceder a endpoints de admin como usuario regular   |
| Lectura de archivos       | 🔴 Alto             | Descargar documentos privados de otros usuarios     |

---

## 3. Prerrequisitos y alcance

### Herramientas requeridas
- [ ] **Burp Suite** (Proxy + Repeater + Intruder)
- [ ] **Postman** o **Insomnia** (validación manual de APIs)
- [ ] **curl** / **httpie** (pruebas en terminal)
- [ ] **ffuf** o **wfuzz** (fuzzing de IDs)
- [ ] Extensión Burp: **Autorize** (automatización de chequeos de autorización)
- [ ] **jq** (parseo de respuestas JSON)

### Credenciales necesarias
- [ ] Al menos **2 cuentas de usuario** con el mismo rol (Víctima A y Atacante B)
- [ ] Idealmente también **1 cuenta admin** para comparar respuestas

### Consideraciones legales
> ⚠️ Todas las pruebas deben realizarse únicamente en entornos **con autorización explícita por escrito**. El acceso a datos reales de terceros sin permiso es un delito.

---

## 4. Fase 1 — Reconocimiento y mapeo

**Objetivo:** Entender la estructura de la aplicación y recolectar todos los identificadores expuestos.

### 4.1 Autenticación y captura de tráfico

1. Abrir Burp Suite y configurar el proxy del navegador.
2. Iniciar sesión con la **cuenta A (víctima)**.
3. Navegar exhaustivamente por toda la aplicación:
   - Perfil de usuario
   - Documentos / facturas / pedidos
   - Mensajes / notificaciones
   - Panel de configuración
   - Funcionalidades CRUD (crear, editar, eliminar)
4. Revisar el **HTTP History** de Burp para identificar todos los endpoints.

### 4.2 Inventario de IDs expuestos

Buscar en URLs, headers, bodies y cookies los siguientes patrones:

| Tipo de ID          | Ejemplos                                                     |
|---------------------|--------------------------------------------------------------|
| Numérico secuencial | `?user_id=101`, `/orders/5523`                               |
| UUID / GUID         | `/profile/3f2504e0-4f89-11d3-9a0c-0305e82c3301`              |
| Hash MD5/SHA        | `/files/d41d8cd98f00b204e9800998ecf8427e`                    |
| Encoded Base64      | `/data/dXNlcl8xMDM=`                                         |
| Referencia por nombre | `/reports/reporte_mensual_enero.pdf`                       |

```bash
# Extraer todos los IDs numéricos de una captura de Burp exportada
grep -Eo '(/[a-z_-]+/[0-9]{3,})' burp_export.txt | sort -u
```

### 4.3 Mapeo de endpoints sensibles

Clasificar cada endpoint encontrado en categorías:

```
[READ]   GET  /api/users/{id}
[READ]   GET  /api/documents/{id}/download
[WRITE]  PUT  /api/users/{id}/email
[WRITE]  POST /api/orders/{id}/cancel
[DELETE] DELETE /api/comments/{id}
```

---

## 5. Fase 2 — Identificación de puntos de ataque

**Objetivo:** Priorizar los vectores con mayor probabilidad y mayor impacto.

### 5.1 Criterios de priorización

| Prioridad | Criterio                                                    |
|-----------|-------------------------------------------------------------|
| 🔴 Alta   | El endpoint devuelve PII (nombre, email, teléfono, docs)    |
| 🔴 Alta   | El endpoint permite modificar o eliminar recursos           |
| 🟠 Media  | El endpoint devuelve metadata de objetos de otros usuarios  |
| 🟡 Baja   | El endpoint devuelve recursos públicos pero con ID interno  |

### 5.2 Checklist de vectores comunes

- [ ] IDs en **path parameters**: `/api/users/1043`
- [ ] IDs en **query parameters**: `/search?account_id=22`
- [ ] IDs en **request body** (POST/PUT): `{"invoice_id": 5521}`
- [ ] IDs en **headers personalizados**: `X-User-ID: 101`
- [ ] IDs en **cookies**: `session_user=aXVzZXJfMTA0Mw==`
- [ ] Referencias en **respuestas JSON** a otros objetos: `"owner_id": 9988`
- [ ] Parámetros de **exportación**: `/export?report_id=88&format=pdf`

---

## 6. Fase 3 — Pruebas activas

**Objetivo:** Confirmar si existe un control de acceso deficiente manipulando los identificadores.

### 6.1 Prueba manual básica (2 cuentas)

**Paso a paso:**

1. Con **cuenta A**, realizar la acción legítima y capturar la request en Burp Repeater.
2. Obtener el ID de un recurso perteneciente a **cuenta B** (o simplemente incrementar/decrementar el ID).
3. Reemplazar el ID en la request de la cuenta A **sin cambiar el token de sesión**.
4. Enviar la request y analizar la respuesta.

**Interpretar la respuesta:**

| Respuesta del servidor              | Interpretación                         |
|-------------------------------------|----------------------------------------|
| `200 OK` + datos de B               | ✅ **IDOR confirmado** — Crítico        |
| `200 OK` + datos de A               | ✅ Servidor ignora el parámetro, seguro |
| `403 Forbidden` / `401 Unauthorized`| ✅ Control de acceso funcionando        |
| `404 Not Found`                     | ⚠️ Ambiguo — puede enmascarar el ID    |
| `200 OK` + respuesta vacía `{}`     | ⚠️ Posible IDOR oculto — investigar    |

### 6.2 Prueba cruzada de sesiones

```
Cuenta A Token: eyJhbGciOiJIUzI1NiJ9.AA...
Cuenta B Token: eyJhbGciOiJIUzI1NiJ9.BB...

Request original (A accede a su recurso):
  GET /api/profile/1001
  Authorization: Bearer <TOKEN_A>

Prueba IDOR (A intenta acceder al recurso de B):
  GET /api/profile/1002
  Authorization: Bearer <TOKEN_A>    ← token A, ID de B
```

### 6.3 Fuzzing de IDs con ffuf

```bash
# Fuzzing básico de IDs numéricos
ffuf -u "https://target.com/api/orders/FUZZ" \
     -H "Authorization: Bearer <TOKEN_A>" \
     -H "Content-Type: application/json" \
     -w /usr/share/wordlists/numbers_1_10000.txt \
     -fs 0 \
     -mc 200 \
     -o resultados_idor.json

# Generar wordlist de IDs numéricos
seq 1000 2000 > /tmp/ids.txt
```

### 6.4 Prueba con Burp Intruder

1. Enviar la request al **Intruder**.
2. Marcar el ID como posición: `GET /api/users/§1001§`.
3. Tipo de ataque: **Sniper**.
4. Payload: lista numérica de `1000` a `1100`.
5. Filtrar respuestas con longitud diferente a la respuesta de error.

### 6.5 Automatización con la extensión Autorize (Burp)

1. Instalar **Autorize** desde la BApp Store de Burp.
2. Ingresar el **token de cuenta B** en la configuración de Autorize.
3. Navegar como **cuenta A** normalmente.
4. Autorize inyectará automáticamente el token de B en cada request y marcará en verde los posibles IDOR.

### 6.6 Prueba en métodos HTTP alternativos

> Algunos endpoints protegen el método `GET` pero olvidan proteger `POST`, `PUT`, `PATCH`, `DELETE`.

```bash
# Probar todos los métodos HTTP
for METHOD in GET POST PUT PATCH DELETE HEAD OPTIONS; do
  echo "--- $METHOD ---"
  curl -s -X $METHOD \
    -H "Authorization: Bearer <TOKEN_A>" \
    "https://target.com/api/resource/1002" | jq .
done
```

---

## 7. Fase 4 — Escalación y variantes avanzadas

### 7.1 IDOR en endpoints de exportación/descarga

```bash
# Intentar descargar archivos de otros usuarios
GET /api/export?user_id=1001&format=pdf   → descargar como cuenta A
GET /api/export?user_id=1002&format=pdf   → ¿descarga datos de B?
```

### 7.2 IDOR mediante manipulación de IDs codificados

```bash
# Decodificar Base64
echo "dXNlcl8xMDM=" | base64 -d   # → user_103

# Incrementar y re-encodear
echo -n "user_104" | base64        # → dXNlcl8xMDQ=

# Enviar el nuevo valor codificado
GET /api/data/dXNlcl8xMDQ=
```

### 7.3 IDOR en parámetros anidados (Mass Assignment / JSON)

```json
// Request original de cuenta A
PUT /api/profile
{
  "name": "Carlos",
  "email": "carlos@email.com"
}

// Prueba de IDOR: agregar user_id al body
PUT /api/profile
{
  "user_id": 1002,
  "name": "Hackeado",
  "email": "atacante@email.com"
}
```

### 7.4 IDOR vertical (escalación de privilegios)

Probar acceder a endpoints de administración con cuentas de usuario normal:

```bash
GET /api/admin/users/1001           → ¿devuelve datos sin ser admin?
GET /api/admin/reports/all          → ¿acceso a reporte global?
DELETE /api/admin/users/1002        → ¿puede eliminar usuarios?
```

### 7.5 IDOR Blind (sin respuesta directa)

Cuando el servidor responde igual independientemente del ID (ej. siempre `200 OK {}`), verificar efectos secundarios:
- ¿Llegó un correo electrónico?
- ¿Cambió el estado de un recurso?
- ¿Aparece en logs del sistema?

---

## 8. Fase 5 — Documentación del hallazgo

**Todo hallazgo confirmado debe documentarse con el siguiente formato:**

---

### 📄 Plantilla de reporte de IDOR

```markdown
## Hallazgo: IDOR en [endpoint]

**ID del hallazgo:** IDOR-001
**Fecha:** YYYY-MM-DD
**Severidad:** Crítica / Alta / Media / Baja
**CVSS Score:** (calcular en https://www.first.org/cvss/calculator/3.1)

### Descripción
[Descripción clara del problema en 2-3 oraciones]

### Endpoint afectado
`GET /api/endpoint/{id}`

### Pasos para reproducir
1. Autenticarse como usuario A (cuenta: test_user_a@ejemplo.com)
2. Enviar la siguiente request:
   ```
   GET /api/endpoint/1002
   Host: target.com
   Authorization: Bearer <TOKEN_A>
   ```
3. Observar que la respuesta contiene datos del usuario con ID 1002.

### Evidencia
- **Request:** [adjuntar captura Burp]
- **Response:** [adjuntar respuesta completa]
- **Datos expuestos:** nombre, email, número de teléfono (PII)

### Impacto
[Describir qué puede hacer un atacante con este acceso]

### Remediación recomendada
- Implementar validación de autorización basada en el usuario autenticado (session-based ownership check).
- Comparar el `user_id` del token JWT con el ID del recurso solicitado.
- Usar UUIDs aleatorios en lugar de IDs secuenciales para reducir enumerabilidad.
- Implementar controles de acceso a nivel de objeto (ABAC/RBAC).

### Referencias
- OWASP IDOR: https://owasp.org/www-project-web-security-testing-guide/
- CWE-639: Authorization Bypass Through User-Controlled Key
```

---

## 9. Checklist de ejecución

Usar esta lista durante cada sesión de prueba. Marcar cada ítem completado.

### ✅ Reconocimiento
- [ ] Tráfico capturado con Burp Suite para ambas cuentas
- [ ] Todos los endpoints con IDs mapeados e inventariados
- [ ] IDs clasificados por tipo (numérico, UUID, hash, base64)
- [ ] Endpoints priorizados por impacto potencial

### ✅ Pruebas básicas
- [ ] Prueba manual: cuenta A accede a recurso de cuenta B
- [ ] Prueba cruzada de tokens (token A + ID de B)
- [ ] Prueba en query params, path params, body y headers
- [ ] Prueba de métodos HTTP alternativos (GET, POST, PUT, DELETE)

### ✅ Pruebas avanzadas
- [ ] Fuzzing de IDs numéricos con ffuf o Burp Intruder
- [ ] Verificación con extensión Autorize
- [ ] IDs en Base64/Hash decodificados y manipulados
- [ ] Prueba de IDOR en parámetros anidados en el body
- [ ] Prueba de escalación vertical (acceso a endpoints admin)
- [ ] Verificación de efectos secundarios (IDOR blind)

### ✅ Documentación
- [ ] Pasos para reproducir documentados
- [ ] Request y response capturados como evidencia
- [ ] Impacto y datos expuestos descritos
- [ ] Remediación recomendada incluida
- [ ] CVSS calculado

---

## 10. Referencias

| Recurso                              | URL                                                                                          |
|--------------------------------------|----------------------------------------------------------------------------------------------|
| OWASP WSTG – Access Control Testing  | https://owasp.org/www-project-web-security-testing-guide/latest/4-Web_Application_Security_Testing/05-Authorization_Testing/04-Testing_for_Insecure_Direct_Object_References |
| PortSwigger – IDOR                   | https://portswigger.net/web-security/access-control/idor                                    |
| CWE-639                              | https://cwe.mitre.org/data/definitions/639.html                                              |
| HackTricks – IDOR                    | https://book.hacktricks.xyz/pentesting-web/idor                                              |
| Autorize (Burp Extension)            | https://github.com/Quitten/Autorize                                                          |
| CVSS Calculator v3.1                 | https://www.first.org/cvss/calculator/3.1                                                    |

---

> 📁 **Siguiente estándar sugerido:** `ESTANDAR_BROKEN_AUTH.md` | `ESTANDAR_SQLI.md` | `ESTANDAR_XSS.md`

