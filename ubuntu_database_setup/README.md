# VAA Brain — Ubuntu Headless Setup Guide

Guía de instalación **100% terminal** para levantar el servidor de memoria cognitiva
del escáner VAA en un Ubuntu Server limpio.

---

## Paso 1 — Instalar Docker en Ubuntu

```bash
# Actualizar paquetes
sudo apt update && sudo apt upgrade -y

# Instalar dependencias de Docker
sudo apt install -y ca-certificates curl gnupg lsb-release

# Agregar repositorio oficial de Docker
sudo install -m 0755 -d /etc/apt/keyrings
curl -fsSL https://download.docker.com/linux/ubuntu/gpg | \
  sudo gpg --dearmor -o /etc/apt/keyrings/docker.gpg
sudo chmod a+r /etc/apt/keyrings/docker.gpg

echo \
  "deb [arch=$(dpkg --print-architecture) signed-by=/etc/apt/keyrings/docker.gpg] \
  https://download.docker.com/linux/ubuntu \
  $(. /etc/os-release && echo "$VERSION_CODENAME") stable" | \
  sudo tee /etc/apt/sources.list.d/docker.list > /dev/null

sudo apt update
sudo apt install -y docker-ce docker-ce-cli containerd.io docker-compose-plugin

# Verificar que Docker instaló correctamente
docker --version

# Permitir usar Docker sin sudo (opcional pero recomendado)
sudo usermod -aG docker $USER
newgrp docker
```

---

## Paso 2 — Transferir los archivos a Ubuntu

**Desde tu PC Windows** (en PowerShell), copia esta carpeta al Ubuntu usando `scp`:
```powershell
# Reemplaza <ubuntu-ip> con la IP real de tu servidor Ubuntu
scp -r .\ubuntu_database_setup\ <tu-usuario>@<ubuntu-ip>:~/vaa_brain/
```

O si prefieres, conecta por SSH y crea los archivos directamente.

---

## Paso 3 — Levantar el contenedor de PostgreSQL

```bash
# Entrar a la carpeta copiada
cd ~/vaa_brain

# Levantar PostgreSQL en background (primera vez descargará la imagen ~50MB)
docker compose up -d

# Verificar que está corriendo
docker compose ps

# Ver logs en tiempo real (Ctrl+C para salir)
docker compose logs -f vaa_brain
```

Deberías ver algo como:
```
vaa_brain  | LOG:  database system is ready to accept connections
```

---

## Paso 4 — Verificar la base de datos

```bash
# Conectarte directamente a la BD para confirmar que las tablas se crearon
docker exec -it vaa_brain psql -U vaa -d lokitrace_memory

# Dentro de psql, ejecutar:
\dt
# Deberías ver: grammar_entries, exploit_memory, endpoint_intel, scan_history
\q
```

---

## Paso 5 — Encontrar la IP del Ubuntu (para configurar el escáner)

```bash
ip addr show | grep "inet " | grep -v "127.0.0.1"
# Ejemplo de output: inet 192.168.1.105/24
# Tu IP de red local sería: 192.168.1.105
```

Con esta IP configuraremos el escáner en Windows para que apunte aquí.

---

## Paso 6 — Abrir el firewall en Ubuntu (si aplica)

```bash
# Permitir conexiones al puerto 5432 desde la red local
sudo ufw allow from 192.168.1.0/24 to any port 5432
sudo ufw status
```
> Reemplaza `192.168.1.0/24` con tu subred real.

---

## Comandos Útiles de Mantenimiento

```bash
# Detener la BD (guarda datos en volumen Docker)
docker compose stop

# Reiniciar la BD
docker compose start

# Ver tamaño de la base de datos
docker exec vaa_brain psql -U vaa -d lokitrace_memory \
  -c "SELECT pg_size_pretty(pg_database_size('lokitrace_memory'));"

# Backup manual de la BD
docker exec vaa_brain pg_dump -U vaa lokitrace_memory > backup_$(date +%Y%m%d).sql
```

---

## Cadena de Conexión para el Escáner

Una vez que tengas la IP del Ubuntu, la cadena de conexión que usará el escáner es:

```
postgresql://vaa:vaa_secret_change_me@<ubuntu-ip>:5432/lokitrace_memory
```

> **Seguridad:** Cambia `vaa_secret_change_me` por una contraseña segura en el
> `docker-compose.yml` antes de levantar el contenedor en producción.
