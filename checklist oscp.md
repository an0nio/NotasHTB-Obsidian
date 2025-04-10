
### 🔐 Active Directory (AD)

#### 🧭 Enumeración con acceso al dominio (PowerView)
```powershell
# Dominio:
Get-Domain | select -ExpandProperty name

# Equipos + IPs para /etc/hosts:
Get-DomainComputer | select -ExpandProperty name > equipos.txt
foreach ($equipo in (Get-Content .\equipos.txt)) {$IP = Resolve-DnsName $equipo | select -ExpandProperty ipaddress; echo "$ip $equipo" } 

# Usuarios del dominio:
Get-DomainUser | select -ExpandProperty sAMAccountName

# Recursos compartidos:
foreach ($equipo in (Get-Content .\equipos.txt)) {net view \\$equipo}
```
#### 🦆 [[Miscelaneo#ASREPRoasting| ASReproasting]]
- Buscar cuentas sin preautenticación Kerberos.
- Obtener hashes y crackear (ej. con hashcat).
#### 🔥 [[Kerberoasting]]
- Solicitar TGS de cuentas con SPN.
- Crackear hash para obtener contraseñas.
#### 💀 Null Sessions SMB
```bash
smbclient -N -U "" -L \\$target
```
#### 🚪 Puertos internos ocultos
```bash
netstat.exe -ano
```
#### ⬆️ [[#🪟 Escalada de privilegios en Windows]]

#### 🧪 Mimikatz
```powershell
# SAM
.\mimikatz.exe privilege::debug lsadump::sam exit > dumpSAM.txt

# LSASS
.\mimikatz.exe privilege::debug sekurlsa::logonpasswords exit > dumpLSASS.txt

# Secrets
.\mimikatz.exe privilege::debug lsadump::lsa /patch exit > secrets_lsa.txt

# Ekeys
.\mimikatz.exe privilege::debug sekurlsa::ekeys exit > ekeys.txt

# Tickets
.\mimikatz.exe privilege::debug sekurlsa::tickets /export exit
```
#### 🗝️ Uso de credenciales
- PTH, PTT, Pass-the-key, credenciales en texto plano.
- Intentar acceso vía:
    - RDP
    - WinRM
    - impacket-wmiexec
    - impacket-psexec
    - con `--local-auth` si procede
    - Utilizar usuarios como contraseñas
#### 📈 BloodHound
- Recolectar con `SharpHound`.
- Analizar relaciones para escalada o movimiento lateral.

---

### 🌐 Pentesting Web - TODO
#### 🔍 Reconocimiento
- `whatweb`, Wappalyzer
- Buscar info en:
    - `/robots.txt`
    - `/sitemap.xml`
    - comentarios HTML, JavaScript expuesto

#### 🗝️ Credenciales por defecto
- Revisar en: [https://github.com/ihebski/DefaultCreds-cheat-sheet](https://github.com/ihebski/DefaultCreds-cheat-sheet)

#### 📂 Fuzzing
- Directorios con `ffuf`, `gobuster`, `feroxbuster`
- VHOSTS vía cabeceras `Host:` o DNS bruteforce

#### 💉 Inyecciones
- Inyectar en campos GET/POST: `SQLi`, `XSS`, `CMDi`
- Cambiar parámetros manualmente
#### 📂 Path Traversal
- Revisar: [https://github.com/swisskyrepo/PayloadsAllTheThings](https://github.com/swisskyrepo/PayloadsAllTheThings)
- Usar listas como: `deep_traversal.txt`

#### 📜 LFI/RFI
- Probar rutas como:
    - `/etc/passwd`
    - archivos de logs
    - php wrappers (`php://filter`)

---

### 🐧 Escalada de privilegios en Linux
#### 🔍 Comprobaciones manuales
```bash
# Archivos sensibles:
ls -l /etc/passwd /etc/shadow /etc/sudoers

# Sudo sin contraseña:
sudo -l

# Binarios SUID/GUID:
find / -perm -4000 -type f 2>/dev/null   # SUID
find / -perm -2000 -type f 2>/dev/null   # GUID

# Capabilities:
getcap -r / 2>/dev/null

# Grupos:
groups

# Versión de sudo:
sudo -V | head -n 1

# Variables de entorno:
env
```
#### 🛠️ Automatización
- `linpeas.sh`
- `pspy64` o `pspy32` para detectar cronjobs y scripts ejecutados

#### 📁 Búsqueda de archivos sospechosos

```bash
# Backups, archivos ocultos y nombres sospechosos:
find / -type f \( -iname "*.old" -o -iname "*.bak" -o -iname "*.backup" -o -iname "*copy*" -o -iname "*backup*" -o -iname "*config*" -o -iname "*save*" -o -iname "*temp*" -o -iname "*dump*" -o -iname "*test*" -o -iname "*.zip" -o -iname "*.tar" -o -iname "*.gz" -o -iname ".*.swp" -o -iname ".*.git" \) 2>/dev/null

# Buscar carpetas con nombres sospechosos:
find / -type d \( -iname "*backup*" -o -iname "*old*" -o -iname "*copy*" -o -iname "*temp*" -o -iname "*save*" \) 2>/dev/null

# Archivos con credenciales:
grep -ri "password\|passwd\|secret\|token\|key" /home/* 2>/dev/null

# Buscar permisos de escritura globales:
find / -writable -type f 2>/dev/null
```
#### 📂 Carpetas útiles para chequear manualmente en **Linux** (escalada de privilegios)
```bash
# Búsqueda de archivos no vacíos dentro de carpetas útiles
find /opt /srv /var/backups /var/www/html /mnt /media /home -type f -size +0c 2>/dev/null
# Búsqueda de archivos sospechosos dentro de carpetas útiles
find /opt /srv /var/backups /var/www/html /mnt /media /home -type f \( -iname "*.zip" -o -iname "*.bak" -o -iname "*backup*" -o -iname "*.old" -o -iname "*.log" \) 2>/dev/null
# Búsqueda de más archivos
find /opt /srv /var/backups /var/www/html /mnt /media /home -type f \( \
    -iname "*.old" -o -iname "*.bak" -o -iname "*.backup" -o -iname "*copy*" \
    -o -iname "*backup*" -o -iname "*config*" -o -iname "*save*" -o -iname "*temp*" \
    -o -iname "*dump*" -o -iname "*test*" -o -iname "*.zip" -o -iname "*.tar" \
    -o -iname "*.gz" -o -iname "*.log" -o -iname "*.kdbx" -o -iname "*keepass*" \
    \) ! -empty 2>/dev/null
# Contenido sensible en estos archivos
grep -rEi "password|secret|token|key|creds" /opt /srv /var/backups /var/www/html /mnt /media /home 2>/dev/null
```

| Carpeta                | Qué buscar                                                                                        |
| ---------------------- | ------------------------------------------------------------------------------------------------- |
| `/home/*`              | Archivos `.bash_history`, `.ssh`, credenciales, scripts personalizados                            |
| `/root` (si accesible) | Archivos de configuración root, credenciales, scripts de mantenimiento                            |
| `/opt/`                | Software de terceros instalado manualmente. Muchas veces con scripts o binarios mal configurados. |
| `/srv/`                | Servidores (web, FTP, etc.) pueden tener backups, datos sensibles.                                |
| `/var/backups/`        | Backups automáticos del sistema. A veces incluye `/etc/shadow` o `.gz`                            |
| `/var/www/html`        | Archivos web. PHPs mal escritos, backups (`.old`, `.zip`, `.bak`, etc.)                           |
| `/etc/cron.*`          | Cronjobs con scripts modificables, tareas automáticas                                             |
| `/tmp/` y `/dev/shm/`  | Archivos temporales, sockets, volcados en texto plano                                             |
| `/run/`, `/var/run/`   | Sockets, procesos activos, demonios mal configurados                                              |
| `/mnt/` y `/media/`    | Discos montados, a veces puntos de respaldo o unidades USB con secretos                           |
| `/usr/local/bin/`      | Binarios personalizados (propensos a errores de permisos)                                         |
| `/etc/`                | Archivos de configuración, contraseñas duras, secretos en texto plano                             |
| `/xampp/` o `/lampp/`  | Entornos LAMP con configuraciones inseguras y paneles accesibles sin contraseña                   |


### 🪟 Escalada de privilegios en Windows

#### 🔑 Privilegios explotables
- **SeImpersonatePrivilege**: permite ejecutar ataques como Juicy Potato, PrintSpoofer.
- **SeDebugPrivilege**: acceso a procesos ajenos, como LSASS.
- **SeTakeOwnershipPrivilege**: puedes adueñarte de objetos protegidos.
- **SeRestorePrivilege / SeBackupPrivilege**: lectura de archivos normalmente inaccesibles.
- **SeChangeNotifyPrivilege**: muy común, pero a veces útil para DLL hijacking.

#### 👥 Grupos integrados de Windows
- **Administrators**: acceso total.
- **Backup Operators**: lectura y backup de archivos, incluso protegidos.
- **Event Log Readers**: acceso a logs con info sensible.
- **DNS Admins**: potencial RCE en servidores DNS.
- **Print/Server Operators**: tareas administrativas con potencial de abuso.

#### ⚙️ Permisos débiles

Detectables con herramientas como PowerUp, WinPEAS o manualmente:
- Servicios modificables (`Modifiable Services`, `Modifiable Binaries`).
- `Unquoted Service Paths`: rutas de ejecutables sin comillas.
- Permisos en claves de ejecución automática (`Startup`, `Run`).

#### 🐚 Herramientas útiles
- `WinPEAS`: escaneo extenso del sistema Windows.
- `Seatbelt`: recolección de info sensible/local.
- `PowerUp`: detección de vectores típicos de privesc.
- `Snaffler`: búsqueda de archivos jugosos en red o disco.

#### 🐞 Kernel exploits (TODO)
- Identifica versión del sistema (`systeminfo`) y compara con exploits conocidos (e.g., MS16-032).
- Usa `windows-exploit-suggester` para sugerencias automáticas.

#### 🔥 Servicios vulnerables y tareas programadas
- Servicios con ejecución como SYSTEM desde rutas editables.
- Tareas con binarios modificables o sin permisos controlados (`schtasks /query /fo LIST /v`).
#### 🪟 Archivos sospechosos

```powershell
# Buscar archivos con nombres sugerentes:
Get-ChildItem -Path C:\ -Recurse -Include *.bak,*.old,*.zip,*.rar,*.7z,*.tar,*.gz,*backup*,*copy*,*temp*,*save*,*config*,*test* -ErrorAction SilentlyContinue -Force

# Buscar carpetas con nombres sospechosos:
Get-ChildItem -Path C:\ -Recurse -Directory -Include *backup*,*old*,*copy*,*temp*,*save* -ErrorAction SilentlyContinue -Force

# Buscar posibles contraseñas en archivos de texto:
Select-String -Path C:\Users\*\Documents\*,C:\Users\*\Desktop\* -Pattern "password|passwd|secret|credentials|key" -CaseSensitive -ErrorAction SilentlyContinue

# Buscar archivos de configuración expuestos:
Get-ChildItem -Path C:\ -Recurse -Include *.config,*.ini,*.xml -ErrorAction SilentlyContinue -Force

```
#### 📂 Carpetas útiles para chequear manualmente en **Windows** (escalada de privilegios)

```powershell
# Búsqueda de archivos no vacíos dentro de carpetas útiles
Get-ChildItem -Path "C:\Users\*", "C:\Scripts", "C:\Backups", "C:\Temp", "C:\ProgramData", "C:\inetpub\wwwroot" -Recurse -File -ErrorAction SilentlyContinue | Where-Object { $_.Length -gt 0 }
# Búsqueda de archivos sospechosos dentro de carpetas útiles
Get-ChildItem -Path "C:\Users\*", "C:\Scripts", "C:\Backups", "C:\Temp", "C:\ProgramData", "C:\inetpub\wwwroot" -Recurse -File -ErrorAction SilentlyContinue | Where-Object {
    $_.Name -match '\.bak$|\.old$|\.zip$|\.log$|\.kdbx$|keepass|backup|copy|cred|password'
}
# Búsqueda de información sensible dentro de estos archivos
(Get-ChildItem -Path "C:\Users\*", "C:\Scripts", "C:\Backups", "C:\Temp", "C:\ProgramData", "C:\inetpub\wwwroot" -Recurse -File -ErrorAction SilentlyContinue | Where-Object { $_.Length -gt 0 }) | Select-String -Pattern "password|secret|token|key|creds" -SimpleMatch | Select-Object Path, LineNumber, Line
```

|Carpeta|Qué buscar|
|---|---|
|`C:\Users\*\Desktop`|Notas, scripts de admins, contraseñas en texto plano|
|`C:\Users\*\Documents`|PDFs, DOCX, credenciales, backups|
|`C:\Users\*\Downloads`|Instaladores, herramientas usadas por el usuario|
|`C:\Users\*\AppData\Local\Temp`|Temporales con volcados o archivos sensibles|
|`C:\Program Files` / `Program Files (x86)`|Software mal configurado, rutas modificables, binarios inseguros|
|`C:\ProgramData`|Configuraciones globales, archivos compartidos|
|`C:\Temp`|Archivos temporales personalizados, muy común en entornos dev|
|`C:\inetpub\wwwroot`|Código fuente de aplicaciones web, bases de datos, credenciales hardcoded|
|`C:\Windows\Tasks` / `System32\Tasks`|Tareas programadas, ejecución automática como SYSTEM|
|`C:\Backups`, `C:\Scripts`|Carpeta común para volcados de seguridad y automatizaciones|
|`C:\Recycle.Bin` o Papelera|Archivos borrados que pueden contener datos útiles|
|Carpetas compartidas (`\\`)|Información accesible vía SMB; usar `net view`, `net use`, `SharpHound`|