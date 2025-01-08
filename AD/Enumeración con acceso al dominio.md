## Sobre MS-RPC y LDAP
 **LDAP y MS-RPC** en conjunto nos una **visión completa del entorno objetivo**. LDAP proporciona una visión **centralizada y amplia** del dominio, mientras que MS-RPC ofrece **detalles más granulares** sobre recursos compartidos, cuentas locales y configuraciones del sistema.  
Combinar ambos enfoques permite descubrir configuraciones inseguras y obtener información crítica.

|**Escenario**|**LDAP**|**MS-RPC**|
|---|---|---|
|**Enumeración de usuarios y grupos**|Listar todos los usuarios y grupos del dominio.|Enumerar usuarios locales o de dominio (SAMR).|
|**Consultas de políticas de seguridad**|Buscar políticas de contraseñas y GPOs.|Revisar permisos de usuarios y privilegios locales.|
|**Recursos compartidos**|No disponible directamente.|Enumerar recursos compartidos (`netshareenum`).|
|**Computadoras del dominio**|Listar equipos registrados en el dominio.|Limitado a equipos locales.|
|**SIDs y RIDs**|Obtenibles a través de LDAP.|Consultar RIDs y mapear SIDs (`lookupsids`).|
|**Administración de cuentas**|Ampliar información de cuentas AD.|Crear, modificar o eliminar cuentas locales.|
## Linux
### `nxc smb` 
- Enumeración de usuarios
	```shell
	sudo nxc smb $target -u forend -p Klmcargo2 --users
	```
- Enumeración de grupos
	```bash
	sudo nxc smb $target -u forend -p Klmcargo2 --groups
	```
- Mostrar usuarios logueados
	```bash
	sudo nxc smb $target -u forend -p Klmcargo2 --loggedon-users
	```
- Mostrar recursos compartidos
	```bash
	sudo nxc smb $target -u forend -p Klmcargo2 --shares
	```
- Mostrar todos los archivos que se pueden leer en un directorio comartido - `spider_plus`
	```bash
	sudo nxc smb $target -u forend -p Klmcargo2 -M spider_plus --share 'Department Shares'
	```
	Guarda la información con los directorios disponibles en `/tmp/cme_spider_plus/<ip>.json`
### `smbmap`
- Comprobar si tenemos acceso
	```bash
	smbmap -u forend -p Klmcargo2 -d INLANEFREIGHT.LOCAL -H $target
	```
- Mostrar todos los directorios disponibles
	```bash
	 smbmap -u forend -p Klmcargo2 -d INLANEFREIGHT.LOCAL -H $target -R 'Department Shares' --dir-only
	```
### `rpcclient` - MS-RPC
Es más útil para enumearr usuarios, grupos y permisos de dominio. Interactúa con el protocolo SMB, pero puede proveer funcionalidades extras vía `MS-RPC`. 
- Conexión 
```bash
# Null session
rpcclient -U "" -N $target
# Con credenciales
rpcclient -U "DOMINIO\usuario%password" -N $target
```
Algunos comandos interesantes
- **`enumdomusers`**: Enumera usuarios.
- **`enumalsgroups domain`**: Enumera los grupos del dominio.
- **`enumalsgroups builtin`**: Enumera los grupos locales del sistema.
- **`enumdomains`**: Enumera la información del dominio.
- **`enumprivs`**: Enumera los privilegios del sistema del usuario.
- **`lookupnames` nombre_de_usuario**: Identifica el SID (Security Identifier) para el nombre de usuario.
- **`queryuser RID#`**: Identifica la información del usuario para el número RID (Relative ID) proporcionado.
### `windapsearch` - LDAP
- Información de la herramienta
	```bash
	python3 windapsearch.py -h
	```
- Enumerar todos los usuarios del dominio
```bash
windapsearch -d dominio.local -u usuario -p contraseña --users
```
- Enumerar todos los grupos del dominio
	```bash
	windapsearch -d dominio.local -u usuario -p contraseña --groups
	```
- Enumerar todas las computadoras del dominio
	```bash
	windapsearch -d dominio.local -u usuario -p contraseña --computers
	```
- Mostrar administradores de dominio
	```bash
	python3 windapsearch.py --dc-ip $target -u forend@inlanefreight.local -p Klmcargo2 --da
	```
- Mostrar usuarios privilegiados
	```bash
	python3 windapsearch.py --dc-ip $target -u forend@inlanefreight.local -p Klmcargo2 -PU
	```
- Recolectar toda la información del dominio
	```bash
	python3 windapsearch.py --dc-ip $target -u forend@inlanefreight.local -p Klmcargo2 -full
	```

### `bloodhound-python` - LDAP
- Si nuestra máquina no está unida al DC, debemos interrogar al DC para que el programa interrogue al DNS para resolver nombres de dominos
	```bash
	cat /etc/resolv.conf 

	# facilita la resolución de nombres internos sin tener que escribir el dominio completo todo el tiempo.
	domain INLANEFREIGHT.LOCAL 
	# domain solo permite un nombre de dominio. existe la opción de poner search si quisieramos añadir mas de un dominio
	# search INLANEFREIGHT.LOCAL FREIGHTLOGISTICS.LOCAL
	nameserver 172.16.5.5
	```
- Ejecutar bloodhound
	```bash
	# Conociendo la ip del servidor DNS (suel ser la misma que el DC)
	sudo bloodhound-python -u 'forend' -p 'Klmcargo2' -ns $target -d inlanefreight.local -c all --zip
	# Conociendo el nombre del dc - Recomendado si tenemos esta información
	bloodhound-python -d INLANEFREIGHT.LOCAL -dc ACADEMY-EA-DC01 -c All -u forend -p Klmcargo2 --zip 
	```
	Guarda un archivo con el formato `bloodhound-output_<fecha>-<hora>.zip`. Si queremos especificar el output, debemos añadir la flag `-op nombre_output`

### Impacket - obtención de shell
Para poder ejecutar los siguientes comandos hacen falta permisos de adminstrador. 
- `psexec.py` - Proporcionará una shell con permisos de `SYSTEM`
	```bash
	impacket-psexec inlanefreight.local/wley:'transporter@4'@$target
	```
- `wmiexec.py` - Lanza un nuevo `cmd.exe` desde `wmi` por cada comando ejecutado (más sigiloso que psexec)
	```bash
	impacket-wmiexec inlanefreight.local/wley:'transporter@4'@$target
	```

## Windows
### Módulo `ActiveDirectory`
- Cargar el módulo y comprobar que está cargado
```powershell
	Import-Module ActiveDirectory 
	# podemos comprobar que está cargado ejecutando lo siguiente: 
	Get-Module
```
- Obtener información del dominio - `Get-ADDomain`
	```powershell
	Get-ADDomain
	```
- Obtener usuarios con SPN configurado (kerberoasting) - `Get-ADUser`
	```powershell
	Get-ADUser -Filter {ServicePrincipalName -ne "$null"} -Properties ServicePrincipalName
	```
- Mostrar relaciones de confianza - `Get-ADTrust`
	```powershell
	Get-ADTrust -Filter *
	```
- Enumeración de grupos - `Get-ADgroup`
	```powershell
	Get-ADGroup -Filter * | select name
	# O información detallada de algunos grupos
	Get-ADGroup -Identity "Backup Operators"
	```
- Membresía de grupos (cuentas que pertenecen a un grupo concreto) - `Get-ADGroupMember`
	```powershell
	Get-ADGroupMember -Identity "Backup Operators"
	```
### Módulo `PowerView`
Hay más información sobre algunos comandos de PowerView [[PowerView| aquí]]. Se muestran algunos comandos interesantes
- Enumeración de usuarios - `Get-DomainUser`
	```powershell
	Get-DomainUser -Identity mmorgan -Domain inlanefreight.local | Select-Object -Property name,samaccountname,description,memberof,whencreated,pwdlastset,lastlogontimestamp,accountexpires,admincount,userprincipalname,serviceprincipalname,useraccountcontrol
```
- Membresía recursiva de grupos - `Get-DomainGroupMember`
	```powershell
	Get-DomainGroupMember -Identity "Domain Admins" -Recurse
	```
- Comprobar si un usuario es administrador local 
	```powershell
	Test-AdminAccess -ComputerName ACADEMY-EA-MS01
	```
- Buscar usuarios con SPN
	```powershell
	Get-DomainUser -SPN -Properties samaccountname,ServicePrincipalName
	```
### Sharpview
Es la versión .NET d `powerView`. Puede ser útil cuando hay medidas de hardening sobre un entorno powershell
### Snaffler
Es una herramienta que nos puede ayudar a recolectar información sensible dentro del AD como credenciales, archivos de configuración, claves SSH, … Ejemplo de ejecución:
```powershell
Snaffler.exe -s -d inlanefreight.local -o snaffler.log -v data
```
### Sharphound
Similar a `bloodhound-python`, aunque permite obtener información de sesiones, ACLs, grupos locales y rutas de confianza, ya además de actúar sobre el protocolo LDAP, también actúa sobre kerberos, WinRM y SMB
```powershell
.\SharpHound.exe -c All --zipfilename ILFREIGHT
.\SharpHound.exe -c all, Group --zipfilename capturaNombreGrupo
```