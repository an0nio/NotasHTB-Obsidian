import#powerview
[chuleta interesante](https://elhacker.info/Cursos/Applied-Purple-Teaming/9-Others/Cheatsheets/PowerView.pdf)

## Uso 
```powershell
Import-Module .\PowerView.ps1
```
## **Comandos y Descripción (PowerView y AD Enumeration)**

| **Comando**           | **Descripción**                                                                |
| --------------------- | ------------------------------------------------------------------------------ |
| `Export-PowerViewCSV` | Agrega los resultados a un archivo CSV.                                        |
| `ConvertTo-SID`       | Convierte un nombre de usuario o grupo a su valor SID.                         |
| `Get-DomainSPNTicket` | Solicita el ticket Kerberos para una cuenta con un nombre de SPN especificado. |
## **Funciones de Dominio/LDAP:**

| **Comando**                 | **Descripción**                                                                                     |
| --------------------------- | --------------------------------------------------------------------------------------------------- |
| `Get-Domain`                | Devuelve el objeto del dominio actual (o especificado).                                             |
| `Get-DomainController`      | Devuelve una lista de Controladores de Dominio (DC) para el dominio especificado.                   |
| `Get-DomainUser`            | Devuelve todos los usuarios o un usuario específico en Active Directory (AD).                       |
| `Get-DomainComputer`        | Devuelve todas las computadoras o una computadora específica en AD.                                 |
| `Get-DomainGroup`           | Devuelve todos los grupos o un grupo específico en AD.                                              |
| `Get-DomainOU`              | Busca todas las Unidades Organizativas (OUs) o una específica en AD.                                |
| `Find-InterestingDomainAcl` | Encuentra ACLs en el dominio con derechos de modificación asignados a objetos que no son internos.  |
| `Get-DomainGroupMember`     | Devuelve los miembros de un grupo de dominio específico.                                            |
| `Get-DomainFileServer`      | Devuelve una lista de servidores que probablemente funcionen como servidores de archivos.           |
| `Get-DomainDFSShare`        | Devuelve una lista de<br>sistemas de archivos distribuidos (DFS) del dominio actual o especificado. |
## **Funciones de Políticas de Grupo (GPO):**

| **Comando**        | **Descripción**                                                               |
| ------------------ | ----------------------------------------------------------------------------- |
| `Get-DomainGPO`    | Devuelve todas las GPOs o una GPO específica en AD.                           |
| `Get-DomainPolicy` | Devuelve la política predeterminada del dominio o del controlador de dominio. |

## **Funciones de Enumeración de Computadoras:**

| **Comando**               | **Descripción**                                                                         |
| ------------------------- | --------------------------------------------------------------------------------------- |
| `Get-NetLocalGroup`       | Enumera los grupos locales en la máquina local o remota.                                |
| `Get-NetLocalGroupMember` | Enumera los miembros de un grupo local específico.                                      |
| `Get-NetShare`            | Devuelve los recursos compartidos abiertos en la máquina local o remota.                |
| `Get-NetSession`          | Devuelve información de sesiones activas en la máquina local o remota.                  |
| `Test-AdminAccess`        | Verifica si el usuario actual tiene acceso administrativo a una máquina local o remota. |
## **Funciones de Meta (Multihilo):**

| **Comando**                       | **Descripción**                                                                                       |
| --------------------------------- | ----------------------------------------------------------------------------------------------------- |
| `Find-DomainUserLocation`         | Encuentra máquinas donde están conectados usuarios específicos.                                       |
| `Find-DomainShare`                | Encuentra recursos compartidos accesibles en máquinas del dominio.                                    |
| `Find-InterestingDomainShareFile` | Busca archivos que cumplan criterios específicos en recursos compartidos accesibles.                  |
| `Find-LocalAdminAccess`           | Encuentra máquinas en el dominio local donde el usuario actual tiene acceso como administrador local. |

## **Funciones de Confianza de Dominio:**

| **Comando**                    | **Descripción**                                                              |
| ------------------------------ | ---------------------------------------------------------------------------- |
| `Get-DomainTrust`              | Devuelve las relaciones de confianza del dominio actual o especificado.      |
| `Get-ForestTrust`              | Devuelve todas las relaciones de confianza entre bosques (forests).          |
| `Get-DomainForeignUser`        | Enumera usuarios que pertenecen a grupos fuera de su dominio.                |
| `Get-DomainForeignGroupMember` | Enumera grupos que contienen miembros de otros dominios.                     |
| `Get-DomainTrustMapping`       | Enumera todas las relaciones de confianza del dominio actual y otros vistos. |

## Filtros interesantes de PS
Se podría utilizar `?` en lugar de `Where-Object` y `select` en lugar de `Select-Object`

| **Comando**                                                                    | **Descripción**                                                          |
| ------------------------------------------------------------------------------ | ------------------------------------------------------------------------ |
| `Get-NetUser`                                                                  | Lista todos los usuarios del dominio.                                    |
| `Get-NetUser \| Select-Object cn, samaccountname`                              | Muestra solo el nombre y el usuario.                                     |
| `Get-NetUser stephanie \| select memberof`                                     | Muestra los grupos a los que pertenece un usuario                        |
| `Get-NetUser \| Where-Object { $_.cn -like "*admin*" }`                        | Filtra usuarios cuyo `CN` contiene "admin".                              |
| `Get-NetUser \| Where-Object { $_.Enabled -eq $false }`                        | Muestra usuarios **deshabilitados**.                                     |
| `Get-NetUser \| Sort-Object whencreated -Descending`                           | Ordena usuarios por **fecha de creación**, del más nuevo al más antiguo. |
| `Get-NetUser \| Format-Table -AutoSize`                                        | Muestra resultados en formato tabla.                                     |
| `Get-NetUser \| Where-Object { $_.lastlogon -gt (Get-Date).AddDays(-30) }`     | Muestra usuarios que han iniciado sesión en los **últimos 30 días**.     |
| `Get-NetUser \| Where-Object { $_.whencreated -gt (Get-Date).AddDays(-7) }`    | Filtra usuarios **creados en la última semana**.                         |
| `Get-NetUser \| Where-Object { $_.memberof -match "Administrators" }`          | Muestra usuarios que pertenecen al grupo **Administrators**.             |
| `Get-NetUser \| Where-Object { $_.logoncount -gt 0 }`                          | Filtra usuarios que **han iniciado sesión al menos una vez**.            |
| `Get-NetComputer \| select dnshostname,operatingsystem,operatingsystemversion` | Muestra equipos y su versión de sistema operativo                        |
| `Get-NetSession -ComputerName files04`                                         | Muestra usuarios logueados en un equipo                                  |
## Algún  otro comando interesante
- Comprobar si un usuario es administrador local en alguno de los equipos del dominio:
	```powershell
	# Guardamos todos los equipos en un fichero
	Get-DomainComputer | select -ExpandProperty name > equipos.txt
	# Comprobamos iterando en cada uno de los equipos: 
	foreach($equipo in (Get-Content .\equipos.txt)) {Test-AdminAccess $equipo}
	```
- Mostrar todos los usuarios administradores locales de los equipos: 
	```powershell
	# Guardamos todos los equipos en un fichero
	Get-DomainComputer | select -ExpandProperty name > equipos.txt
	# Iteramos sobre los equipos
	foreach($equipo in (Get-Content .\equipos.txt)) {Get-NetLocalGroupMember -computername $equipo -GroupName "Administrators"
	}
	```
- Mostrar equipos y direcciones IP de cada uno de ellos para guardar en /etc/hosts
	```powershell
	foreach ($equipo in (Get-Content .\equipos.txt)) {$IP = Resolve-DnsName dc01 | select -ExpandProperty ipaddress; echo "$ip $equipo" }
	```