#john #jtr #hashcat #crawling #bruteforce 
## Contraseñas por defecto
Revisar el [siguiente enlace](https://github.com/ihebski/DefaultCreds-cheat-sheet)
Algunas herramientas como `hydra` tienen la opción (`-C` en el caso de `hydra`) para pasar credenciales como parámetro. Ejemplo: 
```bash
hydra -C <user_pass.list> <protocol>://$target
```
---
## Crawling
Una herramienta muy útil puede ser [CeWL](https://github.com/digininja/CeWL), que genera una lista de palabras a partir de una dirección web:
```bash
cewl https://www.inlanefreight.com -d 4 -m 6 -w inlane.wordlist
# podríamos añadir la flag --lowercase, por ejemplo si lo queremos en minúsculas
```
En este ejemplo `-d` indica la profundidad (depth) y `-m` indica el mínimo número de carácteres. Es útil combinar esto con algunas mutaciones 
## John the Ripper
### Ataque de diccionario
```bash
john --wordlist=<wordlist_file> <hash_file>
```
### Formato del hash
John intentará adivinar el hash, aunque si conocemos el hash es mejor añadir la flag 
``` bash
--format=<hash_type>
```
Podemos listar los hash disponibles con 
```bash
john --list=formats
```
### Craquear archivos
Convertir archivos protegidos por contraseña a archivos craqueables con john. Buscamos: 
```bash
locate *2john*
```
Ejemplo con archivo `Notes.zip` protegido:
```bash
zip2john Notes.zip > notes.hash
john --wordlist=/usr/share/wordlists/rockyou.txt ntoes.hash
```
### `rules`: Mutaciones en el diccionario
Podemos añadir la flag `--rules`, para generar nuevas palabras a partir del diccionario dado. 
#### `john.conf` - Mutaciones disponibles
Las reglas de las mutaciones las encontraremos en este archivo, que en kali está en `/usr/share/john/john.conf`.  En la línea `[List.Rules:Wordlist]` se aplica la regla por defecto. Podemos enumerar todas las reglas que existen en este archivo con el siguiente filtro (se muestran dos ideas distintas):
```bash

 cat /usr/share/john/john.conf | grep "\[List.Rules:" | sed 's/.*\[List.Rules:\(.*\)\].*/\1/' | sort -u
 cat /usr/share/john/john.conf | grep -oP '(?<=\[List.Rules:)[^\]]+' | sort -u
```
- Podemos añadir una regla creada para `hashcat` añadiendo en la primera línea del archivo rules `[List.Rules:<nombreRegla>]`. Ejemplo suponiendo que `custom.rule` es una regla de `hashcat`: 
```bash
# Añadimos la primera línea a una regla personalizada de hashcat
echo "[List.Rules:reglaSSH]" | cat - custom.rule > john.rule
# Añadimos esta regla a las reglas personalizadas de john
sudo sh -c 'cat john.rule >> /etc/john/john.conf'
# Podemos utilizar la regla en john del siguiente modo: 
john --wordlist=<wordlist_file> --rules=reglaSSH 
```
#### Mostrar mutaciones
Podemos ver como se muta un diccionario al utilizar una regla escribiendo lo siguiente: 
```bash
john --wordlist=<wordlist_file> --rules=<regla> --stdout
```
### Recuperación de contraseñas
Todas las contraseñas están guardadas en el directorio `~/.john/john.pot` y también podemos mostrar las contraseñas de los archivos craqueados con el comando 
```bash
john <hash or hash_file> --show
```
## Hashcat
### Uso general
```bash
hashcat -m <hash_type> -a <attack_mode> <hash_file> <wordlist_or_mask>
```
### Ataque por diccionario
```bash
hashcat -m <hash_type> <hash_file> <wordlist>
```
En el ataque por diccionario hay que poner la opción `-a 0`, aunque si no especificas `-a`, Hashcat asume por defecto `-a 0`
### Generar mutaciones
Podemos crear diccionarios utilizando un [ataque basado en reglas](https://hashcat.net/wiki/doku.php?id=rule_based_attack) , utilizando un archivo `<nombre_archivo>.rule`
```bash
hashcat --force password.list -r custom.rule --stdout | sort -u > mut_password.list
# Si solo queremos crear una regla, podemos utilarla junto con hashcat. Ej:
 hashcat -m 0 md5hash /usr/share/wordlists/rockyou.txt -r custom.rule
```
Podemos encontrar reglas en `/usr/share/hashcat/rules`. Una de las más conocidas es `usrbest64.rule`. Otra regla interesante puede ser: `/usr/share/john/rule`
`s/rockyou-30000.rule`
## Servicios de red 
### nxc 
```bash
nxc <proto> $target -u <user or userlist> -p <password or passwordlist>
```
Puede ser interesante añadir lo siguiente al comando:
```bash
--continue-on-success | grep [+]
```
Más información sobre protocolos y demás: 
```bash
nxc -h 
nxc <proto> -h # p. ej nxc smb -h
```
#### Ejemplo smb
```bash
# Importante revisar dominio con -d ó poner --local-auth
nxc smb $target -u user.list -p passwords.list
#imaginamos que hemos obtenido un user y pass válido: 
nxc smb $target -u "user" -p "password" --shares
#Una vez conocido el directorio
smbclient -U user \\\\$target\\SHARENAME
```

### hydra
Uso básico de la herramienta. Puede ser más lenta que alguna de las herrmaientas posteriores, pero es más completa
```bash
hydra -L <user_list> -P <password_list> <protocol>://<target> -s <port_number>
```
podemos utilizar `-l` ó `-p` para único usuario/password en vez de lista. Si no especificamos la flag `-s` atacará al puerto por defeto
```bash
hydra -C <user_pass.list> <protocol>://<target>
```
Donde `<user_pass.list>` es una  combinación de usuario y contraseña separados por `:`

#### HTTP POST Login form
- Podemos hacer fuerza bruta solicitudes tipo POST del siguiente modo (aunque fuzz suele ser más rápido para peticiones de tipo http): 
	```bash
	hydra -l user -P /usr/share/wordlists/rockyou.txt $target http-post-form "/index.php:fm_usr=^USER^&fm_pwd=^PASS^:Login failed. Invalid"
	```
	La opción `http-post-form` indica que el ataque será contra un formulario HTTP POST
	Cada sección va separada por **dos puntos (`:`)**:
	-  **Ruta del formulario**
		- `"/index.php"` → Página donde está el formulario de login.
	- **Cuerpo de la solicitud (`POST` data)**
		- `"fm_usr=^USER^&fm_pwd=^PASS^"` → Parámetros enviados en el formulario.
			(las palabras `^USER^` y `^PASS^` son **marcadores especiales (placeholders)** que **Hydra reemplaza automáticamente** por valores de la lista de usuarios y contraseñas)
	- **Texto que indica un intento fallido**
		- `"Login failed. Invalid"` → Cadena que aparece cuando la autenticación falla.
#### HTTP Basic Auth / Digest Auth
- Este tipo de autenticación ocurre cuando antes de entrar en la página nos encontramos con un cuadro emergente de autenticación. En este caso, las credenciales no se envían en el cuerpo de la solicitud, sino en la cabecera `Authorization`
- Para saber que tipo de autenticación requiere, podemos hacer `curl -i http://$target` ó `curl -I http://$target` (solo cabeceras) y la respuesta nos dará el tipo de autenticación que necesitamos	 
	```bash
	# Basic auth nos dará como respuesta: 
	WWW-Authenticate: Basic realm="Restricted Area"
	# Digest auth nos dará como respuesta: 
	WWW-Authenticate: Digest realm="Restricted Area"
	```
##### Basic Auth
- Tenemos en la cabecera el campo `Authorization` con el formato
	```bash
	Authorization: Basic base64(usuario:contraseña)
	```
- Ataque con hydra:
	```bash
	hydra -l 'admin' -P /usr/share/wordlists/rockyou.txt $target http-get
	```
- También se podría hacer con `ffuf`
	```bash
	ffuf -w /usr/share/wordlists/rockyou.txt:FUZZ \ -H "Authorization: Basic $(echo -n 'admin:FUZZ' | base64)" \ -u "http://$target/"
	```
##### Digest Auth
- Este tipo de autenticación no utiliza `base64`, sino un desafío `nonce` que cambia en cada intento, por lo que no se podría hacer un ataque de fuerza bruta con `ffuf` en este caso
- Ataque con hydra 
	```bash
	hydra -L users.txt -P passwords.txt 192.168.244.201 http-digest-auth 
	```
### Medusa
Permite multitarget
```bash
medusa -h $target -u <username> -P <password_list> -M <servicio>
```
En vez de `-u` para un único usuario podríamos utilizar `-U` para una lista. Mismo con `-p`.
### Crowbar
Es útil para servciios como RDP, SSH (claves), VNC, OpenVPN. Permite hacer fuerza bruta de claves privadas en SSH también
```bash
crowbar -b <protocolo> -s <objetivo> -U <archivo_usuarios> -C <archivo_contraseñas>
```
### Ncrack
Soporta opciones avanzadas más técnicas y está optimizada para ataques de red y autenticación. Soporta algún servicio más que medusa, como RDP, VNC, PostgreSQL.
```bash
ncrack -p <PORT_NUMBER> -U users.txt -P passwords.txt <target_IP>
```

### Metasploit
#### Enumeración SMB
```bash
use auxiliary/scanner/smb/smb_login 
set RHOSTS <IP> 
set USER_FILE user.list 
set PASS_FILE password.list 
run
```