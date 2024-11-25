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
cewl https://www.inlanefreight.com -d 4 -m 6 --lowercase -w inlane.wordlist
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
```
Podemos encontrar reglas en `/usr/share/hashcat/rules`. Una de las más conocidas es best64.rule
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
nxc smb $target -u user.list -p passwords.list
#imaginamos que hemos obtenido un user y pass válido: 
nxc smb $target -u "user" -p "password" --shares
#Una vez conocido el directorio
smblcient -U user \\\\$target\\SHARENAME
```

### hydra
Uso básico de la herramienta
```bash
hydra -L <user_list> -P <password_list> <protocol>://<target>
```
podemos utilizar `-l` ó `-p` para único usuario/password en vez de lista
```bash
hydra -C <user_pass.list> <protocol>://<target>
```
Donde `<user_pass.list>` es una  combinación de usuario y contraseña separados por `:`
### Metasploit
#### Enumeración SMB
```bash
use auxiliary/scanner/smb/smb_login 
set RHOSTS <IP> 
set USER_FILE user.list 
set PASS_FILE password.list 
run
```