## Footprinting del servicio
### nmap
```bash
nmap -p53 -Pn -sV -sC $target
```
### Consulta ns
Devuelve los responsables de resolver un dominio dado
```bash
dig ns inlanefreight.htb @$target
```
### Consulta any
Mostrará todas las entradas disponibles de un dominio dado (MX, A, NS, TXT…)
```bash
dig any inlanefreight.htb @$target
```
### Consulta versión
A veces se pueden realizar consultas de tipo CHAOS (`CH`), que nos puede facilitar información como la versión. Soportada sobre todo en servidores bind
```bash
dig CH TXT version.bind @$target
```
Además de la versión, se podrían hacer consultas como `hostname.bind,` `admin.bind`, `zones.bind`
### Transferencia de zona
Si el servidor permite transferencia de zona (en vez de `$target` podríamos haber puesto un dominio dado)
```
dig axfr inlanefreight.htb @$target
```
#### Fierce
Busca todos los servidores del dominio raíz y buscar una transferencia de zona DNS
```bash
fierce --domain zonetransfer.me
```
## Ataques específicos del protocolo
### Domain takeover
Es la adquisición de un dominio no registrado para acceder a otro dominio. Supongamos un dominio `sub.target.com` tiene el siguiente registro
```bash
sub.target.com.   60   IN   CNAME   anotherdomain.com
```
Si el dominio `anotherdomain.com` expira y lo adquiere un atacante malintencionado tendría control total de `sub.target.com` (ya que las solicitudes a `sub.target.com` se redirigen automáticamente a `anotherdomain.com`)
### Enumeración de subdominios
### Pasiva - subfinder
```bash
./subfinder -d inlanefreight.com -v
```
### Activa 
Se muestran algunas herramientas

| **Aspecto**               | **Subbrute**                                                                                       | **Gobuster (modo DNS)**                                                                                           | **DNSenum**                                                                                                                    |
| ------------------------- | -------------------------------------------------------------------------------------------------- | ----------------------------------------------------------------------------------------------------------------- | ------------------------------------------------------------------------------------------------------------------------------ |
| **Tipo de enumeración**   | Activa (fuerza bruta de subdominios).                                                              | Activa (fuerza bruta de subdominios).                                                                             | Mixta: Enumeración activa y pasiva (registros, transferencias de zona, fuerza bruta).                                          |
| **Método principal**      | Fuerza bruta usando wordlists y resolutores DNS específicos.                                       | Fuerza bruta usando wordlists.                                                                                    | Consultas DNS estándar, fuerza bruta, transferencias de zona, resolución inversa.                                              |
| **Velocidad**             | Moderada (depende de los resolutores y consultas activas).                                         | Muy rápida (multihilo optimizado).                                                                                | Más lenta debido a su enfoque completo y análisis adicional.                                                                   |
| **Capacidades avanzadas** | Soporta múltiples resolutores y rotación.  <br>Diseñado para evitar bloqueos en consultas masivas. | Multihilo rápido.  <br>No soporta transferencias de zona o análisis avanzado.                                     | Transferencias de zona (`AXFR`), resolución inversa, búsquedas externas (Google).                                              |
| **Salida esperada**       | Subdominios válidos confirmados por resolución DNS.                                                | Subdominios válidos confirmados por resolución DNS.                                                               | Subdominios, registros DNS, IPs relacionadas, posibles configuraciones inseguras.                                              |

#### Subbrute
Fuerza bruta de subdominios.
```shell-session
git clone https://github.com/TheRook/subbrute.git >> /dev/null 2>&1
cd subbrute
echo "ns1.inlanefreight.com" > ./resolvers.txt
./subbrute inlanefreight.com -s ./names.txt -r ./resolvers.txt
```
#### Gobuster
Sería similar a utilizar `subbrute`. Puede ser más rápido, pero menos robusto y personalizable que gobuster
```bash
gobuster dns -d $domain -w /usr/share/seclists/Discovery/DNS/subdomains-top1million-110000.txt -r $target
```
#### DNSEnum
Además de hacer fuerza bruta a subdominios, encuentra todos los registros de un dominio e intenta hacer transferencia de zonas y resoluciones inversas, entre otras
```bash
dnsenum --dnsserver $target --enum -p 0 -s 0 -o subdomains.txt -f /usr/share/wordlists/seclists/Discovery/DNS/namelist.txt dev.inlanefreight.htb
```
#### Búsqueda de dominios - estado de la consulta
A veces,  un servidor DNS servidor está rechazando intencionalmente una consulta devolviendo como status: `REFUSED`. La siguiente consulta nos devolvería el estado 
```bash
dig +nocmd "$subdomain.$domain" @$target 2>/dev/null | grep -oP 'status: \K\w+'
```
### DNS Spoofing
Envenenamiento del caché DNS utilizando herramientas MITM como  [Ettercap](https://www.ettercap-project.org/) o [Bettercap](https://www.bettercap.org/)
