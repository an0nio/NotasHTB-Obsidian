## Reconocimiento activo/pasivo
### Activo
En este tipo de reconocimiento hay interacción directamente con la máquina objetivo. Algunas de las formas más comunes de reconocimiento activo son las siguientes: 

|Technique|Description|Example|Tools|Risk of Detection|
|---|---|---|---|---|
|`Port Scanning`|Identifying open ports and services running on the target.|Using Nmap to scan a web server for open ports like 80 (HTTP) and 443 (HTTPS).|Nmap, Masscan, Unicornscan|High: Direct interaction with the target can trigger intrusion detection systems (IDS) and firewalls.|
|`Vulnerability Scanning`|Probing the target for known vulnerabilities, such as outdated software or misconfigurations.|Running Nessus against a web application to check for SQL injection flaws or cross-site scripting (XSS) vulnerabilities.|Nessus, OpenVAS, Nikto|High: Vulnerability scanners send exploit payloads that security solutions can detect.|
|`Network Mapping`|Mapping the target's network topology, including connected devices and their relationships.|Using traceroute to determine the path packets take to reach the target server, revealing potential network hops and infrastructure.|Traceroute, Nmap|Medium to High: Excessive or unusual network traffic can raise suspicion.|
|`Banner Grabbing`|Retrieving information from banners displayed by services running on the target.|Connecting to a web server on port 80 and examining the HTTP banner to identify the web server software and version.|Netcat, curl|Low: Banner grabbing typically involves minimal interaction but can still be logged.|
|`OS Fingerprinting`|Identifying the operating system running on the target.|Using Nmap's OS detection capabilities (`-O`) to determine if the target is running Windows, Linux, or another OS.|Nmap, Xprobe2|Low: OS fingerprinting is usually passive, but some advanced techniques can be detected.|
|`Service Enumeration`|Determining the specific versions of services running on open ports.|Using Nmap's service version detection (`-sV`) to determine if a web server is running Apache 2.4.50 or Nginx 1.18.0.|Nmap|Low: Similar to banner grabbing, service enumeration can be logged but is less likely to trigger alerts.|
|`Web Spidering`|Crawling the target website to identify web pages, directories, and files.|Running a web crawler like Burp Suite Spider or OWASP ZAP Spider to map out the structure of a website and discover hidden resources.|Burp Suite Spider, OWASP ZAP Spider, Scrapy (customisable)|Low to Medium: Can be detected if the crawler's behaviour is not carefully configured to mimic legitimate traffic.|

### Pasivo
En este tipo de reconocimiento no hay interacción directa con el objetivo. Se analiza información pública disponible. Algunas de las formas más comunes de enumeración de este tipo son las siguientes: 


|Technique|Description|Example|Tools|Risk of Detection|
|---|---|---|---|---|
|`Search Engine Queries`|Utilising search engines to uncover information about the target, including websites, social media profiles, and news articles.|Searching Google for "`[Target Name] employees`" to find employee information or social media profiles.|Google, DuckDuckGo, Bing, and specialised search engines (e.g., Shodan)|Very Low: Search engine queries are normal internet activity and unlikely to trigger alerts.|
|`WHOIS Lookups`|Querying WHOIS databases to retrieve domain registration details.|Performing a WHOIS lookup on a target domain to find the registrant's name, contact information, and name servers.|whois command-line tool, online WHOIS lookup services|Very Low: WHOIS queries are legitimate and do not raise suspicion.|
|`DNS`|Analysing DNS records to identify subdomains, mail servers, and other infrastructure.|Using `dig` to enumerate subdomains of a target domain.|dig, nslookup, host, dnsenum, fierce, dnsrecon|Very Low: DNS queries are essential for internet browsing and are not typically flagged as suspicious.|
|`Web Archive Analysis`|Examining historical snapshots of the target's website to identify changes, vulnerabilities, or hidden information.|Using the Wayback Machine to view past versions of a target website to see how it has changed over time.|Wayback Machine|Very Low: Accessing archived versions of websites is a normal activity.|
|`Social Media Analysis`|Gathering information from social media platforms like LinkedIn, Twitter, or Facebook.|Searching LinkedIn for employees of a target organisation to learn about their roles, responsibilities, and potential social engineering targets.|LinkedIn, Twitter, Facebook, specialised OSINT tools|Very Low: Accessing public social media profiles is not considered intrusive.|
|`Code Repositories`|Analysing publicly accessible code repositories like GitHub for exposed credentials or vulnerabilities.|Searching GitHub for code snippets or repositories related to the target that might contain sensitive information or code vulnerabilities.|GitHub, GitLab|Very Low: Code repositories are meant for public access, and searching them is not suspicious.|
## whois
**WHOIS** es un **protocolo de consulta basado en TCP (puerto 43)** que permite obtener información registrada sobre dominios, direcciones IP y sistemas autónomos, como propietario, registrador, fechas de registro y contactos administrativos.
## DNS

### Diferencia DNS y vhosts
 **Reconocimiento DNS** busca **nombres de dominio/subdominios existentes en el DNS**, mientras que el **reconocimiento de vhosts** busca **hosts virtuales configurados en el servidor web**, que pueden existir aunque no estén publicados en DNS. **En la práctica real, es necesario tanto DNS fuzzing como VHost fuzzing**, ya que ambos descubren superficies distintas
 
|DNS recon|VHost recon|
|---|---|
|Busca nombres en DNS|Busca configuraciones en el web server|
|Depende de registros DNS|Depende del servidor HTTP|
|Encuentra subdominios publicados|Puede encontrar hosts ocultos|
|Ej: `dnsrecon`, `fierce`|Ej: `ffuf -H "Host: FUZZ.example.com"`|
#### Vhosts sin dns
Puede tener sentido crear vhosts sin DNS en producción. Por ejemplo: 
- Aplicaciones internas accesibles solo por:
    - `/etc/hosts`
    - VPN
    - reverse proxy interno
- Deploys temporales
- Testing antes de publicar el subdominio
- Multitenancy interno en servidores compartidos

En estos casos, puede ser necesario añadir manualmente el dominio en `/etc/hosts` para **acceder al servicio una vez identificado**.
#### DNS sin vhosts

Encontrar un vhost por `Host header` funciona **solo si estamos conectando a la IP correcta del servidor**.  Si el subdominio apunta a **otra IP distinta**, o está detrás de un **CDN / reverse proxy**, necesitarás **DNS enumeration**.

- Escenario donde sí necesitamos enumeración DNS
	```textplain
	example.com        → 1.2.3.4
	hola.example.com   → 5.6.7.8
	```
- Otro escenario
	```
	example.com → servidor origen
	hola.example.com → CDN (Cloudflare/Akamai)
	```

### Herramientas típicas de reconocimiento DNS
| Tool                         | Key Features                                                                                            | Use Cases                                                                                                                               |
| ---------------------------- | ------------------------------------------------------------------------------------------------------- | --------------------------------------------------------------------------------------------------------------------------------------- |
| `dig`                        | Versatile DNS lookup tool that supports various query types (A, MX, NS, TXT, etc.) and detailed output. | Manual DNS queries, zone transfers (if allowed), troubleshooting DNS issues, and in-depth analysis of DNS records.                      |
| `nslookup`                   | Simpler DNS lookup tool, primarily for A, AAAA, and MX records.                                         | Basic DNS queries, quick checks of domain resolution and mail server records.                                                           |
| `host`                       | Streamlined DNS lookup tool with concise output.                                                        | Quick checks of A, AAAA, and MX records.                                                                                                |
| `dnsenum`                    | Automated DNS enumeration tool, dictionary attacks, brute-forcing, zone transfers (if allowed).         | Discovering subdomains and gathering DNS information efficiently.                                                                       |
| `fierce`                     | DNS reconnaissance and subdomain enumeration tool with recursive search and wildcard detection.         | User-friendly interface for DNS reconnaissance, identifying subdomains and potential targets.                                           |
| `dnsrecon`                   | Combines multiple DNS reconnaissance techniques and supports various output formats.                    | Comprehensive DNS enumeration, identifying subdomains, and gathering DNS records for further analysis.                                  |
| `theHarvester`               | OSINT tool that gathers information from various sources, including DNS records (email addresses).      | Collecting email addresses, employee information, and other data associated with a domain from multiple sources.                        |
| `Online DNS Lookup Services` | User-friendly interfaces for performing DNS lookups.                                                    | Quick and easy DNS lookups, convenient when command-line tools are not available, checking for domain availability or basic information |
### Descubrimiento de subdominios
#### Activo
Mediante fuerza bruta contra el objetivo o intentando hacer transferencia de zona. Puede ser con herramientas como `dnsenum`, `ffuf`, `gobuster` ...

##### Fuerza burta
Algunas de las herramientas más típicas son las siguientes: 

|Tool|Description|
|---|---|
|[dnsenum](https://github.com/fwaeytens/dnsenum)|Comprehensive DNS enumeration tool that supports dictionary and brute-force attacks for discovering subdomains.|
|[fierce](https://github.com/mschwager/fierce)|User-friendly tool for recursive subdomain discovery, featuring wildcard detection and an easy-to-use interface.|
|[dnsrecon](https://github.com/darkoperator/dnsrecon)|Versatile tool that combines multiple DNS reconnaissance techniques and offers customisable output formats.|
|[amass](https://github.com/owasp-amass/amass)|Actively maintained tool focused on subdomain discovery, known for its integration with other tools and extensive data sources.|
|[assetfinder](https://github.com/tomnomnom/assetfinder)|Simple yet effective tool for finding subdomains using various techniques, ideal for quick and lightweight scans.|
|[puredns](https://github.com/d3mondev/puredns)|Powerful and flexible DNS brute-forcing tool, capable of resolving and filtering results effectively.|
Ejemplo con dnsenum 
```bash
dnsenum --enum inlanefreight.com -f /usr/share/seclists/Discovery/DNS/subdomains-top1million-20000.txt -r
```

##### Transferencia de zona
Puede ser muy eficiente y menos invasivo que hacer fuerza bruta si está activado. La transferencia de zona (`AXFR request`) está pensada para  sincronizar los registros DNS entre servidores autoritativos primarios y secundarios, permitiendo replicar toda la información de la zona DNS de forma automática.

![[Pasted image 20260213125532.png]]
La mayoría de servidores actuales están configurados para hacer transferencia de zona a solamente servidores secundarios de confianza, pero aún así podemos intentar hacer transferencia de zona del siguiente modo 

```bash
dig axfr @nsztm1.digi.ninja zonetransfer.me
```

En este caso ` @nsztm1.digi.ninja`   sería el servidor DNS responsable de `zonetransfer.me`
#### Pasivo
Una de las formas más comunes es buscando en los 
 `Certificate Transparency (CT) logs` , que están en los repositorios públicos de los certificados `SSL/TLS` o utilizando motores de búsqueda como google o duckduckgo
### Descubrimiento de vhosts
Son configuraciones dentro del servidor web que permiten mostrar múltiples páginas dentro de una misma dirección IP.

![[Pasted image 20260213134415.png]]
 Ejemplo de configuración apache
```apacheconf
# Example of name-based virtual host configuration in Apache
<VirtualHost *:80>
    ServerName www.example1.com
    DocumentRoot /var/www/example1
</VirtualHost>

<VirtualHost *:80>
    ServerName www.example2.org
    DocumentRoot /var/www/example2
</VirtualHost>

<VirtualHost *:80>
    ServerName www.another-example.net
    DocumentRoot /var/www/another-example
</VirtualHost>
```
#### Fuerza bruta
Algunas de las herramientas que podemos utilizar para hacer fuerza bruta de subdominios son las siguientes: 

|Tool|Description|Features|
|---|---|---|
|[gobuster](https://github.com/OJ/gobuster)|A multi-purpose tool often used for directory/file brute-forcing, but also effective for virtual host discovery.|Fast, supports multiple HTTP methods, can use custom wordlists.|
|[Feroxbuster](https://github.com/epi052/feroxbuster)|Similar to Gobuster, but with a Rust-based implementation, known for its speed and flexibility.|Supports recursion, wildcard discovery, and various filters.|
|[ffuf](https://github.com/ffuf/ffuf)|Another fast web fuzzer that can be used for virtual host discovery by fuzzing the `Host` header.|Customizable wordlist input and filtering options.|
- Ejemplo con `gobuster`:
	```bash
	# Funcionamiento general
	gobuster vhost -u http://<target_IP_address> -w <wordlist_file> --append-domain
	# Ejemplo
	gobuster vhost -u http://inlanefreight.htb:81 -w /usr/share/seclists/Discovery/DNS/subdomains-top1million-110000.txt --append-domain
	```
- Ejemplo con `ffuf`
	```bash
	#Primero debemos añadir el dominio a /etc/hosts con cualquiera de estos dos comandos
	echo "$target $domain" | sudo tee -a /etc/hosts 
	sudo sh -c "echo \"$target $domain\" >> /etc/hosts"
	# Después hacemos fuzzing al header
	ffuf -w /usr/share/wordlists/seclists/Discovery/DNS/subdomains-top1million-5000.txt:FUZZ -u http://$domain:$port/ -H "Host: FUZZ.$domain" -o vhostsFuzzing_$domain
	# Siempre recibiremos un código de respuesta 200, pero en este caso la idea es filtrar según el tamaño de la respuesta con -fs (filter size)
	ffuf -w /usr/share/wordlists/seclists/Discovery/DNS/subdomains-top1million-5000.txt:FUZZ -u http://$domain:$port/ -fs SIZE_RESPONSE -H "Host: FUZZ.$domain" -o vhostsFuzzing_$target
	```
### Certificate Transparency Logs
**Certificate Transparency logs** son registros públicos y auditables donde se almacenan los certificados TLS emitidos por las autoridades certificadoras, permitiendo detectar certificados emitidos para dominios y subdominios, incluso si no están publicados en DNS.
Ejemplo interesante de uso: 
```bash
curl -s "https://crt.sh/?q=facebook.com&output=json" | jq -r '.[]
 | select(.name_value | contains("dev")) | .name_value' | sort -u
```

## Fingerprinting
**Fingerprinting** es el proceso de identificar tecnologías, servidores, frameworks, lenguajes y configuraciones utilizadas por una aplicación web mediante el análisis de respuestas HTTP, cabeceras, contenido y comportamiento del servicio.
Algunas herramientas más comunes: 

|Tool|Description|Features|
|---|---|---|
|`Wappalyzer`|Browser extension and online service for website technology profiling.|Identifies a wide range of web technologies, including CMSs, frameworks, analytics tools, and more.|
|`BuiltWith`|Web technology profiler that provides detailed reports on a website's technology stack.|Offers both free and paid plans with varying levels of detail.|
|`WhatWeb`|Command-line tool for website fingerprinting.|Uses a vast database of signatures to identify various web technologies.|
|`Nmap`|Versatile network scanner that can be used for various reconnaissance tasks, including service and OS fingerprinting.|Can be used with scripts (NSE) to perform more specialised fingerprinting.|
|`Netcraft`|Offers a range of web security services, including website fingerprinting and security reporting.|Provides detailed reports on a website's technology, hosting provider, and security posture.|
|`wafw00f`|Command-line tool specifically designed for identifying Web Application Firewalls (WAFs).|Helps determine if a WAF is present and, if so, its type and configuration.|
### Banner grabbing
**Banner grabbing** es la técnica de obtener información sobre un servicio remoto leyendo los mensajes de identificación (banners) que el servidor envía al establecer una conexión, permitiendo identificar software, versiones y configuraciones expuestas. 
Si estamos ante una aplicación web, podemos hacer banner grabbing del mostrando las cabeceras, con `curl -I`:
```bash
curl -I inlanefreight.com
```
### Wafw00f
**WAF (Web Application Firewall)** es un sistema de seguridad que inspecciona y filtra el tráfico HTTP/HTTPS entre el cliente y la aplicación web para detectar y bloquear ataques como SQLi, XSS o explotación de vulnerabilidades.

**Wafw00f** es una herramienta de fingerprinting que permite identificar la presencia y el tipo de WAF protegiendo una aplicación web mediante el análisis de las respuestas HTTP y su comportamiento ante peticiones específicas. Ejemplo de uso
```bash
 wafw00f inlanefreight.com
```

## Crawling
**Web crawling** es el proceso automatizado de recorrer una aplicación web siguiendo enlaces y recursos accesibles para descubrir páginas, endpoints, parámetros y funcionalidades expuestas dentro del sitio.
### robots.txt
**robots.txt** es un archivo ubicado en la raíz de un sitio web que indica a los crawlers qué rutas pueden o no pueden ser rastreadas, y que frecuentemente revela directorios o recursos interesantes para enumeración.
### Well-Known URIs
**Well-known URIs** son rutas estandarizadas bajo `/.well-known/` definidas por distintos protocolos para publicar información específica del servicio (configuraciones, claves, políticas, endpoints), que pueden proporcionar datos útiles durante el reconocimiento.

IANA mantiene un registro de las well-know URIs, cada una con un determinado propósito: 

|URI Suffix|Description|Status|Reference|
|---|---|---|---|
|`security.txt`|Contains contact information for security researchers to report vulnerabilities.|Permanent|RFC 9116|
|`/.well-known/change-password`|Provides a standard URL for directing users to a password change page.|Provisional|https://w3c.github.io/webappsec-change-password-url/#the-change-password-well-known-uri|
|`openid-configuration`|Defines configuration details for OpenID Connect, an identity layer on top of the OAuth 2.0 protocol.|Permanent|http://openid.net/specs/openid-connect-discovery-1_0.html|
|`assetlinks.json`|Used for verifying ownership of digital assets (e.g., apps) associated with a domain.|Permanent|https://github.com/google/digitalassetlinks/blob/master/well-known/specification.md|
|`mta-sts.txt`|Specifies the policy for SMTP MTA Strict Transport Security (MTA-STS) to enhance email security.|Permanent|RFC 8461|
### Algunas herramientas de crawling
Algunas de las herramientas de crawling más comunes
1. `Burp Suite Spider`
2. `OWASP ZAP (Zed Attack Proxy)`
3. `Scrapy (Python Framework)
4. `Apache Nutch (Scalable Crawler)
#### Ejemplo de uso con ReconSpider
Se ha puesto la herramienta en `/opt/reconSpider`, aunque se puede instalar fácilmente del siguiente modo: 
```bash
# Suele ser necesario instalar la herramienta scrapy previamente
wget -O ReconSpider.zip https://academy.hackthebox.com/storage/modules/144/ReconSpider.v1.2.zip
unzip ReconSpider.zip 
python3 ReconSpider.py http://inlanefreight.com
```
Uso de la herramienta: 
```bash
python3 ReconSpider.py http://inlanefreight.com
```
(devuelve un archivo .json con la información del último escaner)
## Search engine Discovery

**Search engine discovery** es la técnica de obtener información sobre un dominio o aplicación mediante consultas avanzadas en motores de búsqueda (dorks), permitiendo descubrir páginas indexadas, archivos expuestos, credenciales filtradas o recursos ocultos sin interactuar directamente con el objetivo.

|Operator|Description|Example|
|---|---|---|
|`site:`|Restricts search results to a specific website.|`site:example.com "password reset"`|
|`inurl:`|Searches for a specific term in the URL of a page.|`inurl:admin login`|
|`filetype:`|Limits results to files of a specific type.|`filetype:pdf "confidential report"`|
|`intitle:`|Searches for a term within the title of a page.|`intitle:"index of" /backup`|
|`cache:`|Shows the cached version of a webpage.|`cache:example.com`|
|`"search term"`|Searches for the exact phrase within quotation marks.|`"internal error" site:example.com`|
|`OR`|Combines multiple search terms.|`inurl:admin OR inurl:login`|
|`-`|Excludes specific terms from search results.|`inurl:admin -intext:wordpress`|
Podemos encontrar algunos de los dorks más populares en [google hacking database](https://www.exploit-db.com/google-hacking-database)
## Web archive
**Search engine discovery** es la técnica de obtener información sobre un dominio o aplicación mediante consultas avanzadas en motores de búsqueda (dorks), permitiendo descubrir páginas indexadas, archivos expuestos, credenciales filtradas o recursos ocultos sin interactuar directamente con el objetivo. Uno de los más conocidos es [wayback machine](https://web.archive.org/) ó [archive is](https://archive.is/)

## Herramientas de reconocimiento automático
Pueden realizar algunas de las acciones anteriormente descritas de forma automática. Mostramos como utilizar una herramienta como `finalrecon`

- Instalación
	```bash
	git clone https://github.com/thewhiteh4t/FinalRecon.git
	cd FinalRecon
	pip3 install -r requirements.txt
	chmod +x ./finalrecon.py
	./finalrecon.py --help
	```
- Uso
	```bash
	./finalrecon.py --headers --whois --url http://inlanefreight.com
	```