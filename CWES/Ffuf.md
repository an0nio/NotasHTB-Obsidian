:FFUEl término fuzzing se refiera a varios tipos de técnias utilizados para estudiar como se comporta una aplicación al aplicar distintos inputs distintos en ciertos campos. 
## Fuzzing de directorios
Podemos realizar fuzzing de directorios del siguiente modo

```bash
ffuf -w /usr/share/wordlists/dirb/common.txt:FUZZ -u http://$target:$port/FUZZ -e .html,.php -o directoryFuzzing_$target_$port
# otro clásico (20K): 	/usr/share/wordlists/seclists/Discovery/Web-Content/directory-list-2.3-medium.txt
# Otro (5K): /usr/share/seclists/Discovery/Web-Content/common.txt
# más extensiones: ".txt,.htm,.html,.xhtml,.php,.asp,.aspx,.jsp,.do,.cgi,.pl,.py,.conf"
```
### Fuzzing recursivo
```bash
ffuf -w /usr/share/wordlists/seclists/Discovery/Web-Content/directory-list-2.3-small.txt:FUZZ -u http://$target:$port/FUZZ -recursion -recursion-depth 1 -e .php -v -o recursiveFuzzing_$target_$port
```
El parámetro `-e` en `ffuf` hace que el fuzzing se realice tanto sin la extensión como con la(s) extensión(es) especificada(s)
### Algunos filtros interesantes
```bash
# Mostrar todas las urls 
jq .results.[].url directoryFuzzing_$target
# Mostrar todas las urls que devulvan un estado distinto al 403
jq -r '.results.[] | select(.status!=403) | .url' directoryFuzzing_$target
# Mostrar todas las urls y estado ordenado alfabéticamente por url
jq -r '.results | sort_by(.url)[] | {url,status}' directoryFuzzing_192.168.120.201
# o sin que aparezca el formato json
jq -r '.results | sort_by(.url)[] | "\(.url) \(.status)"' directoryFuzzing_192.168.120.201
```
### Diccionarios clásicos
Algunos de los diccionarios que se suelen utilizar son los siguientes: 
- `/usr/share/wordlists/dirb/common.txt` (5K)
- `/usr/share/wordlists/seclists/Discovery/Web-Content/directory-list-2.3-medium.txt` (220K )
- `/usr/share/wordlists/seclists/Discovery/Web-Content/common.txt` (5K)

## Fuzzing de extensiones
```bash
ffuf -w /usr/share/wordlists/seclists/Discovery/Web-Content/web-extensions.txt:EXT -u http://$target:$port/indexEXT -o extensionsFuzzing_$target
```
- Ejemplo en el que para cada extensión queremos mostrar el contenido de los resultados que aparecen entre `<p>`
	```bash
	cat extensionsFuzzing_$target | jq .results.[].url | tr -d '"' > extensiones
	cat extensiones | while read -r ext; do echo -e "\n🌍 URL: $ext"; curl -s "$ext" | grep -oP '(?<=<p>).*?(?=</p>)' | awk '{print "📝", $0}'; done
	```
### Extensiones comunes
Podemos encontrar diccionarios de extensiones en nuestra kali escribiendo lo siguiente: 
```
ls /usr/share/wordlists/seclists/Discovery/Web-Content/ | grep -i ext 
```
Uno de los diccionarios más comunes es el siguiente: 
```
/usr/share/wordlists/seclists/Discovery/Web-Content/web-extensions.txt
```

## Fuzzing de subdominios

```bash
ffuf -w /usr/share/wordlists/seclists/Discovery/DNS/subdomains-top1million-5000.txt:FUZZ -u http://FUZZ.$domain/ -o subdomainFuzzing_$target 
```
Los diccionarios clásicos los podemos encontrar en `/usr/share/seclists/Discovery/DNS/`, como por ejemplo: 
`/usr/share/seclists/Discovery/DNS/subdomains-top1million-110000.txt`

## Fuzzing de vhosts

**Fuzzing vhosts:** Podríamos pensar que es un fuzzing de subdominios en la misma IP. Puede que los vhosts no tengan registros DNS. La idea es hacer fuzzing al header del siguiente modo: 
```bash
#Primero debemos añadir el dominio a /etc/hosts con cualquiera de estos dos comandos
echo "$target $domain" | sudo tee -a /etc/hosts 
sudo sh -c "echo \"$target $domain\" >> /etc/hosts"
# Después hacemos fuzzing al header
ffuf -w /usr/share/wordlists/seclists/Discovery/DNS/subdomains-top1million-5000.txt:FUZZ -u http://$domain:$port/ -H "Host: FUZZ.$domain" -o vhostsFuzzing_$domain
# Siempre recibiremos un código de respuesta 200, pero en este caso la idea es filtrar según el tamaño de la respuesta con -fs (filter size)
ffuf -w /usr/share/wordlists/seclists/Discovery/DNS/subdomains-top1million-5000.txt:FUZZ -u http://$domain:$port/ -fs SIZE_RESPONSE -H "Host: FUZZ.$domain" -o vhostsFuzzing_$target
```
- IMPORTANTE: Añadir los hosts descubiertos automáticamente a `/etc/hosts` 
```bash
cat vhostsFuzzing_$target | jq .results.[].host | tr -d '"' > vhost_$target
awk -v ip="$target" '{print ip, $1}' vhosts_$target | sudo tee -a /etc/hosts
```
## Proxy
Proxy:** Podríamos hacer pasar por un proxy como burpsuite añadiendo la flag `-x http://127.0.0.1:8080`. Ejemplo con petición de descubrimiento de vhosts: 
```bash
ffuf -w /usr/share/wordlists/seclists/Discovery/DNS/subdomains-top1million-5000.txt:FUZZ -u http://$domain:$port/ -H "Host: FUZZ.$domain" -o vhostsFuzzing_$target -x http://127.0.0.1:8080
```
## Fuzzing de parámetros GET/POST
### GET

```bash
ffuf -w /usr/share/wordlists/seclists/Discovery/Web-Content/burp-parameter-names.txt:FUZZ -u http://admin.$domain:$port/admin/admin.php?FUZZ=key -fs xxx 
# Si hay un parámetro válido, cambiará el tamaño de la respuesta
```
### POST
Para hacer fuzzing de parámetros POST hay que añadir la flag `-d` (data) y probablemente cambiar el header. Al igual que con curl, no hace falta explicitar el método POST, aunque en este ejemplo sí lo ponemos explícitamente
```bash
ffuf -w /usr/share/wordlists/seclists/Discovery/Web-Content/burp-parameter-names.txt:FUZZ -u http://admin.$domain:$port/admin/admin.php -X POST -d 'FUZZ=key' -H 'Content-Type: application/x-www-form-urlencoded' -fs xxx
```

- Inciso sobre cabeceras de parámeros post: 
	- `Content-Type: application/x-www-form-urlencoded` → Datos en formato URL (`key=value&key2=value2`).
	- `Content-Type: multipart/form-data` → Para **archivos o formularios** con archivos adjuntos.
	- `Content-Type: application/json` → Cuando se envía **JSON** (`{"key": "value"}`).
### Value fuzzing
 Aquí no siempre hay un diccionario claro que elegir, por lo que deberemos elegirlo en función de la situación (en el caso en el que tengamos un `id`, podemos crear un diccionario personalizado como en el ejemplo)
```bash
# Creación de diccionario
for i in $(seq 1 1000); do echo $i >> ids.txt; done
# Fuzzing de valores
ffuf -w ids.txt:FUZZ -u http://admin.$domain:$port/admin/admin.php -X POST -d 'id=FUZZ' -H 'Content-Type: application/x-www-form-urlencoded' -fs xxx
```
## Fuzzing con varios parámetros
**Fuzzing con varios parámetros**: (supongamos que el archivo vhosts contiene hosts descubiertos como `admin.inlanefreight.htb`, ...)
```bash
ffuf -w vhosts:HOSTS -w /usr/share/wordlists/seclists/Discovery/Web-Content/web-extensions.txt:EXT -u http://HOSTS:$port/indexEXT -x http://127.0.0.1:8080 -o doublefuzzing
```