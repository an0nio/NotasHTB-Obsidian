:FFUEl término fuzzing se refiera a varios tipos de técnias utilizados para estudiar como se comporta una aplicación al aplicar distintos inputs distintos en ciertos campos. 
- **Fuzzing básico de directorios:** 
	```bash
	ffuf -w /usr/share/wordlists/dirb/common.txt:FUZZ -u http://$target:$port/FUZZ -e .html,.php -o directoryFuzzing_$target_$port
	# otro clásico (20K): 	/usr/share/wordlists/seclists/Discovery/Web-Content/directory-list-2.3-medium.txt
	# Otro (5K): /usr/share/seclists/Discovery/Web-Content/common.txt
	# más extensiones: ".txt,.htm,.html,.xhtml,.php,.asp,.aspx,.jsp,.do,.cgi,.pl,.py,.conf"
	```
- **Filtrado de resultados**
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
- **Fuzzing de extensiones**
	```bash
	ffuf -w /usr/share/wordlists/seclists/Discovery/Web-Content/web-extensions.txt:EXT -u http://$target:$port/indexEXT -o extensionsFuzzing_$target
	```
	- Ejemplo en el que para cada extensión queremos mostrar el contenido de los resultados que aparecen entre `<p>`
		```bash
		cat extensionsFuzzing_$target | jq .results.[].url | tr -d '"' > extensiones
		cat extensiones | while read -r ext; do echo -e "\n🌍 URL: $ext"; curl -s "$ext" | grep -oP '(?<=<p>).*?(?=</p>)' | awk '{print "📝", $0}'; done
		```
- **Fuzzing recursivo**
	```bash
	ffuf -w /usr/share/wordlists/seclists/Discovery/Web-Content/directory-list-2.3-small.txt:FUZZ -u http://$target:$port/FUZZ -recursion -recursion-depth 1 -e .php -v -o recursiveFuzzing_$target_$port
	```
	El parámetro `-e` en `ffuf` hace que el fuzzing se realice tanto sin la extensión como con la(s) extensión(es) especificada(s)
- **Fuzzing de subdominios:**
	```bash
	#Primero debemos añadir el dominio a /etc/hosts con cualquiera de estos dos comandos
	echo "$target $domain" | sudo tee -a /etc/hosts 
	sudo sh -c "echo \"$target $domain\" >> /etc/hosts"
	# A continuación realizamos el fuzzing de subdominios
	ffuf -w /usr/share/wordlists/seclists/Discovery/DNS/subdomains-top1million-5000.txt:FUZZ -u http://FUZZ.$domain/ -o subdomainFuzzing_$target 
	```
- **Fuzzing vhosts:** Podríamos pensar que es un fuzzing de subdominios en la misma IP. Puede que los vhosts no tengan registros DNS. La idea es hacer fuzzing al header del siguiente modo: 
	```bash
	ffuf -w /usr/share/wordlists/seclists/Discovery/DNS/subdomains-top1million-5000.txt:FUZZ -u http://$domain:$port/ -H "Host: FUZZ.$domain" -o vhostsFuzzing_$domain
	# Siempre recibiremos un código de respuesta 200, pero en este caso la idea es filtrar según el tamaño de la respuesta con -fs (filter size)
	ffuf -w /usr/share/wordlists/seclists/Discovery/DNS/subdomains-top1million-5000.txt:FUZZ -u http://$domain:$port/ -fs SIZE_RESPONSE -H "Host: FUZZ.$domain" -o vhostsFuzzing_$target
	# IMPORTANTE: Recordar poner los hosts encontrados en /etc/hosts o no se podrán resolver
	```
	- Añadir los hosts descubiertos automáticamente a `/etc/hosts`
	```
	cat vhostsFuzzing_$target | jq .results.[].host | tr -d '"' > vhost_$target
	awk -v ip="$target" '{print ip, $1}' vhosts_$target | sudo tee -a /etc/hosts
	```
- **Proxy:** Podríamos hacer pasar por un proxy como burpsuite añadiendo la flag `-x http://127.0.0.1:8080`. Ejemplo con petición anterior: 
	```
	ffuf -w /usr/share/wordlists/seclists/Discovery/DNS/subdomains-top1million-5000.txt:FUZZ -u http://$domain:$port/ -H "Host: FUZZ.$domain" -o vhostsFuzzing_$target -x http://127.0.0.1:8080
	```
- **Fuzzing de parámetros GET** 
	```bash
	ffuf -w /usr/share/wordlists/seclists/Discovery/Web-Content/burp-parameter-names.txt:FUZZ -u http://admin.$domain:$port/admin/admin.php?FUZZ=key -fs xxx 
	# Si hay un parámetro válido, cambiará el tamaño de la respuesta
	```
- **Fuzzing de parámetros POST**: Hay que añadir la flag `-d` (data) y probablemente cambiar el header. Al igual que con curl, no hace falta explicitar el método POST, aunque en este ejemplo sí lo ponemos explícitamente
	```bash
	ffuf -w /usr/share/wordlists/seclists/Discovery/Web-Content/burp-parameter-names.txt:FUZZ -u http://admin.$domain:$port/admin/admin.php -X POST -d 'FUZZ=key' -H 'Content-Type: application/x-www-form-urlencoded' -fs xxx
	```
	- Inciso sobre cabeceras de parámeros post: 
		- `Content-Type: application/x-www-form-urlencoded` → Datos en formato URL (`key=value&key2=value2`).
		- `Content-Type: multipart/form-data` → Para **archivos o formularios** con archivos adjuntos.
		- `Content-Type: application/json` → Cuando se envía **JSON** (`{"key": "value"}`).
- **Value fuzzing**: Aquí no siempre hay un diccionario claro que elegir, por lo que deberemos elegirlo en función de la situación (en el caso en el que tengamos un `id`, podemos crear un diccionario personalizado como en el ejemplo)
	```bash
	# Creación de diccionario
	for i in $(seq 1 1000); do echo $i >> ids.txt; done
	# Fuzzing de valores
	ffuf -w ids.txt:FUZZ -u http://admin.$domain:$port/admin/admin.php -X POST -d 'id=FUZZ' -H 'Content-Type: application/x-www-form-urlencoded' -fs xxx
	```
- **Fuzzing con varios parámetros**: (supongamos que el archivo vhosts contiene hosts descubiertos como `admin.inlanefreight.htb`, ...)
	```bash
	ffuf -w vhosts:HOSTS -w /usr/share/wordlists/seclists/Discovery/Web-Content/web-extensions.txt:EXT -u http://HOSTS:$port/indexEXT -x http://127.0.0.1:8080 -o doublefuzzing
	# mostrar resultados
	cat doublefuzzing | jq -r .results.[].url
	```