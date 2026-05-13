## HTTP
### URL - Uniform Resource Locator
**FQDN** identifica unívocamente un host en el DNS.  
Una **URL** define cómo y dónde acceder a un recurso (incluye el host).  
Aunque el campo **host** de una URL puede coincidir con un FQDN, no siempre es un FQDN estricto, ya que puede contener representaciones ambiguas o no-DNS como:  
`example.com@127.0.0.1`, `example.com.attacker.net`, `example.com.`, `[::1]`, `localhost`, `%00`, `%2e`.

![[Pasted image 20260104200126.png]]

|**Component**|**Example**|**Description**|
|---|---|---|
|`Scheme`|`http://` `https://`|This is used to identify the protocol being accessed by the client, and ends with a colon and a double slash (`://`)|
|`User Info`|`admin:password@`|This is an optional component that contains the credentials (separated by a colon `:`) used to authenticate to the host, and is separated from the host with an at sign (`@`)|
|`Host`|`inlanefreight.com`|The host signifies the resource location. This can be a hostname or an IP address|
|`Port`|`:80`|The `Port` is separated from the `Host` by a colon (`:`). If no port is specified, `http` schemes default to port `80` and `https` default to port `443`|
|`Path`|`/dashboard.php`|This points to the resource being accessed, which can be a file or a folder. If there is no path specified, the server returns the default index (e.g. `index.html`).|
|`Query String`|`?login=true`|The query string starts with a question mark (`?`), and consists of a parameter (e.g. `login`) and a value (e.g. `true`). Multiple parameters can be separated by an ampersand (`&`).|
|`Fragments`|`#status`|Fragments are processed by the browsers on the client-side to locate sections within the primary resource (e.g. a header or section on the page).|

### HTTPFlow
Diagrama que representa la antomía de una request HTTP a muy alto nivel
![[Pasted image 20260105120804.png]]
### cURL
Es una herramienta que soporta, además de HTTP, muchos otros protocolos. Algunos comandos de curl interesantes: 

| **Command**                                                                                                      | **Description**                                      |
| ---------------------------------------------------------------------------------------------------------------- | ---------------------------------------------------- |
| `curl -h`                                                                                                        | cURL help menu                                       |
| `curl inlanefreight.com`                                                                                         | Basic GET request                                    |
| `curl -s -O inlanefreight.com/index.html`                                                                        | Download file                                        |
| `curl -k https://inlanefreight.com`                                                                              | Skip HTTPS (SSL) certificate validation              |
| `curl inlanefreight.com -v`                                                                                      | Print full HTTP request/response details             |
| `curl -I https://www.inlanefreight.com`                                                                          | Send HEAD request (only prints response headers)     |
| `curl -i https://www.inlanefreight.com`                                                                          | Print response headers and response body             |
| `curl https://www.inlanefreight.com -A 'Mozilla/5.0'`                                                            | Set User-Agent header                                |
| `curl -u admin:admin http://<SERVER_IP>:<PORT>/`                                                                 | Set HTTP basic authorization credentials             |
| `curl http://admin:admin@<SERVER_IP>:<PORT>/`                                                                    | Pass HTTP basic authorization credentials in the URL |
| `curl -H 'Authorization: Basic YWRtaW46YWRtaW4=' http://<SERVER_IP>:<PORT>/`                                     | Set request header                                   |
| `curl 'http://<SERVER_IP>:<PORT>/search.php?search=le'`                                                          | Pass GET parameters                                  |
| `curl -X POST -d 'username=admin&password=admin' http://<SERVER_IP>:<PORT>/`                                     | Send POST request with POST data                     |
| `curl -b 'PHPSESSID=c1nsa6op7vtk7kdis7bcnbadf1' http://<SERVER_IP>:<PORT>/`                                      | Set request cookies                                  |
| `curl -X POST -d '{"search":"london"}' -H 'Content-Type: application/json' http://<SERVER_IP>:<PORT>/search.php` | Send POST request with JSON data                     |
### HTTPS Flow
Si visitamos una página web que fuerza HTTPS (puede ser por `HTS`, política del navegador, ó simplemente redirección 301)
![[Pasted image 20260105122248.png]]
### cURL sobre HTTPS
Si queremos utilizar curl sobre el protocolo https, debemos utilizar la flag `-k`, para saltarse la validación del certificado HTTPS (SSL)
```bash
curl -k https://$target
```
### Mostrar/modificar cabeceras con cURL
#### Mostrar cabeceras
Podemos usar la flag `-I` para mostrar la cabecera de una petición ó la flag `-i` para mostrar tanto la cabecera de la petición como el cuerpo. Ejemplo: 
```bash
 curl -I https://www.inlanefreight.com
```
#### Setear headers
Podemos setear headers con la flag `-H` ó cambiar el user-agent con la flag `-A`. También podemos utilizar la flag `-b` (brower cookies - send cookies) para enviar cookies. Ejemplos: 
```bash
# Header simple
curl -H "X-Test: value" http://target/
# Múltiples headers
curl \
  -H "X-Test: value" \
  -H "X-Forwarded-For: 127.0.0.1" \
  http://target/
# Cambiar user-agent - Forma explícita y recomendada
curl -H "User-Agent: Mozilla/5.0 (Windows NT 10.0)" http://target/
curl -A "Mozilla/5.0 (Windows NT 10.0)" http://target/
# Envíar cookies manualmente. 
curl -b "PHPSESSID=abc123" http://target/
curl -b "PHPSESSID=abc123; role=admin" http://target/
# Usar cookie jar. Flujo completo: 
curl -c cookies.txt http://target/
curl -b cookies.txt -A "Mozilla/5.0" http://target/dashboard

```


## HTTP request and responses
### HTTP request
Cuando hacemos una petición a un URL como la que sigue:  `http://inlanefreight.com/users/login.html`
![[Pasted image 20260105123642.png]]
> **Note:** HTTP version 1.X sends requests as clear-text, and uses a new-line character to separate different fields and different requests. HTTP version 2.X, on the other hand, sends requests as binary data in a dictionary form.

### HTTP Response
Una vez el navegador procesa nuestra petición envía una respuesta. Ejemplo de respuesta:

![[Pasted image 20260105130336.png]]Al final de la petición puede haber un cuerpo de respuesta, que suele ser código HTML, pero también puede ser JSON o similar dependiendo del contexto 

### cURL `-v`
Podemos ver la petición completa con curl utilizando la flag `-v` (la flag `-vvv` proporcionaría aún más información), verbose, que nos permite ver cómo se realizan exactamente las peticiones y las respuestas que se reciben
### Browser DevTools
Podemos utilizar el navegador también para ver todas las peticiones y respuestas que se envían en la parte de Networking al refrescar la paǵina

## HTTP Headers
Podemos dividir las cabeceras en las siguientes categorías:
1. `General Headers`
2. `Entity Headers`
3. `Request Headers`
4. `Response Headers`
5. `Security Headers`
#### General Headers
Aparecen tanto en las peticiones como en las respuestas y describen el mensaje en lugar del contenido

|**Header**|**Example**|**Description**|
|---|---|---|
|`Date`|`Date: Wed, 16 Feb 2022 10:38:44 GMT`|Holds the date and time at which the message originated. It's preferred to convert the time to the standard [UTC](https://en.wikipedia.org/wiki/Coordinated_Universal_Time) time zone.|
|`Connection`|`Connection: close`|Dictates if the current network connection should stay alive after the request finishes. Two commonly used values for this header are `close` and `keep-alive`. The `close` value from either the client or server means that they would like to terminate the connection, while the `keep-alive` header indicates that the connection should remain open to receive more data and input.|
#### Entity Headers
Describen las características del **contenido (body/payload)** del mensaje HTTP (ese contenido también es conocido como entidad). Pueden aparecer tanto en **requests** (ej. POST/PUT) como en **responses**.

|**Header**|**Example**|**Description**|
|---|---|---|
|`Content-Type`|`Content-Type: text/html`|Used to describe the type of resource being transferred. The value is automatically added by the browsers on the client-side and returned in the server response. The `charset` field denotes the encoding standard, such as [UTF-8](https://en.wikipedia.org/wiki/UTF-8).|
|`Media-Type`|`Media-Type: application/pdf`|The `media-type` is similar to `Content-Type`, and describes the data being transferred. This header can play a crucial role in making the server interpret our input. The `charset` field may also be used with this header.|
|`Boundary`|`boundary="b4e4fbd93540"`|Acts as a marker to separate content when there is more than one in the same message. For example, within a form data, this boundary gets used as `--b4e4fbd93540` to separate different parts of the form.|
|`Content-Length`|`Content-Length: 385`|Holds the size of the entity being passed. This header is necessary as the server uses it to read data from the message body, and is automatically generated by the browser and tools like cURL.|
|`Content-Encoding`|`Content-Encoding: gzip`|Data can undergo multiple transformations before being passed. For example, large amounts of data can be compressed to reduce the message size. The type of encoding being used should be specified using the `Content-Encoding` header.|

#### Request Headers
Solo se usan en peticiones y proporcionan información adicional sobre la **petición del cliente**, como el tipo de contenido esperado, credenciales, estado de la sesión o contexto del cliente.

|**Header**|**Example**|**Description**|
|---|---|---|
|`Host`|`Host: www.inlanefreight.com`|Used to specify the host being queried for the resource. This can be a domain name or an IP address. HTTP servers can be configured to host different websites, which are revealed based on the hostname. This makes the host header an important enumeration target, as it can indicate the existence of other hosts on the target server.|
|`User-Agent`|`User-Agent: curl/7.77.0`|The `User-Agent` header is used to describe the client requesting resources. This header can reveal a lot about the client, such as the browser, its version, and the operating system.|
|`Referer`|`Referer: http://www.inlanefreight.com/`|Denotes where the current request is coming from. For example, clicking a link from Google search results would make `https://google.com` the referer. Trusting this header can be dangerous as it can be easily manipulated, leading to unintended consequences.|
|`Accept`|`Accept: */*`|The `Accept` header describes which media types the client can understand. It can contain multiple media types separated by commas. The `*/*` value signifies that all media types are accepted.|
|`Cookie`|`Cookie: PHPSESSID=b4e4fbd93540`|Contains cookie-value pairs in the format `name=value`. A [cookie](https://en.wikipedia.org/wiki/HTTP_cookie) is a piece of data stored on the client-side and on the server, which acts as an identifier. These are passed to the server per request, thus maintaining the client's access. Cookies can also serve other purposes, such as saving user preferences or session tracking. There can be multiple cookies in a single header separated by a semi-colon.|
|`Authorization`|`Authorization: BASIC cGFzc3dvcmQK`|Another method for the server to identify clients. After successful authentication, the server returns a token unique to the client. Unlike cookies, tokens are stored only on the client-side and retrieved by the server per request. There are multiple types of authentication types based on the webserver and application type used.|
Enlace con todos los request headers  [aquí](https://tools.ietf.org/html/rfc7231#section-5).
#### Response headers
Proporcionan información adicional sobre la **respuesta del servidor**, como metadatos del recurso, control de caché, redirecciones o instrucciones para el cliente.

|**Header**|**Example**|**Description**|
|---|---|---|
|`Server`|`Server: Apache/2.2.14 (Win32)`|Contains information about the HTTP server, which processed the request. It can be used to gain information about the server, such as its version, and enumerate it further.|
|`Set-Cookie`|`Set-Cookie: PHPSESSID=b4e4fbd93540`|Contains the cookies needed for client identification. Browsers parse the cookies and store them for future requests. This header follows the same format as the `Cookie` request header.|
|`WWW-Authenticate`|`WWW-Authenticate: BASIC realm="localhost"`|Notifies the client about the type of authentication required to access the requested resource.|
#### Security headers
Indican políticas de seguridad que el navegador debe aplicar al procesar la respuesta, con el objetivo de **reducir la superficie de ataque** del cliente.

| **Header**                  | **Example**                                   | **Description**                                                                                                                                                                                                                                                                                                                             |
| --------------------------- | --------------------------------------------- | ------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| `Content-Security-Policy`   | `Content-Security-Policy: script-src 'self'`  | Dictates the website's policy towards externally injected resources. This could be JavaScript code as well as script resources. This header instructs the browser to accept resources only from certain trusted domains, hence preventing attacks such as [Cross-site scripting (XSS)](https://en.wikipedia.org/wiki/Cross-site_scripting). |
| `Strict-Transport-Security` | `Strict-Transport-Security: max-age=31536000` | Prevents the browser from accessing the website over the plaintext HTTP protocol, and forces all communication to be carried over the secure HTTPS protocol. This prevents attackers from sniffing web traffic and accessing protected information such as passwords or other sensitive data.                                               |
| `Referrer-Policy`           | `Referrer-Policy: origin`                     | Dictates whether the browser should include the value specified via the `Referer` header or not. It can help in avoiding disclosing sensitive URLs and information while browsing the website.                                                                                                                                              |

## Métodos y códigos HTTP
Se muestran algunos de los métodos y redirecciones más comunes
### Request methods
Aquí se muestran algunos de los métodos más utilizados

|**Method**|**Description**|
|---|---|
|`GET`|Requests a specific resource. Additional data can be passed to the server via query strings in the URL (e.g. `?param=value`).|
|`POST`|Sends data to the server. It can handle multiple types of input, such as text, PDFs, and other forms of binary data. This data is appended in the request body present after the headers. The POST method is commonly used when sending information (e.g. forms/logins) or uploading data to a website, such as images or documents.|
|`HEAD`|Requests the headers that would be returned if a GET request was made to the server. It doesn't return the request body and is usually made to check the response length before downloading resources.|
|`PUT`|Creates new resources on the server. Allowing this method without proper controls can lead to uploading malicious resources.|
|`DELETE`|Deletes an existing resource on the webserver. If not properly secured, can lead to Denial of Service (DoS) by deleting critical files on the web server.|
|`OPTIONS`|Returns information about the server, such as the methods accepted by it.|
|`PATCH`|Applies partial modifications to the resource at the specified location.|
### Status code

Ejemplos de los códigos de estado más comunes que nos podemos encontrar:

|**Class**|**Description**|
|---|---|
|`1xx`|Provides information and does not affect the processing of the request.|
|`2xx`|Returned when a request succeeds.|
|`3xx`|Returned when the server redirects the client.|
|`4xx`|Signifies improper requests `from the client`. For example, requesting a resource that doesn't exist or requesting a bad format.|
|`5xx`|Returned when there is some problem `with the HTTP server` itself.|

The following are some of the commonly seen examples from each of the above HTTP status code classes:

|**Code**|**Description**|
|---|---|
|`200 OK`|Returned on a successful request, and the response body usually contains the requested resource.|
|`302 Found`|Redirects the client to another URL. For example, redirecting the user to their dashboard after a successful login.|
|`400 Bad Request`|Returned on encountering malformed requests such as requests with missing line terminators.|
|`403 Forbidden`|Signifies that the client doesn't have appropriate access to the resource. It can also be returned when the server detects malicious input from the user.|
|`404 Not Found`|Returned when the client requests a resource that doesn't exist on the server.|
|`500 Internal Server Error`|
## GET

Es un método HTTP utilizado para **solicitar un recurso al servidor**, enviando los parámetros en la URL. Está pensado para **operaciones de lectura**, no debería modificar el estado del servidor y sus respuestas pueden ser **cacheables**. Es un método que se suele utilizar para renderizar páginas y hacer búsquedas a traves de parámetros en el navegador. 

### HTTP Basic Auth
Son mecanismos de autenticación a nivel de protocolo HTTP en los que el cliente envía credenciales en el header `Authorization` para acceder a recursos protegidos. Basic envía las credenciales codificadas en Base64, mientras que Digest utiliza un esquema de `challenge-response` para evitar el envío de la contraseña en claro.
Si una página implementa este tipo de autenticación y tratamos de cargar la página, nos encontraremos que nos pide credenciales antes de renderizar la página
#### Flujo de navegación HTTP Basic / Digest Auth
- **Paso 1 - Petición SIN credenciales**

	El usuario accede a:	
	```text
	GET / HTTP/1.1 Host: testpage.com
	```
	El navegador **no envía credenciales** porque aún no las tiene.
	
- **Paso 2 - Respuesta del servidor**
	El servidor en este caso respondería con lo siguiente: 
	```bash 
	HTTP/1.1 401 Authorization Required
	Date: Mon, 21 Feb 2022 13:11:46 GMT
	Server: Apache/2.4.41 (Ubuntu)
	Cache-Control: no-cache, must-revalidate, max-age=0
	WWW-Authenticate: Basic realm="Access denied"
	Content-Length: 13
	Content-Type: text/html; charset=UTF-8
	
	Access denied
	```
- **Paso 3 - El navegador pide credenciales**
	- Muestra popu nativo
	- El usuario introduce `username:password`
- **Paso 4 - Nueva petición con credenciales**
	El navegador reenvía la request con (ejemplo de `admin:admin` en base64)
	```bash
	Authorization: Basic YWRtaW46YWRtaW4=
	```
- **Paso 5 - Acceso concedido**
	Si las credenciales son correctas renderiza la aplicación
#### Petición con basic / digest auth con curl
Hay dos maneras de hacer una petición envíando este tipo de credenciales con curl: 
```bash
curl http://admin:admin@testpage.com
# o más recomendable
curl -u admin:admin http://testpage.com
```
#### Entendiendo que hace la petición
Podemos ver el flujo de lo que ocurre, si introducimos la flag `-v` 
```bash
curl -v http://admin:admin@<SERVER_IP>:<PORT>/

*   Trying <SERVER_IP>:<PORT>...
* Connected to <SERVER_IP> (<SERVER_IP>) port PORT (#0)
* Server auth using Basic with user 'admin'
> GET / HTTP/1.1
> Host: <SERVER_IP>
> Authorization: Basic YWRtaW46YWRtaW4=
> User-Agent: curl/7.77.0
> Accept: */*
> 
* Mark bundle as not supporting multiuse
< HTTP/1.1 200 OK
< Date: Mon, 21 Feb 2022 13:19:57 GMT
< Server: Apache/2.4.41 (Ubuntu)
< Cache-Control: no-store, no-cache, must-revalidate
< Expires: Thu, 19 Nov 1981 08:52:00 GMT
< Pragma: no-cache
< Vary: Accept-Encoding
< Content-Length: 1453
< Content-Type: text/html; charset=UTF-8
< 

```
Podríamos obtener el mismo resultado con la siguiente petición
```bash

curl -H 'Authorization: Basic YWRtaW46YWRtaW4=' http://<SERVER_IP>:<PORT>/
# ó
curl http://$target -H "Authorization: Basic $(echo -n admin:admin | base64 )"
```


## POST
**POST** es un método HTTP utilizado para **enviar datos al servidor** como parte del cuerpo de la petición. Se usa habitualmente para **crear o procesar recursos**, puede **modificar el estado del servidor** y sus peticiones **no son cacheables por defecto**.
### Realizando una petición post con cookies de sesión
Podemos realizar una petición post a un formulario de autenticación como sigue: 
```bash
curl -X POST -d 'username=admin&password=admin' http://$target
# Ó siguiendo redirecciones con -L, si la respuesta es 3xx
curl -L -X POST -d 'username=admin&password=admin' http://$target
```
Si la autenticación es válida, recibiremos un seteo de cookie de sesión:
```bash
HTTP/1.1 200 OK
Date: 
Server: Apache/2.4.41 (Ubuntu)
Set-Cookie: PHPSESSID=c1nsa6op7vtk7kdis7bcnbadf1; path=/

...SNIP...
        <em>Type a city name and hit <strong>Enter</strong></em>
...SNIP...

```
y podremos realizar la petición autenticados del siguiente modo: 
```bash
curl -b 'PHPSESSID=c1nsa6op7vtk7kdis7bcnbadf1' http://<SERVER_IP>:<PORT>/
```
#### Forma correcta
La forma correcta y más simple de realizar todo esto es seteando una cookie jar del siguiente modo: 
```bash
curl -L -c cookiesSesion.txt -X POST -d 'username=admin&password=admin' http://$target
curl -b cookiesSesion.txt http://$target
```

## CRUD API
Cuando nos enfrentamos a una API tenemos 4 tipos de operaciones básicas en general:

| Operation | HTTP Method | Description                                        |
| --------- | ----------- | -------------------------------------------------- |
| `Create`  | `POST`      | Adds the specified data to the database table      |
| `Read`    | `GET`       | Reads the specified entity from the database table |
| `Update`  | `PUT`       | Updates the data of the specified database table   |
| `Delete`  | `DELETE`    | Removes the specified row from the database table  |
Expandido y ligeramente  más realista

| Operación            | Método   | Comentario                               |
| -------------------- | -------- | ---------------------------------------- |
| `Create`             | `POST`   | Creación con ID generado por el servidor |
| `Create` / `Replace` | `PUT`    | Crea o reemplaza si el ID es conocido    |
| `Read`               | `GET`    | Lectura                                  |
| `Update` (full)      | `PUT`    | Reemplazo completo                       |
| `Update` (partial)   | `PATCH`  | Modificación parcial                     |
| `Delete`             | `DELETE` | Eliminación                              |

### READ
Se hace mediante una petición `GET`

```bash
# Ejemplo en el que al pasar un string vacío recibiríamos todos los campos
curl http://$target/api.php/city/
# Query sobre una ciudad concreta, ej: london
curl http://$target/api.php/city/london
```
### CREATE
Se hace mediante una petición `POST`, aunque `PUT` también puede crear recursos, pero muchas APIs no lo permiten por diseño. Es necesario añadir `Content-Type: application/json` en la cabecera. Ejemplo

```bash
curl -X POST http://$target/api.php/city/ -d '{"city_name":"HTB_City", "country_name":"HTB"}' -H 'Content-Type: application/json'
```
### UPDATE
Se actualiza completamente un campo utilizando `PUT` (que crea el objeto si no existe y lo puede reemplazar completamente), aunque algunas APIs también aceptan `PATCH`(cambia parcialmente una entrada, que debe existir previamente). También es necesario añadir en la cabecera `Content-Type: application/json`

```bash
curl -X PUT http://<SERVER_IP>:<PORT>/api.php/city/london -d '{"city_name":"New_HTB_City", "country_name":"HTB"}' -H 'Content-Type: application/json'
# esto borraría la ciudad london y crearía la ciudad New_HTB_City
```
### DELETE
Es un método muy simple, basta con poner un identificador válido y lo podemos eliminar: 
```bash
curl -X DELETE http://<SERVER_IP>:<PORT>/api.php/city/New_HTB_City
```


---
## Cookie jar
Un **cookie jar** es el almacenamiento donde un cliente HTTP guarda cookies recibidas vía `Set-Cookie` para reutilizarlas en peticiones posteriores. 
### ¿Qué hace exactamente el navegador con las cookies?

#### Flujo REAL (simplificado pero correcto)

1. **Hace una petición HTTP**
2. **Recibe una respuesta** (puede ser `200 OK`, `302/301/307` login /redirects, `401/403` ó incluso `404`)
3. Si la respuesta contiene:
	```bash
	Set-Cookie: name=value; Domain=...; Path=...; flags...
	```
	entonces:    
	- Valida la cookie ( comprueba una serie de reglas como `Domain`, `Path`, flags válidos, `Secure`, `SameSite`)
	- La guarda en su **cookie jar**
4. En **peticiones posteriores**, si:
	- El dominio coincide
	- El path coincide
	- Se cumplen flags (`Secure`, `SameSite`, etc.)
	👉 **Adjunta automáticamente**:

	```bash
	Cookie: name=value
	```


📌 **Esto ocurre sin intervención del usuario**.
### ¿Cómo simular el flujo cookie jar con curl ó python?
#### cURL

```bash
curl -c cookies.txt http://target/
curl -b cookies.txt http://target/users/login.html
```
- `-c cookies.txt` → **guardar cookies**
- `-b cookies.txt` → **reenviar cookies**
- `cookies.txt` = cookie jar

#### python 

```python 
import requests

s = requests.Session()   # ← cookie jar automático
s.get("http://target/")
r = s.get("http://target/users/login.html")
```

- `Session()` mantiene cookies
- Se comporta como un navegador (a nivel HTTP
#### JavaScript (Node.js)

En Node **NO hay cookie jar por defecto**.

Necesitas librerías:

- `axios` + `axios-cookiejar-support`
    
- `tough-cookie`

Ejemplo conceptual:
```js

const jar = new CookieJar(); 
axios.get(url, { jar, withCredentials: true });
```