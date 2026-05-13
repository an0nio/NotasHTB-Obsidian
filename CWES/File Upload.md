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
### Blacklist extensions y fuzzing de extensiones
Si no podemos subir algún archivo determinado porque está blacklisteado, p. ej: 
```php
$fileName = basename($_FILES["uploadFile"]["name"]); $extension = pathinfo($fileName, PATHINFO_EXTENSION); $blacklist = array('php', 'php7', 'phps'); if (in_array($extension, $blacklist)) { echo "File type not allowed"; die(); }
```
Podemos intentar hacer fuzzing con diccionarios como los siguientes: 
- [Lista php payload all the things](https://github.com/swisskyrepo/PayloadsAllTheThings/blob/master/Upload%20Insecure%20Files/Extension%20PHP/extensions.lst)
- [Lista .net payload all the things](https://github.com/swisskyrepo/PayloadsAllTheThings/tree/master/Upload%20Insecure%20Files/Extension%20ASP)
- `/usr/share/wordlists/seclists/Discovery/Web-Content/web-extensions.txt
- [Wordlist más extensa](https://github.com/KernelPan1k/upload-list-extension/blob/master/wordlist.txt)
