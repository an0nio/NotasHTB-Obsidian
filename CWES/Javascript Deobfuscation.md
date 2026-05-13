## Qué es la ofuscación js
**La ofuscación de JavaScript** es la técnica de transformar el código en una versión difícil de leer o entender sin alterar su funcionamiento, mediante cambios como renombrado de variables, codificación de cadenas o uso de estructuras complejas.

Sus propósitos incluyen proteger la lógica de aplicaciones legítimas frente a ingeniería inversa, reducir la exposición de algoritmos propietarios y, con frecuencia en contextos de seguridad ofensiva, **ocultar código malicioso para dificultar su análisis y detección**, siendo este último uno de los usos más habituales por parte de atacantes.

## Algunas herramientas de ofuscación
- **[javascript-minifier](https://javascript-minifier.com/)**:  Herramienta online que permite **minificar y desminificar código JavaScript**, reduciendo su tamaño o haciéndolo más legible para facilitar su análisis.
- **[BeautifyTools](http://beautifytools.com/javascript-obfuscator.php)** : Plataforma web que ofrece utilidades para **ofuscar, desofuscar y formatear código JavaScript**, útil tanto para proteger código como para analizar scripts ofuscados.
- **[JS Console](https://jsconsole.com/)**: Consola interactiva en línea que permite **ejecutar código JavaScript directamente desde el navegador**, útil para probar fragmentos de código durante el análisis.
- **[Prettier](https://prettier.io/playground/)** : Formateador de código que **reorganiza automáticamente JavaScript (y otros lenguajes) en un formato legible y consistente**, facilitando la revisión de scripts complejos u ofuscados.
- **[Beautifier](https://beautifier.io/)**:  Herramienta web que permite **reformatear y estructurar código JavaScript, HTML y CSS**, mejorando su legibilidad durante tareas de análisis.
- **[JSNice](http://www.jsnice.org/)** : Herramienta que utiliza análisis estadístico para **reconstruir nombres de variables y mejorar la legibilidad del código JavaScript ofuscado o minificado**, ayudando en procesos de ingeniería inversa.
-  [JJ Encode](https://utf-8.jp/public/jjencode.html) or [AA Encode](https://utf-8.jp/public/aaencode.html): Otras herramientas de ofuscación, que en muchas ocasiones pueden hacer que la página vaya lenta
## Algunos ejemplos de ofuscación (encodig-decoding)
|                                                    |               |
| -------------------------------------------------- | ------------- |
| `echo hackthebox \| base64`                        | base64 encode |
| `echo ENCODED_B64 \| base64 -d`                    | base64 decode |
| `echo -n hackthebox \| xxd -p`                     | hex encode    |
| `echo -n ENCODED_HEX \| xxd -p -r`                 | hex decode    |
| `echo hackthebox \| tr 'A-Za-z' 'N-ZA-Mn-za-m'`    | rot13 encode  |
| `echo ENCODED_ROT13 \| tr 'A-Za-z' 'N-ZA-Mn-za-m'` | rot13 decode  |
