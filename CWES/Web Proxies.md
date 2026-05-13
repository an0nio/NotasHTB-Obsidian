Nos saltamos toda la parte de configuración y vamos directamente a algunos ejemplos interesantes
## Automatic  modification
Puede ser útil para hacer modificaciones automáticas en cualquier petición que pase a través del proxy, como cambiar el user-agent. 
### Burp match and replace
Para activar esta opción debemos ir a `Proxy>Proxy settings>HTTP match and replace rules` y hacer clic en `Add`. Podemos hacer modificaciones tanto en las peticiones como en las respuestas
### Automatic request:  Zap Replacer
Se puede acceder a esta funcionalidad presionando `CTRL+R` y buscar un match string que sustituir en las peticiones

### Redirección automática de tráfico (Upstream Proxy / Forwarding)

Puede ser útil cuando una herramienta **no soporta proxies**, permitiendo que todas las peticiones enviadas a un listener local (por ejemplo `127.0.0.1:8080`) sean reenviadas automáticamente al servidor objetivo real.

En **Burp Suite**, esto se configura en:

`Proxy Listeners > Edit > Request handling`

Allí podemos añadir reglas indicando:
- **Redirect to host**: servidor real objetivo
- **Redirect to port**: puerto real del objetivo

De esta forma, el flujo será:

```
Herramienta → 127.0.0.1:8080 (Burp listener)  
Burp → target real (forward automático)
```

Esto permite interceptar, modificar y registrar el tráfico incluso cuando la herramienta no permite configurar un proxy manualmente.

## URL Encoding - Decoding
### URL Encoding

Podemos urlencodear escribiendo `CTRL+U` en el texto seleccionado en Burp. ZAP lo hace automáticamente. Hay distintos tipos de URL encoding como `Full URL-Encoding`(cada byte se interpreta como `%HH`) o `Unicode URL` (para ASCII puro, `a-z`, `/`, `<`,  no hay diferencia práctica, pero sí para carácteres no ASCII)
> Burp `Ctrl+U` no es un encoder “crudo”; es un encoder contextual orientado a peticiones válidas, no a bypasses. Normalmente utiliza `application/x-www-form-urlencoded`** (encoding de formulario), no “Unicode URL”.

## Herramientas de proxy
Normalmente burp está configurado para escuchar en `127.0.0.1:8080`, por lo que si queremos que alguno de nuestros programas corra sobre proxy deberemos configurarlos correctamente
### Proxychains
Es una herramienta que permite enrutar el trafico proveniente de cualquier herramienta de CLI.
Lo primero que debemos hacer para configurarlo es editar `/etc/proxychains.conf`, comentar la última línea y añadir lo siguiente (se suele descomentar también `dynamic_chain` o `strict_chain`): 
```
http 127.0.0.1 8080
```
Después de esto podremos hacer una petición como sigue: 
```bash
proxychains -q curl http://$target
# En curl podríamos lograr el mismo efecto así: 
curl http://$target -x http://127.0.0.1:8080
```
lo que provocaría que la petición pase por el proxy. 
### Metasploit
Una vez dentro de metasploit, podemos configurarlo para que todas las peticiones pasen por burp del siguiente modo (ejemplo de escaner sobre burp): 
```bash
msf6 > use auxiliary/scanner/http/robots_txt
msf6 auxiliary(scanner/http/robots_txt) > set PROXIES HTTP:127.0.0.1:8080
msf6 auxiliary(scanner/http/robots_txt) > set RHOST SERVER_IP
msf6 auxiliary(scanner/http/robots_txt) > set RPORT PORT
msf6 auxiliary(scanner/http/robots_txt) > run
```
### Python 
#### Request usando un proxy
- Forma clásica
	```python 
	import requests
	
	proxies = {
	    "http": "http://127.0.0.1:8080",
	    "https": "http://127.0.0.1:8080"
	}
	
	r = requests.get("http://target", proxies=proxies)
	print(r.text)
	
	```
- Con sesión  y envíando alguna información adicional(equivalente a navegador)
	```python
	import requests
	
	s = requests.Session()
	s.proxies = {
	    "http": "http://127.0.0.1:8080",
	    "https": "http://127.0.0.1:8080"
	}
	
	s.cookies.set("PHPSESSID", "abc123")
	s.headers.update({"Authorization": "Bearer TOKEN"})
	
	s.get("http://target")
	```
#### Ejemplo de proxy mínimo en python 
```python 
import http.server
import socketserver
import requests

class Proxy(http.server.BaseHTTPRequestHandler):
    def do_GET(self):
        resp = requests.get(self.path)
        self.send_response(resp.status_code)
        for k, v in resp.headers.items():
            self.send_header(k, v)
        self.end_headers()
        self.wfile.write(resp.content)

PORT = 8081
with socketserver.TCPServer(("", PORT), Proxy) as httpd:
    print(f"Proxy listening on {PORT}")
    httpd.serve_forever()
```
Ideas de ampliación 
```python 
# forzar x-forwarded-for
resp = requests.get(
    self.path,
    headers={"X-Forwarded-For": "127.0.0.1"}
)
```

Ejemplo de uso: 
```bash
python3 proxy.py
curl -x http://127.0.0.1:8081 http://example.com
```
## Burp intruder 
No se toman apuntes, ya que se ha utilizado de sobra