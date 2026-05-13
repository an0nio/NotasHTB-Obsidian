
## Web fuzzing
**Web fuzzing** es la técnica de enviar múltiples solicitudes automatizadas con entradas manipuladas (rutas, parámetros, valores o headers) para descubrir directorios ocultos, endpoints, funcionalidades no documentadas o comportamientos inesperados en una aplicación web.
Algunas de las aplicaciones de fuzzing: 
- Encontrar directorios y archivos ocultos
- Encontrar endpoints inseguros en APIs
- Encontrar puntos de SQLi
- Encontrar vulnerabildades de tipo XSS
- Encontrar defectos que permiten command inyection
### Diferencia fuzzing/fuerza bruta
| Criterio                | Fuerza bruta                                                                                                    | Fuzzing                                                                                                          |
| ----------------------- | --------------------------------------------------------------------------------------------------------------- | ---------------------------------------------------------------------------------------------------------------- |
| **Definición**          | Probar sistemáticamente todas las combinaciones posibles de datos de entrada para adivinar un valor específico. | Inyectar datos inesperados o aleatorios en una aplicación para encontrar vulnerabilidades y recursos ocultos.    |
| **Propósito**           | Romper contraseñas, claves u otras credenciales de acceso.                                                      | Descubrir vulnerabilidades de la aplicación, archivos ocultos, directorios y problemas de validación de entrada. |
| **Metodología**         | Búsqueda exhaustiva sobre todas las combinaciones posibles de entrada.                                          | Inyección dinámica de entradas para provocar respuestas inesperadas en la aplicación.                            |
| **Enfoque**             | Datos o entradas específicas, como contraseñas o claves API.                                                    | Comportamiento general de la aplicación bajo diferentes condiciones de entrada.                                  |
| **Eficiencia**          | Consume mucho tiempo debido a su naturaleza exhaustiva; menos eficiente en espacios de entrada grandes.         | Más eficiente para identificar comportamientos inesperados y vulnerabilidades mediante entradas variadas.        |
| **Herramientas usadas** | Crackers de contraseñas, herramientas de recuperación de claves.                                                | Fuzzers web, escáneres de vulnerabilidades.                                                                      |
| **Resultado**           | Coincidencia exitosa del valor de entrada correcto.                                                             | Descubrimiento de vulnerabilidades, configuraciones incorrectas y recursos ocultos.                              |
## Directory fuzzing
### ffuf
Visto en [[Ffuf]], auque ponemos alguna configuración adicional que se utiliza aquí
```bash
ffuf -w /usr/share/wordlists/dirb/common.txt:FUZZ -u http://$target:$port/FUZZ -e .html,.php -ic -v -o directoryFuzzing_$target_$port -rate 500
```
- `-ic ` para ignorar comentarios 
- `-rate 500` para limitar el número de peticiones por segundo
#### Fuzzing recursivo
```bash
ffuf -w /usr/share/seclists/Discovery/Web-Content/directory-list-2.3-medium.txt -ic -v -u http://$target:$port/FUZZ -e .html -recursion  -rate 500
# o si quieremos limitar el nivel de recursión: 
#-recursion -recursion-depth 2
```

## Virtual host y subdomain fuzzing
### Gobuster
Puede ser más cómodo que ffuf para hacer este tipo de tareas
### fuzzing de VHost
Debemos añadir el target  a `/etc/hosts`.
```bash
echo "$target $domain" | sudo tee -a /etc/hosts
```
Después
```bash
gobuster vhost -u http://$domain:$port -w /usr/share/wordlists/seclists/Discovery/Web-Content/common.txt --append-domain -xs "400" 
```
Es obligatorio `--apend-domain` , ya que añade el dominio a cada palabra en el wordlist, asegurando que el host header en cada petición sea completo. (sino la petición del Host sería `Host: admin` en lugar de `Host: admin.example.com` ). 
En este caso se ha añadido exclude status 400 con `-xs "400,500"`
### fuzzing DNS
Podemos hacerlo del siguiente modo: 
```
gobuster dns --domain "$domain" -w /usr/share/wordlists/seclists
/Discovery/DNS/subdomains-top1million-5000.txt 
```
## Fuzzing de APIs
### Api fuzzer
- Instalación (isntalado en `/opt/api_fuzzer`)
	```shell-session
	git clone https://github.com/PandaSt0rm/webfuzz_api.git
	cd webfuzz_api
	pip3 install -r requirements.txt
	```
- Ejecución 
	```shell-session
	python3 api_fuzzer.py http://IP:PORT
	```