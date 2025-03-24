- [ ]  Known DC vulnerabilities:
    - [ ]  Zerologon
    - [ ]  PetitPotam
    - [ ]  NoPAC (once you have a user's creds)
- [ ]  Kerberoastable accounts
- [ ]  AS-REP Roastable accounts
- [ ]  Find computers where Domain Users can RDP
- [ ]  Find computers where Domain Users are Local Admin
- [ ]  Shortest Path to Domain Admins (esp. from Owned Principals)
- [ ]  Write-permissions on any critical accounts?
- [ ]  Enumerate:
    - [ ]  Users (interesting permissions)
    - [ ]  Groups (memberships)
    - [ ]  Services (which hosts? users w/ SPNs?)
    - [ ]  Computers (which ones have useful sessions?)
## Directorio activo
- Enumeración con acceso al dominio. Equipos, usuarios, dominio (`powerview`)
	```powershell
	# Dominio
	 Get-Domain | select -ExpandProperty name
	# Equipos y dirección ip para pegar a /etc/hosts
	 Get-DomainComputer | select -ExpandProperty name > equipos.txt
	foreach ($equipo in (Get-Content .\equipos.txt)) {$IP = Resolve-DnsName $equipo | select -ExpandProperty ipaddress; echo "$ip $equipo" } 
	# Usuarios del dominio
	Get-DomainUser | select -ExpandProperty name	
	```
- [[Miscelaneo#ASREPRoasting| Asreproasting]]: Cuentas sin preautenticación kerberos. Podemos obtener el hash de usuarios asreproasteables e intentar crackearlos. 
- [[Kerberoasting| Cuentas kerberoasteables]] : Cualquier usuario autenticado puede solicitar un TGS de una cuenta con SPN e intentar crackearlo con hashcat. Si se consigue acceso a la cuenta se usaría como una cuenta normal
- Puertos internos expuestos que no se ven desde fuera (`netstat.exe -at`)
- Escalar privilegios y tratar de encontrar más información (`whoami /priv`, `winpeas`, `findstr`...)
- Recopilación información con mimikatz 
	```powershell
	# SAM ... token::elevate? (pth y crack)
	.\mimikatz.exe privilege::debug lsadump::sam exit *> dumpSAM.txt
	# LSASS (pth, ovth, silver ticket,info en texto plano)
	.\mimikatz.exe privilege::debug sekurlsa::logonpasswords exit *> dumpLSASS.txt
	# Secrets (info adicional)
	.\mimikatz.exe privilege::debug lsadump::lsa /patch exit *> secrets_lsa.txt
	# ekeys (opth)
	.\mimikatz.exe privilege::debug sekurlsa::ekeys exit *> ekeys.txt
	# Extraer tickets (ptt)
	.\mimikatz.exe privilege::debug sekurlsa::tickets /export exit
	```
- Con la información probar pth, ptt, opth, crackear
- Con las credenciales obtenidas intentar conexión vía `rdp`, `winrm`, `impacket-wmiexec`, `impacket-psexec`
- Información útil con bloodhound

## Webpage

- [ ]  Check `searchsploit` for vulns in server software, web stack
- [ ]  Check `/robots.txt` and `/sitemap.xml` for directories/files of interest
- [ ]  Inspect HTML comments/source for juicy info
    - [ ]  secrets/passwords
    - [ ]  directories of interest
    - [ ]  software libraries in use
- [ ]  Inspect SSL certs for DNS subdomains and emails
- [ ]  Watch out for [Apache virtual hosts](https://httpd.apache.org/docs/current/vhosts/%7CApache%20virtual%20hosts.md) (and nginx/IIS/etc. equivalents)! Set `/etc/hosts` with ALL (sub)domains for the target IP.
- [ ]  Attempt login with default/common creds
- [ ]  Attempt login auth bypass (SQLi): `' or 1=1 -- #`
- [ ]  Test for [SQL/NoSQL Injection](https://github.com/camercu/oscp-prep/blob/main/CHEATSHEET.md#3.5.3%20SQL%20Injection) using "bad" chars: `'")}$%%;\`
- [ ]  Test for [Command Injection](https://github.com/camercu/oscp-prep/blob/main/CHEATSHEET.md#3.5.6%20Command%20Injection)
    - [ ]  separator characters: `; | & || &&`
    - [ ]  quoted context escape: `" '`
    - [ ]  UNIX subshells: `$(cmd)`, `>(cmd)` and backticks
- [ ]  Test for [Path Traversal](https://github.com/camercu/oscp-prep/blob/main/CHEATSHEET.md#3.5.4%20Directory%20Traversal) in URL query and (arbitrary?) file upload
- [ ]  Test for [LFI/RFI](https://github.com/camercu/oscp-prep/blob/main/CHEATSHEET.md#3.5.5%20LFI/RFI), especially in URL query params
- [ ]  Test for [XSS](https://github.com/camercu/oscp-prep/blob/main/CHEATSHEET.md#3.5.7%20Cross-Site%20Scripting%20\(XSS\)) on all input fields, URL query params, and HTTP Headers:
    - [ ]  Check what remains after filtering applied on input: `'';!--"<XSS>=&{()}`
    - [ ]  Try variations of `<script>alert(1)</script>`
---
- Comprobar whatweb y wappalizer + búsqueda de vulnerabilidades en el software, web stack vía searchsploit y navegador
- Buscar en directorio como `/robots.txt` , `/sitemap.xml`
- Intentar utilizar [credenciales por defecto](https://github.com/ihebski/DefaultCreds-cheat-sheet/blob/main/DefaultCreds-Cheat-Sheet.csv)
- Hacer [[Ffuf| fuzzing]] de directorios y vhosts si procede
- Intentar en todos los campos que proceda inyectar comandos (sqli, xss,)
- Intentar path traversal
- Intentar LFI/RFI, especialmente en parámetros url