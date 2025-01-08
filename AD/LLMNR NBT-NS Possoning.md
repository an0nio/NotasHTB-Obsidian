#mitm #responder
## LLMNR/NBT-NS Possoning
[Link-Local Multicast Name Resolution](https://datatracker.ietf.org/doc/html/rfc4795) (LLMNR) and [NetBIOS Name Service](https://docs.microsoft.com/en-us/previous-versions/windows/it-pro/windows-2000-server/cc940063(v=technet.10)?redirectedfrom=MSDN) (NBT-NS) son métodos alternativos de resolución de nombres que pueden ser usados cuando falla el DNS. Cualquier host puede responder utilizando alguno de los protocolos mencionados. 
## Linux - `responder`
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
