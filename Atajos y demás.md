- Crear un archivo urlencodeado a partir de otro: 
```bash
while IFS= read -r linea; do echo "$linea" | jq -sRr @uri; done < archivo > archivo_urlencodeado
```
- Saber si está corriendo powershell ó cmd
	```powershell
	(dir 2>&1 *`|echo CMD);&<# rem #>echo PowerShell
	```
- Saber si una llave SSH tiene el formato correcto
```bash
ssh-keygen -lf id_rsa
# Generar la clave pública a partir de la privada
ssh-keygen -y -f id_rsa > id_rsa.pub
```
- [FullTTY](https://hacktricks.boitatech.com.br/shells/shells/full-ttys)