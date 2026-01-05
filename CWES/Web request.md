## HTTP
### URL - Uniform Resource Locator
**FQDN** identifica unívocamente un host en el DNS.  
Una **URL** define cómo y dónde acceder a un recurso (incluye el host).  
Aunque el campo **host** de una URL puede coincidir con un FQDN, no siempre es un FQDN estricto, ya que puede contener representaciones ambiguas o no-DNS como:  
`example.com@127.0.0.1`, `example.com.attacker.net`, `example.com.`, `[::1]`, `localhost`, `%00`, `%2e`.

![[Pasted image 20260104200126.png]]

|**Component**|**Example**|**Description**|
|---|---|---|
|`Scheme`|`http://` `https://`|This is used to identify the protocol being accessed by the client, and ends with a colon and a double slash (`://`)|
|`User Info`|`admin:password@`|This is an optional component that contains the credentials (separated by a colon `:`) used to authenticate to the host, and is separated from the host with an at sign (`@`)|
|`Host`|`inlanefreight.com`|The host signifies the resource location. This can be a hostname or an IP address|
|`Port`|`:80`|The `Port` is separated from the `Host` by a colon (`:`). If no port is specified, `http` schemes default to port `80` and `https` default to port `443`|
|`Path`|`/dashboard.php`|This points to the resource being accessed, which can be a file or a folder. If there is no path specified, the server returns the default index (e.g. `index.html`).|
|`Query String`|`?login=true`|The query string starts with a question mark (`?`), and consists of a parameter (e.g. `login`) and a value (e.g. `true`). Multiple parameters can be separated by an ampersand (`&`).|
|`Fragments`|`#status`|Fragments are processed by the browsers on the client-side to locate sections within the primary resource (e.g. a header or section on the page).|

