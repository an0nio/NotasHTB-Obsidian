

## 🔢 Puerto 445 / 139 → SMB

  

**Protocolo:** SMB / NetBIOS

**Herramientas y ejemplos:**

  

- `smbclient`

```bash

smbclient -L //$target -N

```

  

- `enum4linux`

```bash

enum4linux $target

```

  

- `crackmapexec`

```bash

crackmapexec smb $target --shares --users --pass-pol

```

  

- `rpcclient`

```bash

rpcclient -U "" $target

> enumdomusers

```

  

- `nmblookup`

```bash

nmblookup -A $target

```

  

**Qué puedes enumerar sin credenciales:**

- Shares públicas

- Usuarios y grupos (si null session)

- SID del dominio

- Nombre NetBIOS

- Políticas de contraseñas

- Archivos expuestos

  

---

  

## 🔢 Puerto 135 → RPC (MS-RPC sobre SMB)

  

**Protocolo:** MS-RPC

**Herramientas y ejemplos:**


- `rpcclient`

```bash

rpcclient -U "" $target

> enumdomusers

> enumdomgroups

> querygroupmem RID

> srvinfo

```

  

- `enum4linux`

```bash

enum4linux $target

```

  

- `crackmapexec`

```bash

crackmapexec smb $target --users

```

  

**Qué puedes enumerar sin credenciales:**

- Usuarios y grupos

- Miembros de grupos

- SID del dominio

- Información del sistema

- Políticas de contraseñas

  

---

  

## 🔢 Puerto 389 / 636 → LDAP / LDAPS

  

**Protocolo:** LDAP

**Herramientas y ejemplos:**

  

- `ldapsearch`

```bash

ldapsearch -x -H ldap://$target -b "DC=dominio,DC=local"

```

  

- `windapsearch`

```bash

windapsearch -d dominio.local -B

```

  

- `nmap`

```bash

nmap -p 389 --script "ldap* and not brute" $target

```

  

- `crackmapexec`

```bash

crackmapexec ldap $target

```

  

**Qué puedes enumerar sin credenciales (si permite bind anónimo):**

- Usuarios del dominio

- OUs, máquinas

- Atributos como `mail`, `description`

- Estructura del dominio

- Relaciones de confianza

  

---

  

## 🔢 Puerto 88 → Kerberos

  

**Protocolo:** Kerberos

**Herramientas y ejemplos:**

  

- `kerbrute`

```bash

kerbrute userenum --dc $target -d dominio.local users.txt

```

  

- `GetNPUsers.py`

```bash

GetNPUsers.py dominio.local/ -no-pass -usersfile users.txt -dc-ip $target

```

  

- `crackmapexec`

```bash

crackmapexec kerberos $target -u users.txt

```

  

**Qué puedes hacer sin credenciales:**

- Enumerar usuarios válidos

- Realizar AS-REP roasting

- Validar nombres de usuario

  

---

  

## ✅ Tabla resumen

  

| Puerto | Servicio | Herramientas clave | Enumeración sin credenciales |

|--------|----------|--------------------|-------------------------------|

| 445 | SMB | smbclient, enum4linux, rpcclient, crackmapexec | ✅ |

| 135 | RPC | rpcclient, enum4linux, crackmapexec | ✅ (si null session) |

| 389 | LDAP | ldapsearch, windapsearch, crackmapexec, nmap | ✅ (si bind anónimo) |

| 88 | Kerberos | kerbrute, GetNPUsers.py, crackmapexec | ✅ |