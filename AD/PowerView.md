import#powerview
[chuleta interesante](https://elhacker.info/Cursos/Applied-Purple-Teaming/9-Others/Cheatsheets/PowerView.pdf)

## Uso 
```powershell
Import-Module .\PowerView.ps1
```
## **Comandos y Descripción (PowerView y AD Enumeration)**

| **Comando**           | **Descripción**                                                                |
| --------------------- | ------------------------------------------------------------------------------ |
| `Export-PowerViewCSV` | Agrega los resultados a un archivo CSV.                                        |
| `ConvertTo-SID`       | Convierte un nombre de usuario o grupo a su valor SID.                         |
| `Get-DomainSPNTicket` | Solicita el ticket Kerberos para una cuenta con un nombre de SPN especificado. |
## **Funciones de Dominio/LDAP:**

| **Comando**                 | **Descripción**                                                                                    |
| --------------------------- | -------------------------------------------------------------------------------------------------- |
| `Get-Domain`                | Devuelve el objeto del dominio actual (o especificado).                                            |
| `Get-DomainController`      | Devuelve una lista de Controladores de Dominio (DC) para el dominio especificado.                  |
| `Get-DomainUser`            | Devuelve todos los usuarios o un usuario específico en Active Directory (AD).                      |
| `Get-DomainComputer`        | Devuelve todas las computadoras o una computadora específica en AD.                                |
| `Get-DomainGroup`           | Devuelve todos los grupos o un grupo específico en AD.                                             |
| `Get-DomainOU`              | Busca todas las Unidades Organizativas (OUs) o una específica en AD.                               |
| `Find-InterestingDomainAcl` | Encuentra ACLs en el dominio con derechos de modificación asignados a objetos que no son internos. |
| `Get-DomainGroupMember`     | Devuelve los miembros de un grupo de dominio específico.                                           |
| `Get-DomainFileServer`      | Devuelve una lista de servidores que probablemente funcionen como servidores de archivos.          |
| `Get-DomainDFSShare`        | Devuelve una lista de sistemas de archivos distribuidos (DFS) del dominio actual o especificado.   |
## **Funciones de Políticas de Grupo (GPO):**

| **Comando**        | **Descripción**                                                               |
| ------------------ | ----------------------------------------------------------------------------- |
| `Get-DomainGPO`    | Devuelve todas las GPOs o una GPO específica en AD.                           |
| `Get-DomainPolicy` | Devuelve la política predeterminada del dominio o del controlador de dominio. |

## **Funciones de Enumeración de Computadoras:**

| **Comando**                 | **Descripción**                                                                         |
| --------------------------- | --------------------------------------------------------------------------------------- |
| `Get-NetLocalGroup`       | Enumera los grupos locales en la máquina local o remota.                                |
| `Get-NetLocalGroupMember` | Enumera los miembros de un grupo local específico.                                      |
| `Get-NetShare`            | Devuelve los recursos compartidos abiertos en la máquina local o remota.                |
| `Get-NetSession`          | Devuelve información de sesiones activas en la máquina local o remota.                  |
| `Test-AdminAccess`        | Verifica si el usuario actual tiene acceso administrativo a una máquina local o remota. |
## **Funciones de Meta (Multihilo):**

| **Comando**                         | **Descripción**                                                                                       |
| ----------------------------------- | ----------------------------------------------------------------------------------------------------- |
| `Find-DomainUserLocation`         | Encuentra máquinas donde están conectados usuarios específicos.                                       |
| `Find-DomainShare`                | Encuentra recursos compartidos accesibles en máquinas del dominio.                                    |
| `Find-InterestingDomainShareFile` | Busca archivos que cumplan criterios específicos en recursos compartidos accesibles.                  |
| `Find-LocalAdminAccess`           | Encuentra máquinas en el dominio local donde el usuario actual tiene acceso como administrador local. |

## **Funciones de Confianza de Dominio:**

| **Comando**                    | **Descripción**                                                              |
| ------------------------------ | ---------------------------------------------------------------------------- |
| `Get-DomainTrust`              | Devuelve las relaciones de confianza del dominio actual o especificado.      |
| `Get-ForestTrust`              | Devuelve todas las relaciones de confianza entre bosques (forests).          |
| `Get-DomainForeignUser`        | Enumera usuarios que pertenecen a grupos fuera de su dominio.                |
| `Get-DomainForeignGroupMember` | Enumera grupos que contienen miembros de otros dominios.                     |
| `Get-DomainTrustMapping`       | Enumera todas las relaciones de confianza del dominio actual y otros vistos. |

