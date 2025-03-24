### **🛠️ Enumeración de vulnerabilidades**

| **Comando**                       | **Descripción**                                                                                             |
| --------------------------------- | ----------------------------------------------------------------------------------------------------------- |
| `Invoke-AllChecks`                | Ejecuta **todas las pruebas** de PowerUp para detectar posibles escalaciones.                               |
| `Get-ModifiablePath`              | Encuentra **directorios donde el usuario puede escribir** (potencial DLL hijacking o binario reemplazable). |
| `Get-ModifiableFile`              | Lista **archivos modificables** por el usuario en rutas críticas.                                           |
| `Get-ModifiableService`           | Busca **servicios vulnerables** a modificación de configuración.                                            |
| `Get-ModifiableServiceFile`       | Encuentra archivos de servicio que el usuario puede modificar (**Binary Hijacking**).                       |
| `Find-PathDLLHijack`              | Busca rutas vulnerables a **DLL Hijacking**.                                                                |
| `Get-UnquotedService`             | Detecta servicios con **rutas sin comillas** (Unquoted Service Paths).                                      |
| `Get-ModifiableRegistryAutoRun`   | Busca claves **AutoRun modificables** en el Registro para persistencia/escalación.                          |
| `Get-ModifiableScheduledTaskFile` | Identifica **tareas programadas** con archivos modificables.                                                |

---

### **🚀 Explotación y persistencia**

|**Comando**|**Descripción**|
|---|---|
|`Invoke-ServiceAbuse`|Modifica la configuración de un **servicio vulnerable** para ejecutar comandos maliciosos.|
|`Write-ServiceBinary`|Reemplaza el **binario de un servicio modificable** para ejecutar código malicioso.|
|`Write-HijackDll`|Genera una **DLL maliciosa** para explotar una ruta vulnerable (DLL Hijacking).|
|`New-ServiceBinary`|Crea un **nuevo servicio malicioso** con permisos elevados.|

---

💡 **📢 Tip:** Para ejecutar un análisis rápido de escalación de privilegios:

```powershell
Invoke-AllChecks -Verbose
```
 