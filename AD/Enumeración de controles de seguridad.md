## Microsoft Defender
- **Ver estado de Microsoft Defender:**
	```powershell
	Get-MpComputerStatus
	```

- **Ver protección en tiempo real:**
	```powershell
	(Get-MpComputerStatus).RealTimeProtectionEnabled
	Get-MpComputerStatus | Get-Member | ? {$_.name -like "*realtime*"}
	```

## AppLocker
Lista blanca de aplicaciones que se pueden utilizar en el sistema
-  [Ubicaciones  ejecutables PowerShell](https://www.powershelladmin.com/wiki/PowerShell_Executables_File_System_Locations)(puede que no todas las ubicaciones estén bloqueadas)
- **Ver políticas de AppLocker:**
	```
	Get-AppLockerPolicy -Effective | select -ExpandProperty RuleCollections
	```

- **Ver modo de lenguaje de PowerShell:**
	`FullLanguage` : sin restricciones. `ContstrainedLanguaje`: modo restringido
	```powershell
	$ExecutionContext.SessionState.LanguageMode
	```

## LAPS (Local Administrator Password Solution)
Aleatoriza cuentas de admin en Windows impidiendo movimiento lateral inmediato.
- **Ver OUs y grupos delegados con permisos LAPS:**
	Muestra OUs y grupos que tienen permisos para leer contraseñas gestionadas por LAPS
	```powershell
	Find-LAPSDelegatedGroups
	```

- **Ver usuarios con permisos extendidos de lectura (LAPS):**
	Muestra grupos o usuarios con permisos del tipo `All Extended Rights`, que permite leer contraseñas locales
	```powershell
	Find-AdmPwdExtendedRights
	Find-AdmPwdExtendedRights -Identity "NombreDelEquipo"
	```

- **Ver PCs con LAPS activado y leer contraseñas (si autorizado):**
	```powershell
	Get-LAPSComputers
	```