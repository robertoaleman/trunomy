# Guía de inicio rápido

De un clon limpio a una sesión de Trunomy OS en QEMU, con cada comando y lo que debes ver. Si algo difiere, `./trunomy check` (o la sección "Si algo falla") te dice por qué.

> Trunomy es un prototipo de investigación, sin auditoría independiente. No lo uses con datos reales.

Convenciones: `$` es tu terminal; `λ [Trunomy] >` es el prompt de la shell dentro de QEMU. Los números marcados con `…` (pids, ids de tenant, handles, marcos libres) cambian de una ejecución a otra; lo que importa es la forma del resultado.

## 1. Instalar

Necesitas `rustup` (el toolchain está fijado en `rust-toolchain.toml`), `openssl` con Ed25519, `objcopy`/`readelf` (binutils), `dosfstools` + `mtools`, y QEMU + OVMF para arrancar.

```bash
# AlmaLinux / Fedora
sudo dnf install -y binutils openssl dosfstools mtools qemu-kvm edk2-ovmf git
# Debian / Ubuntu
sudo apt install -y binutils openssl dosfstools mtools qemu-system-x86 ovmf git
# Rust (si no lo tienes)
curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh
```

```bash
git clone https://github.com/robertoaleman/trunomy-experimental.git
cd trunomy-experimental
./trunomy check
```

`check` lista cada herramienta, el toolchain, las claves y QEMU con `[OK]`, `[WARN]` o `[MISSING]`. No sigas hasta que no quede ningún `[MISSING]` en herramientas y toolchain (QEMU y OVMF solo hacen falta para arrancar). En una copia nueva las claves de firma aparecen como `[WARN]`: `./trunomy build` te ofrece generar las tuyas en su primera etapa.

## 2. Compilar y arrancar

```bash
./trunomy up
```

Hace, en este orden: comprobar la máquina, compilar y firmar el bootloader, la shell y el kernel, escribir `trunomy.img` y arrancarlo en QEMU. Cada etapa dice qué hace y por qué; la salida de cargo queda en `target/build-logs/` y solo se muestra si algo falla (`--verbose` la muestra siempre). La compilación debe terminar **sin avisos**.

Trunomy solo ejecuta código firmado y el repositorio no trae claves privadas. En un clon nuevo el build te ofrece generar las tuyas; `./build_os.sh --own-keys` lo hace sin preguntar. Esas claves son tuyas: la cadena de confianza resultante no la comparte nadie más.

Al arrancar, el final del registro debe verse así (las direcciones PCI y los números pueden variar):

```text
[KERNEL] W^X image: text pages R-X=0x… rodata R--=0x… data RW-=0x…
[KERNEL] Timer: PIT divisor 0x… (100 Hz), PIC remapped to 0x20, only IRQ0 enabled
[KERNEL] Console: COM1 via IRQ4 (1-byte FIFO), blocking reads
[KERNEL] Network: virtio-net at PCI 00:02.0 MAC 52:54:00:12:34:56 link up (negotiated: inactive until `net up`)
[KERNEL] Scheduler: 0x…02 tasks, quantum 5 ticks; entering Ring 3...
Welcome to Trunomy OS - True Zero Trust CLI v0.1.0
λ [Trunomy] >
```

Después del prompt aparecen puntos `.` (uno por segundo): es la segunda tarea del planificador y confirma que la multitarea corre.

**Salir de QEMU:** `Ctrl-A` y luego `X`. Para volver a arrancar sin recompilar: `./trunomy run`.

Variables de `run`: `QEMU=/ruta/qemu`, `OVMF_CODE=/ruta/OVMF_CODE.fd` si no los detecta, y `NET=0` para arrancar sin tarjeta de red.

### Versión de seguridad del kernel (rollback)

Cada kernel lleva una versión de seguridad firmada junto con él (`config/security-version`, un entero; `./trunomy build` la firma y escribe `kernel_x86_64.elf.ver` en la imagen). El bootloader guarda en una variable UEFI no volátil la mayor versión aceptada y se niega a arrancar un kernel firmado pero **más antiguo** (`ROLLBACK REJECTED`). Sube el número a propósito (`echo 2 > config/security-version`) al publicar una corrección: `ci.sh security-version` falla si baja respecto al commit anterior.

En QEMU la variable solo persiste si le das un NVRAM de verdad (`OVMF_VARS=copia-de-OVMF_VARS.fd ./trunomy run`); sin él, `./trunomy run` arranca igual y el bootloader avisa de que no pudo guardar el mínimo. `python3 scripts/rollbacktest.py` hace el recorrido completo (arranca N+1, rechaza N, rechaza un `.ver` editado, vuelve a arrancar N+1 y muestra que con el NVRAM borrado el kernel viejo arranca: el límite que documenta I-49). Trabaja sobre copias y necesita `mtools`, `openssl` y `.keys/`.

## 3. Primer recorrido (como root)

Escribe `help` para ver todos los comandos. Los de estado leen el kernel, no un texto fijo:

| Comando | Qué debes ver |
|---|---|
| `whoami` | `name: root` y una línea `pid=1 tenant=… subject=1` |
| `id` | `pid=1 tenant=… subject=1` |
| `caps` | las capabilities de root, separadas por `;` (por ejemplo `object.create; …`) |
| `free` | `frames: … KiB free of … KiB \| kernel heap: … KiB used of … KiB` |
| `ps` | una línea `pid=… parent=… running` por proceso; el primero es el líder (`pid=1`) |
| `uptime` | `up N.NN s (… ticks)` |
| `net info` | `net: virtio-net 1af4:1000 pci 00:02.0 mac 52:54:00:12:34:56 link up \| negotiated: inactive (net up)` |
| `status` / `version` | `Trunomy OS v0.1.0` y el estado de los módulos |

Ejecuta `free` dos veces seguidas: los marcos libres no deben bajar (sin fugas de memoria).

### Editar la línea e histórico

La consola tiene un editor de línea mínimo (I-50). Se escribe siempre al final de la línea: **las flechas izquierda/derecha, Inicio, Fin y Supr no mueven nada** (no puedes salir de la línea ni pisar el prompt), y solo se aceptan caracteres ASCII imprimibles.

| Tecla | Qué hace |
|---|---|
| `↑` / `↓` | recorre las últimas 16 órdenes (↓ pasada la más reciente deja la línea vacía) |
| Retroceso | borra el último carácter tecleado (con la línea vacía no hace nada) |
| `Ctrl-U` | borra la línea entera |
| `Ctrl-C` | cancela la línea y vuelve al prompt |

Una orden recordada con `↑` se puede editar (retroceso y seguir escribiendo) antes de pulsar Enter. El histórico no guarda líneas vacías ni la misma orden dos veces seguidas, vive solo en la RAM del kernel (se pierde al apagar) y pertenece a la consola, no a una identidad: tras `su bob`, `↑` también muestra lo que escribió root. Cada entrada se borra con ceros antes de reutilizarse, porque una orden puede llevar un secreto (`object create clave …`). `python3 scripts/linetest.py` lo comprueba en QEMU (`linetest: OK`).

## 4. La demo de seguridad

```text
λ [Trunomy] > demo
```

Ejecuta 18 comandos y al final `audit`. Dos tenants (`acme`, `evil`); `alice` y `bob` en `acme`, `mallory` en `evil`. Qué debes ver, en orden:

1. alice crea `secret` (`ok handle=…`) y le da a bob `read` (`ok granted`).
2. bob lee `secret`: **permitido**, muestra `hello-world`.
3. bob intenta escribir: `denied: PermissionDenied` (READ no se convierte en WRITE).
4. mallory copia el handle crudo de alice (`copied raw handle (the kernel decides)`) y lo usa: **denegado** (conocer el handle no es tener autoridad).
5. alice revoca (`ok revoked`).
6. bob vuelve a leer: `denied: RevokedCapability`.
7. `audit` imprime las decisiones del kernel: líneas `#N subject=… tenant=… … -> allowed` y `-> DENIED <error>`.

## 5. Probar a mano

> **Antes de empezar:** el estado vive en RAM y los usuarios no se pueden modificar después de crearlos (ni darles `ipc` a posteriori). Si ya corriste `demo` o probaste otros nombres, reinicia QEMU (`Ctrl-A`, `X`, luego `./trunomy run`) para partir de cero, o usa nombres nuevos; `user exists` / `tenant exists` significan que ese nombre ya está usado.

Los nombres son comodidad de la shell; el kernel solo ve handles e identidades. Cada operación de un usuario corre en un proceso nuevo con su identidad (`su <user>` solo elige en nombre de quién se ejecuta lo siguiente).

**Tenants y usuarios**

```text
λ [Trunomy] > tenant create acme
tenant acme id=…
λ [Trunomy] > user create alice acme
user alice pid=… tenant=acme
λ [Trunomy] > tenant list
```

`tenant list` (solo root) imprime una tabla ASCII leída del kernel: una fila por capability, con los datos de la entidad en su primera línea y una línea separadora entre entidades.

```text
+-------------+-------------------------+------+------------------------+
| Tenant ID   | Entity (Role / User)    | PID  | Permissions / Capabilities |
+-------------+-------------------------+------+------------------------+
| 1           | root (session leader)   | 1    | pipe.create            |
|             |                         |      | metadata.read          |
|             |                         |      | …                      |
+-------------+-------------------------+------+------------------------+
| 1000 acme   | alice                   | 1000 | object.create          |
+-------------+-------------------------+------+------------------------+
```

La columna Tenant ID lleva el id y el nombre que le dio el shell; los marcadores `[FROZEN]` (tenant congelado) y `[retired]` (usuario retirado) aparecen en su celda.

**Objetos y capabilities**

```text
λ [Trunomy] > su alice
λ [Trunomy] > object create nota hola
ok handle=…
λ [Trunomy] > ls
no filesystem: objects are capabilities. Handles named by this identity:
  nota
λ [Trunomy] > cap grant bob nota read 2
ok granted
```

`cap grant <user> <nombre> <derechos> [usos]`: derechos `read`, `write`, `delegate` separados por coma; `usos` limita cuántas veces se puede usar. `object read|write|delete <nombre>` y `cap revoke <nombre>` completan el ciclo. Un nombre sin handle da `no handle for that name`.

**Denegaciones esperadas**

| Intento | Resultado |
|---|---|
| un usuario ejecuta `ps`, `tenant list` o `net info` | `denied: PermissionDenied` |
| un usuario ejecuta `halt` | `denied: PermissionDenied` (queda en `audit`) |
| un usuario ejecuta `audit` | `denied: PermissionDenied` (solo el líder lee la auditoría: `su root`) |
| `su root` y `audit` | los registros nuevos desde la última lectura, o `(no new records)` |

**IPC entre usuarios.** La autoridad IPC (`ipc.send` / `ipc.recv`) solo existe si se pide **al crear** el usuario, y solo funciona dentro del mismo tenant. Por eso este ejemplo crea usuarios nuevos (`ana`, `beto`, `eve`) con `ipc`; no sirven `alice` ni `bob` si los creaste sin él. Root tampoco tiene `ipc.send`: un `ipc send` como root da `denied: InvalidCapability`, y es lo correcto.

```text
λ [Trunomy] > user create ana acme ipc
user ana pid=… tenant=acme ipc
λ [Trunomy] > user create beto acme ipc
user beto pid=… tenant=acme ipc
λ [Trunomy] > tenant create evil
λ [Trunomy] > user create eve evil ipc
λ [Trunomy] > su ana
λ [ana] > ipc send beto hola
ok sent
λ [ana] > su beto
λ [beto] > ipc recv
hola
λ [beto] > ipc recv
(no messages)
λ [beto] > su eve
λ [eve] > ipc send ana x
denied: PermissionDenied
λ [eve] > su root
λ [Trunomy] > audit
```

`audit` debe mostrar una línea `ipc -> DENIED …` para eve. Para comprobar qué autoridad tiene cada uno, `tenant list` (como root) muestra `ipc.send` e `ipc.recv` solo bajo los usuarios creados con `ipc`.

| Intento | Resultado |
|---|---|
| enviar desde un usuario creado **sin** `ipc` | `denied: InvalidCapability` |
| enviar desde root | `denied: InvalidCapability` |
| enviar a un usuario de otro tenant | `denied: PermissionDenied` (y queda en `audit`) |
| mensaje de más de 32 bytes | `message too long (max 32 bytes)` |

**Corte de emergencia de un tenant (`tenant panic`).** `halt` apaga toda la máquina; esto corta solo a un tenant comprometido y deja trabajar a los demás. Solo root puede. Con los usuarios del ejemplo de IPC (`eve` en `evil`, `ana` y `beto` en `acme`):

```text
λ [Trunomy] > tenant panic evil
tenant evil PANIC: 0 processes killed, 3 capabilities revoked, 0 objects wiped
tenant frozen; its users are retired (tenant thaw allows NEW users)
λ [Trunomy] > tenant list
…
| 1001 evil [FROZEN] | eve [retired]           | 1002 | (no capabilities)      |
…
λ [Trunomy] > su eve
λ [eve] > whoami
denied: PermissionDenied
λ [eve] > su ana
λ [ana] > ipc send beto hola
ok sent
λ [ana] > tenant panic acme
denied: PermissionDenied
λ [ana] > su root
λ [Trunomy] > audit
```

Qué comprueba cada paso: se revocan **todas** las capabilities de `eve` (la cifra depende de lo que haya hecho; aquí `object.create`, `ipc.send` e `ipc.recv`); `eve` ya no puede lanzar nada; `acme` sigue funcionando con normalidad; un usuario no puede cortar a nadie. `audit` debe mostrar `panic -> allowed` (el corte), `identity -> DENIED PermissionDenied` (el intento de lanzar a `eve`) y `panic -> DENIED PermissionDenied` (el intento de `ana`).

- `tenant panic <nombre> wipe` además borra los objetos del tenant (con puesta a cero); sin `wipe` quedan inalcanzables pero no destruidos.
- `tenant thaw evil` reabre el tenant solo para usuarios **nuevos** (`user create eve2 evil` funciona); `eve` sigue retirada y sin capabilities.
- Los nombres de usuarios retirados siguen ocupados hasta reiniciar QEMU.

## 6. Contención de fallos

Las pruebas de `selftest` corren en un worker con identidad de usuario (no como root) y comprueban que el kernel contiene el fallo y la shell sigue viva:

```text
λ [Trunomy] > su bob
λ [Trunomy] > selftest fault
worker terminated by the kernel: <excepción>
contained: the shell is still alive
```

| Prueba | Qué simula | Resultado esperado |
|---|---|---|
| `selftest fault` | acceso a memoria inválida | terminado por el kernel (page fault), shell viva |
| `selftest ud` | instrucción inválida | terminado (#UD), shell viva |
| `selftest hang` | bucle infinito | `cpu quota exceeded` (o `timed out`), shell viva |
| `selftest stack` | desbordar la pila | terminado por el kernel, shell viva |
| `selftest console` | usar la consola sin capability | `denied: InvalidCapability`, queda en `audit` |

Tras cada una, `free` como root debe mostrar los mismos marcos libres que antes: el kernel recupera lo del worker.

## 7. Red (solo en QEMU)

El kernel descubre un virtio-net legacy y lo negocia, pero lo deja **inactivo**: sin DMA hasta que el líder lo pida.

```text
λ [Trunomy] > net info                 (root)
net: virtio-net 1af4:1000 pci 00:02.0 mac 52:54:00:12:34:56 link up | negotiated: inactive (net up)
λ [Trunomy] > net up
net up: queues registered, bus master on (net selftest checks it end to end)
λ [Trunomy] > net selftest
net selftest: OK (ARP reply from the gateway 10.0.2.2: send and receive work)
λ [Trunomy] > net stats
net stats: tx 1 rx 1 | tx full 0 rx dropped 0 | queues ok
λ [Trunomy] > net down
net down: bus master off, device reset, queue memory wiped and returned
```

`net up` hace en el kernel, en este orden: construir y validar las dos colas, registrarlas, y solo entonces encender el bus master y `DRIVER_OK`. `net selftest` envía un ARP real al gateway de QEMU y espera su respuesta: es la prueba de extremo a extremo (necesita `-netdev user`, que ya trae `run_os.sh`; con `NET=0` falla). Tras `net down`, `free` debe mostrar los mismos marcos libres que antes de `net up`. Con la red en marcha, `net info` termina en `ACTIVE (queues registered, bus master on)`.

Un usuario no puede nada de esto:

```text
λ [Trunomy] > su bob
λ [bob] > net up
denied: PermissionDenied
```

La denegación queda en `audit` (operación `net`). Si `net selftest` falla, mira `net stats`: `QUEUE POISONED` significa que el dispositivo mintió sobre sus colas y el kernel dejó de usarlas.

### Red entre actores

La red de los actores exige una capability global: se concede al crear el usuario con `net`. Cada puerto lo posee el proceso que lo liga; los demás no pueden usarlo.

```text
λ [Trunomy] > net up                              (root; sin esto no hay MAC ni dispositivo)
λ [Trunomy] > tenant create lab
λ [Trunomy] > user create nora lab net
user nora pid=… tenant=lab net
λ [Trunomy] > user create omar lab
λ [Trunomy] > su nora
λ [nora] > net loopback hola
from 52:54:00:12:34:56 port 40001: hola
net loopback: OK (sent to this machine and received through the kernel)
λ [nora] > su omar
λ [omar] > net loopback hola
denied: InvalidCapability
λ [omar] > su root
λ [Trunomy] > audit
```

`net loopback` liga dos puertos de `nora`, se envía a sí misma (MAC `self`) y recibe por el kernel: prueba sintaxis, capabilities, dueño de puerto y colas sin otro extremo. En `audit` debe aparecer `net DENIED` para `omar`. `net stats` suma los descartes del protocolo (tramas mal formadas, con MAC ajena o sin dueño); en QEMU `-netdev user` verás subir esa cifra con el tráfico ajeno (ARP, DHCP) que el protocolo de Trunomy descarta a propósito.

Otros comandos de usuario con `net`: `net listen <puerto> [1]` espera como mucho ~1 s un mensaje en ese puerto y lo muestra, y `net send <origen> <mac|self|bcast> <destino> <texto>` envía una trama (`mac` = `aa:bb:cc:dd:ee:ff`). Un puerto vive lo que dura el comando: el usuario corre en un proceso corto que muere al terminar, y entonces el kernel cierra sus puertos. `tenant panic lab` también los cierra.

#### Demo guiada: `net demo`

Si solo quieres ver qué hace la red, no tienes que teclear nada de lo anterior: como root, `net demo` lo recorre entero dentro del shell, con una línea `# …` que explica cada paso antes del comando real (`> …`).

```text
λ [Trunomy] > net demo
# 1. Only root turns the NIC on. The kernel validates the device, then enables DMA (I-44).
> net up
…
# 2. Real traffic: an ARP request to the QEMU gateway 10.0.2.2 and its reply, through the queues.
> net selftest
net selftest: OK (ARP reply from the gateway 10.0.2.2: send and receive work)
…
# 6. omar has no network authority. The kernel denies both directions, even for his own tenant.
> su omar
> net send 40001 bcast 7 intruder
denied: InvalidCapability
> net listen 7
denied: InvalidCapability
```

Los pasos: red activa, ARP real contra el gateway, `nora` (con `net`) y `omar` (sin `net`) en el tenant `netlab`, bucle local de `nora` por el kernel, una trama real a la red (`ok` = la NIC la aceptó; nadie confirma la entrega: no hay TCP/IP), `omar` denegado al enviar y al escuchar, y al final `net stats` y `audit` con las denegaciones. Se puede repetir (reutiliza `netlab`, `nora` y `omar`). El demo no decide nada: cada paso es el comando normal y el veredicto es del kernel. Deja la red encendida; `net down` la apaga. Sin NIC (`NET=0`) lo dice y se detiene. `python3 scripts/netdemotest.py` lo corre en QEMU y comprueba la salida (`netdemotest: OK`).

#### Tramas reales desde el host

`scripts/nettest.py` arranca el sistema con un backend `-netdev socket,udp=…` (variable `NETDEV` de `run_os.sh`): cada trama del invitado llega al script como un datagrama UDP y cada datagrama del script llega al invitado como trama. El script es una segunda implementación del protocolo, escrita desde la especificación, así que contrasta el kernel con algo que no es su propio código.

```text
$ ./trunomy build            (hace falta trunomy.img)
$ python3 scripts/nettest.py --transcript /tmp/nettest.log
  ok   net send responde ok
  ok   el host recibe una trama Trunomy
  ...
nettest: OK
```

Comprueba: lo que el invitado emite (MAC, puertos, carga, relleno), que un usuario sin `net.send` no emite nada, que `net listen` recibe unicast y difusión del host, que once tramas hostiles (una regla rota cada una) no se entregan y quedan contadas, que un puerto sin dueño cuenta como descarte, y que tras una inundación las colas siguen sanas y se sigue recibiendo. El invitado no avisa cuando empieza a escuchar, así que el host reenvía la trama durante la ventana de `net listen`. `python3 scripts/nettest.py --selftest` prueba solo el codec, sin QEMU. Si algo falla, `--transcript` guarda todo lo que imprimió el invitado.

#### Dos VMs enlazadas

`scripts/nettest2.py` arranca dos VMs a la vez con sus backends `-netdev socket,udp` apuntados entre sí (cada una con su MAC, `NETMAC`, y en modo `SNAPSHOT=1` para compartir `trunomy.img` sin escribirla), crea un tenant `lab` con `nora` (con `net`) y `omar` (sin `net`) en cada una y comprueba: A→B y B→A con la MAC del otro extremo mostrada solo como dato, 128 bytes intactos, una trama para una tercera MAC que no llega, denegación sin `net.recv`/`net.send`, 10 mensajes seguidos y colas sanas. Termina con `nettest2: OK`; `--transcript-dir DIR` guarda lo que imprimió cada VM. Como el receptor no avisa cuando empieza a escuchar, el script reintenta el par `net listen`/`net send`.

Para hacerlo a mano: dos terminales con `NETMAC=52:54:00:12:34:56 SNAPSHOT=1 NETDEV="socket,udp=127.0.0.1:5001,localaddr=127.0.0.1:5000" ./run_os.sh` y `NETMAC=52:54:00:12:34:58 SNAPSHOT=1 NETDEV="socket,udp=127.0.0.1:5000,localaddr=127.0.0.1:5001" ./run_os.sh`; en cada una `net up`, y en B `net listen 7` mientras en A `net send 40001 52:54:00:12:34:58 7 hola`.

Sin tarjeta: `NET=0 ./trunomy run` y `net info` da `net: no device`. Si ves `no usable … disable-modern=on`, QEMU presentó un virtio moderno: `run_os.sh` ya pasa `disable-modern=on`; si usas tu propia línea de QEMU, añádelo.

Aún no hay autoridad de red para los tenants: solo el líder maneja el dispositivo. Qué no valida QEMU: DMA, IOMMU y tiempos reales de dispositivo. Esas garantías esperan hardware real (ver `docs/invariants.md`, I-44).

## 8. Pruebas en el host

No arrancan nada; son rápidas y no necesitan QEMU.

```bash
./trunomy test            # pruebas unitarias de todos los crates
./scripts/ci.sh docs      # cada invariante I-16+ tiene su fila de trazabilidad
./scripts/ci.sh keys      # claves de kernel y shell aprovisionadas, no nulas y distintas
./scripts/ci.sh baremetal # compila bootloader, shell y kernel para sus targets reales
./scripts/ci.sh all       # todo lo anterior (+ toolchain y lock)
```

`ci.sh all` termina con `[OK] todo en verde`; cualquier aviso del compilador cuenta como fallo. Los objetivos sueltos son `lock`, `toolchain`, `host`, `baremetal`, `docs` y `keys`.

Reproducibilidad: compila dos clones limpios y compara los hashes.

```bash
./trunomy verify
```

Debe terminar con `[OK] build reproducible` y los cuatro artefactos (`kernel`, `shell`, `shell.bin`, `.efi`) como `SAME`. Funciona también en un árbol sin `.git` (un `.zip` descomprimido): compila dos copias del directorio, sin `.git`, `target/` ni `.keys/`. Detalle en `docs/reproducible-demo.md`.

## 9. Lista de comprobación

| Paso | Comando | Resultado |
|---|---|---|
| Máquina lista | `./trunomy check` | sin `[MISSING]` |
| Compila sin avisos | `./trunomy build` | termina sin avisos |
| Arranca | `./trunomy run` | prompt `λ [Trunomy] >` y puntos `.` |
| Red | log de arranque / `net info` | virtio-net negociado, inactivo |
| Autoridad | `demo` | permitido / `PermissionDenied` / denegado / `RevokedCapability` / `audit` |
| IPC | sección 5 | `ok sent`, `hola`, `(no messages)`, denegación de eve |
| Contención | `selftest …` como usuario | worker terminado, shell viva, sin fugas |
| Red entre actores | `net loopback hola` como un usuario con `net` | `from …: hola`; sin `net`: `denied: InvalidCapability` |
| Corte de tenant | `tenant panic evil` | `PANIC: … revoked`, `[FROZEN]`/`[retired]`, `acme` intacto |
| Red desde el host | `python3 scripts/nettest.py` | `nettest: OK` |
| Red entre dos VMs | `python3 scripts/nettest2.py` | `nettest2: OK` |
| Demo guiada de red | `net demo` en el shell, o `python3 scripts/netdemotest.py` | recorrido de 7 pasos; `netdemotest: OK` |
| Editor de línea | `python3 scripts/linetest.py` (o `↑`/`←` a mano en el prompt) | `linetest: OK`; las flechas laterales no mueven el cursor, `↑` recuerda órdenes |
| Auditoría acotada | `python3 scripts/audittest.py` | `audittest: OK` |
| Rollback | `python3 scripts/rollbacktest.py` | `rollbacktest: OK` |
| Pruebas | `./scripts/ci.sh all` | `[OK] todo en verde` |
| Reproducible | `./trunomy verify` | `[OK] build reproducible` |

## Si algo falla

| Síntoma | Causa y solución |
|---|---|
| `[ERROR] no encuentro QEMU` / `OVMF_CODE.fd` | instala `qemu-kvm`/`qemu-system-x86` y `edk2-ovmf`/`ovmf`, o `QEMU=… OVMF_CODE=… ./trunomy run` |
| `[ERROR] el compilador emitio N aviso(s)` | arréglalos o justifica un `#[allow]` con comentario; el CI exige cero avisos |
| `falta kernel_x86_64.elf.sig: no se carga (I-18)` | el bootloader rechaza un kernel sin firma: vuelve a correr `./trunomy build` |
| `[KERNEL_ERROR] … imagen sin descriptor de layout W^X` | la shell se compiló con un linker script viejo: `./trunomy build` |
| `falta kernel_x86_64.elf.ver: no se carga (I-49)` | la imagen es anterior al versionado del kernel: `./trunomy build` |
| `ROLLBACK REJECTED: … < minimum accepted …` | el NVRAM recuerda un kernel más nuevo que el de la imagen: reconstruye con la versión actual o, solo si es a propósito, restaura el NVRAM (`OVMF_VARS` nuevo) |
| `net: … found, not usable (modern virtio …)` | usa `disable-modern=on` (ya lo hace `run_os.sh`) |
| `denied: InvalidCapability` al hacer `ipc send` | el emisor se creó sin `ipc` (o es root): crea usuarios nuevos con `user create <n> <tenant> ipc` |
| `user exists` / `tenant exists` | ese nombre ya está usado en esta sesión: reinicia QEMU o usa otro |
| QEMU lento | sin `/dev/kvm` usa emulación; funciona, pero tarda más |
| `cargo audit` rojo en el workflow | es informativo; revisa el aviso en `docs/ci.md` |
