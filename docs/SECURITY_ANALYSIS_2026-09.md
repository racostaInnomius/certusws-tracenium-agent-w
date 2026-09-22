# Análisis de seguridad del agente — septiembre 2026

- **Fecha**: 2026-09-22 · **Versión revisada**: `main` en `e3919f8` (Bump 1.1.79)
- **Alcance**: `certusws-tracenium-agent-w` completo — AgentCore (`src/`), PrivSvc Windows (C#), PrivSvc Linux/macOS (TS), instaladores (`windows/`, `packaging/`, `privsvc/macos/pkg-scripts`), build.
- **Método**: revisión estática de código en seis superficies en paralelo, con evidencia `fichero:línea` para cada afirmación; los hallazgos críticos y altos los re-verifiqué a mano sobre el código. No hubo pruebas dinámicas ni explotación real: donde digo "explotable" es por lectura del código, no por demostración.
- **Fuera de alcance**: control plane y UI (salvo cuando el agente confía en ellos), apps móviles, PKI.

---

## 1. Veredicto

**El agente tiene una base de seguridad seria, mejor que la media de agentes de endpoint que he visto, y al mismo tiempo tres agujeros críticos y una decena de altos que hay que cerrar antes de vender el producto a un cliente con equipo de seguridad propio.**

Lo bueno no es cosmético: claves CNG no exportables en Windows, mTLS obligatorio en el DP, jaula de rutas con `realpath` y staging `O_EXCL|O_NOFOLLOW`, credenciales de vCenter cifradas extremo a extremo que el control plane no puede leer, `execFile` con argv en todo Linux/macOS, hash por fuente tras cada descarga, consentimiento que falla cerrado, escrituras de registro con lista de prefijos protegidos y todo-o-nada. Eso es diseño, no suerte.

Lo malo se concentra en **cuatro patrones**, no en cuarenta bugs sueltos:

| Patrón | Qué significa | Hallazgos |
|---|---|---|
| **El control plane es un adversario no contemplado** | Varias rutas ejecutan lo que el servidor diga como SYSTEM/root sin ninguna verificación que el agente pueda hacer por su cuenta | C-2, C-3, A-1, A-5, A-7, M-6 |
| **Verificar y ejecutar en momentos y directorios distintos** | Se comprueba la firma o el hash, y luego otro proceso ejecuta minutos después desde un directorio que un usuario puede escribir | A-2, A-4 |
| **Windows confía en los ACL por defecto de ProgramData y Temp** | `Users` puede crear ficheros ahí; el código lo sabe en cuatro sitios y lo olvida en los demás | A-2, A-3, A-4, A-6 |
| **Lo que da acceso remoto no exige prueba de autorización en el endpoint** | El agente acepta cualquier oferta de sesión, cualquier consentimiento y cualquier política que le llegue | A-6, A-7, A-8 |

**Madurez por área (0–5)**: transporte e identidad **3,5** · PrivSvc/IPC **3** · jobs y actualización **2,5** · Remote Control **2,5** · datos en disco y servicio: Windows **2,5**, Linux/macOS **3,5** · colectores y DP **4** · cadena de suministro **3**. **Global: 3/5.**

---

## 2. Modelo de amenaza usado

| Adversario | Qué tiene | Qué NO debería conseguir |
|---|---|---|
| **U** Usuario local sin privilegios / malware en su sesión | Ejecutar como el usuario en un equipo inscrito | SYSTEM/root; leer inventario ajeno o secretos del agente; aprobar sesiones remotas |
| **A** Administrador local | Todo en el equipo | Suplantar la identidad del equipo en otro; abrir el equipo a un operador sin que el usuario lo vea |
| **R** Atacante de red / LAN | MITM, ARP/DNS en la LAN, peers de DP | Hablar por el control plane; robar la identidad mTLS; inyectar binarios |
| **C** Control plane comprometido o impersonado | Mandar cualquier job/política | Ejecutar código arbitrario como SYSTEM en toda la flota sin una segunda verificación local |
| **O** Operador autenticado de RCP | Shell/ficheros/pantalla donde la política lo permita | Persistencia como SYSTEM; actuar sin rastro ni indicador |

Contexto que agrava **R** y **C**: la clave de la CA emisora estuvo publicada en una imagen pública de Docker Hub (documentado en `privsvc/linux/src/server-pin.ts:5-15`); mientras no se complete la rotación, quien tenga esa clave y esté en la ruta de red **es** el control plane para el agente.

---

## 3. Lo que está bien (con evidencia)

- **Claves Windows no exportables, en CNG de máquina**: `Ipc/CryptoCsr.cs:287,360` `ExportPolicy = CngExportPolicies.None`, `MachineKey`.
- **Schannel restringido y sin "aceptar todo"**: `Ipc/GrpcBridge.cs:837` TLS 1.2/1.3; el callback devuelve `found`, nunca `true` incondicional (`:922-941`).
- **`checkServerIdentity` personalizado que no salta la verificación de host**: `server-pin.ts:139` llama al verificador por defecto antes del pin.
- **Renovación validada antes del swap**: nombre y firma (`crypto-store.ts:200`), coincidencia de clave (`:177`), ventana de validez (`:222-232`), re-check TOCTOU y escritura atómica 0600 (`cert-renewal.ts:17-51, 322-333`).
- **Token de inscripción triturado en fichero y redactado en logs**: `token-source.ts:205-244`, `enroll.ts:466`.
- **Sin secretos en metadata gRPC**: identidad solo por mTLS (`GrpcBridge.cs:962`, `grpc-bridge.ts:1090`).
- **DP servidor exige mTLS** (`privsvc/macos/src/dp.ts:259-261`), ruta única `/sdp/blob/[0-9a-f]{64}` anclada (`dp.ts:124`, `Dp.cs:79-80`), sin listado, sin escritura, sin traversal; CAs entregadas solo si encadenan a un ancla ya presente (`dp-peer-cas.ts:55-94`).
- **Hash tras cada descarga, por fuente, con unlink en fallo** (`privsvc/macos/src/sdp.ts:610-655`); URLs https-only en dos capas.
- **Pipe de PrivSvc sin Everyone/Users** (`NamedPipeServer.cs:53-84`); sockets Unix `0600 root` en macOS, `0660 root:tracenium` en Linux; límite de 64 KB por línea sin tirar la conexión.
- **Sin deserialización polimórfica** (`Protocol.cs:6-31`); **sin `shell: true`** en ningún `spawn` de Linux/macOS.
- **Escrituras genéricas de registro/secedit validadas**: HKLM/HKU, sin `..`/NUL, tipadas, lista de prefijos protegidos, máximo 64, todo-o-nada (`GenericWriteShape.cs:116-135, 186-284`).
- **Credenciales de vCenter selladas extremo a extremo**: RSA-OAEP + AES-GCM con la huella del certificado como AAD (`envelope.ts:88-90`); solo PrivSvc las abre; clave maestra 0600; contraseña puesta a cero en `finally`; jamás en logs.
- **Jaula de rutas de `rcp.file`**: realpath del ancestro existente más profundo (`path-jail.ts:393-407`), deny antes que allow, staging `mkdtemp 0700` + `O_CREAT|O_EXCL|O_NOFOLLOW` (`file-session.ts:869-879`), `transferId` validado, re-gate antes del rename.
- **Consentimiento fail-closed** (timeout = deniego; prompter que lanza = deniego) y gate de capacidad evaluado en el agente, no solo en el backend (`session-manager.ts:270-287`).
- **Live Query es un enum tipado**, sin lenguaje de consulta, sin contenidos de fichero, sin valores con nombre de secreto (`live-query-question.ts:40-56`).
- **Descubrimiento de certificados salta ficheros con clave privada por contenido** (`cert-files.ts:88`); GPO borra el XML en `finally` y no lo sube.
- **Linux no toca el trust store del sistema** (`privsvc/linux/src/crypto-store.ts:22`); empaquetado con permisos explícitos y mínimos (`nfpm.yaml.tmpl`, `postinstall.sh:54-64`).
- **Grabaciones AES-256-GCM con clave no persistida**, 0700/0600, teclas redactadas (`recording-store.ts:264-324`).
- **Build**: SHA-256 del tarball de Node contra `SHASUMS`, `npm ci` aislado, firma con hardened runtime y notarización en macOS, Azure Trusted Signing en Windows, lockfile presente.

---

## 4. Hallazgos

Severidad = impacto × facilidad, con el adversario indicado. **C** crítico, **A** alto, **M** medio, **B** bajo.

### Críticos

**C-1 · `rcp.file` puede sobrescribir binarios que ejecuta SYSTEM, incluidos los del propio agente** · adversario **O**, **C**
- `Program Files` y `Program Files (x86)` son raíces por defecto de la jaula (`src/plugins/rcp/path-jail.ts:119-133`); la lista de extensiones denegadas es solo material de claves (`:215-223`), no `.exe/.dll/.js`; el rename final no comprueba si el destino existe (`file-session.ts:802-803`).
- El helper de captura de pantalla se resuelve desde el directorio de instalación y se lanza con el token elevado del usuario (`SessionScreenCapture.cs:343-344, 511-515`).
- Impacto: un operador con `remoteFile` reemplaza `node.exe`, el exe del servicio o `tracenium-screencap.exe` y obtiene SYSTEM al siguiente reinicio del servicio, o admin elevado en la siguiente sesión de pantalla. Sin consentimiento ni indicador en el endpoint (B-7). En Linux/macOS: `/opt`, `/srv`, `~/.bashrc`.
- Fix: añadir los directorios de instalación a `defaultDenyPaths`; raíces con marca de solo descarga; rechazar sobrescritura salvo `overwrite:true` explícito y auditado; denegar extensiones ejecutables en subida.

**C-2 · La auto-actualización en Linux y macOS instala paquetes sin firma; en Linux el grupo `tracenium` equivale a root** · adversario **C**, **U** (si compromete al usuario `tracenium`)
- `privsvc/linux/src/agent-install.ts:83-128`: acepta cualquier ruta bajo `/var/lib/tracenium/updates` (directorio del usuario no privilegiado) y ejecuta `dpkg -i` / `rpm -U --force --nodeps` como root. Sin firma ni hash en ese lado; `verifyWindowsUpdateSignatureOrThrow` solo existe para Windows (`update-service.ts:701`).
- macOS: `updater-runner.ts:258` lanza `/usr/sbin/installer -pkg … -target /` sin `pkgutil --check-signature`, aunque esa llamada ya existe para paquetes SDP (`privsvc/macos/src/sdp.ts:894`).
- Impacto: cualquier RCE en el colector sin privilegios de Linux es root vía `postinst`; un control plane comprometido instala lo que quiera en Linux/macOS. La separación de privilegios del PrivSvc queda anulada.
- Fix: verificar firma del `.deb/.rpm/.pkg` dentro del PrivSvc (clave de publicador empaquetada) antes de instalar; quitar `--force --nodeps`; staging en directorio solo-root.

**C-3 · Un job `software_install` ejecuta un comando arbitrario como SYSTEM/root antes de cualquier verificación** · adversario **C**, **R**
- Regla de detección `command_exit`: `src/plugins/sdp/detection.ts:164` acepta `cmd` y `args` sin lista blanca; se ejecuta en `preDetect` antes de descargar ni verificar (`index.ts:396`); PrivSvc lo lanza tal cual (`privsvc/macos/src/sdp.ts:340`, `Ipc/Sdp.cs:1226-1245`).
- Agravado por: el gate de firma del instalador es opcional y lo decide el mismo payload (`signature-gate.ts:56 if (!signingRequired) return { proceed: true }`), y `silentInstallArgs` llegan a `msiexec` como SYSTEM.
- Fix: `cmd` como enumeración de sondas vetadas, o ruta absoluta bajo directorio permitido con `WinVerifyTrust` (como ya hace `SignedScripts.cs:35`); `signingRequired` por defecto `true` para exe/msi, rebajable solo por política; `args` a un conjunto de flags vetado.

### Altos

**A-1 · Inyección de PowerShell en `patch.install` a través de `kbArticleIds`** · adversario **C**, **A**
- `Ipc/PatchManagement.cs:233-235` interpola `JsonSerializer.Serialize(kb)` dentro de un literal PowerShell entre comillas dobles; el serializador de .NET no escapa `$`, y PowerShell interpola `$(…)` en comillas dobles. Un KB `$(Start-Process calc)` ejecuta como SYSTEM. El agente solo hace `String(item).trim()` (`grpc-stream.ts:969-970`). Verificado a mano.
- Fix: validar `^KB?\d{1,10}$` por elemento y rechazar el job si no cumple; o pasar la lista por fichero JSON leído con `ConvertFrom-Json`.

**A-2 · Verificar y ejecutar en momentos distintos desde directorios escribibles por usuarios (Windows)** · adversario **U**
- Shim de actualización: `updater-runner.ts:86-89` escribe `tracenium-update-<epoch>-<pid>.cmd` en `os.tmpdir()` = `C:\Windows\Temp` (Users puede crear ficheros) y lo registra con `schtasks /ru SYSTEM /rl HIGHEST` para 31–90 s después (`:158-170`). El MSI verificado espera en `ProgramData\Tracenium\updates`, creado con `mkdirSync` sin ACL (`update-service.ts:28-42`).
- Staging de SDP: `Ipc/Sdp.cs:44-51` decide expresamente no endurecer el directorio; `HandleInstall` solo re-comprueba prefijo y existencia (`:727-735`), sin re-hash ni Authenticode, tras tres viajes IPC separados (`sdp/index.ts:575, 605, 685`).
- Fix: shim y staging en directorio con DACL SYSTEM+Administrators (el patrón `HardenDirectory` ya existe en `CryptoCertStage.cs:127-150`); nombre aleatorio y apertura `wx`; re-verificar (hash o `WinVerifyTrust`) inmediatamente antes de `Process.Start`/`msiexec`, en el mismo proceso.

**A-3 · El token de inscripción queda expuesto a usuarios locales en las tres plataformas** · adversario **U**
- Windows: `AgentCoreFiles.wxs:29-31` lo guarda en `HKLM\Software\CertusWS\Tracenium\ENROLLMENT_TOKEN` sin `PermissionEx` (Users: lectura) y nunca se borra: la limpieza solo tritura el fichero (`token-source.ts:205`). El script de despliegue lo pasa además en la línea de comandos de `msiexec` (`Install-TraceniumAgent.ps1:251`). Es un token de flota multiuso.
- macOS: `pkg-scripts/postinstall:8-12` hace `chmod 644` del log, redirige todo a él y activa `set -x`; la línea `:217 printf "%s\n" "$TOKEN" > "$TOKEN_FILE"` imprime el token expandido en `/Library/Application Support/Tracenium/Logs/installer.pkg.log`. Se lee además de `/private/tmp/tracenium-enrollment.token` (`:21, 200-201`), y Linux igual (`preinstall.sh:95-97`).
- Impacto: un usuario sin privilegios inscribe equipos falsos en el tenant, o pre-crea el fichero de `/tmp` para dirigir la inscripción a otro tenant.
- Fix: borrar el valor del registro tras inscribir y ACL SYSTEM+Admins; `set +x` alrededor del bloque del token o log 600; token por variable de entorno del instalador, no por ruta fija en `/tmp`; tokens de un solo uso en el servidor.

**A-4 · `%ProgramData%\Tracenium\Agent` nunca se endurece: inventario legible y ficheros de control escribibles** · adversario **U**
- Creado con `fs.mkdirSync` (`paths.ts:35-39`) y `New-Item` (`register-watchdog.ps1:11`) heredando el DACL de ProgramData; el comentario "ACL: SYSTEM/Admin write" de `paths.ts:91` no lo implementa nada. `mode: 0o600` de Node no hace nada en NTFS.
- Contiene `outbox.db` (inventario completo y payloads de jobs, gzip+base64 sin cifrar), `enrollment.json`, `policy.json`, `debug.flag`, `updates/*.msi`, `recordings/`, `watchdog.ps1` (script que corre como SYSTEM cada 5 min desde un directorio escribible por usuarios, `register-watchdog.ps1:7-49`).
- Fix: aplicar `HardenDirectory` a `Tracenium\Agent` al arrancar el servicio y a `Tracenium` en el MSI; mover `watchdog.ps1` a `Program Files`.

**A-5 · Anclas de confianza: la inscripción se valida contra el almacén del SO y planta raíz; la renovación la replanta; el pinning nunca se activa** · adversario **R**, **C**
- `enroll.ts:487` usa `fetch` global sin `ca` ni pin; la respuesta `caBundlePem` va al almacén **Root** de LocalMachine (`CryptoCertInstall.cs:153-160`) y al llavero del sistema en macOS (`crypto-store.ts:338, 874-876`). `assertCertUsable` solo prueba que el bundle es coherente consigo mismo.
- La renovación repite la operación en cada ciclo (`crypto-store.ts:1072-1074`); el modo anti-ancla es `observe` por defecto (`crypto-store.ts:239`, `AnchorPin.cs:56`).
- El pin SPKI de servidor en Linux/macOS es código inalcanzable: `server-pin.ts:180` lee `params.serverKeyPins`, pero `grpc-client.ts:553` nunca lo envía; en Windows el pin es por huella de CA y esa lista la actualiza el propio control plane (`cert-renewal.ts:292`).
- Impacto: un MITM con cualquier CA que el SO ya acepte (proxy corporativo) obtiene el token y planta una raíz en la máquina; un control plane comprometido lo hace en toda la flota Windows/macOS por la ruta rutinaria.
- Fix: fijar el HTTPS de inscripción/renovación a la raíz empaquetada (`undici.Agent({connect:{ca}})`); rechazar anclas que no encadenen a esa raíz; `enforce` por defecto cuando termine la rotación; pins desde configuración local propiedad de root, nunca del control plane.

**A-6 · El consentimiento de sesión remota se puede falsificar desde cualquier sesión de usuario** · adversario **U**
- `consent-prompter-tray.ts:128-155` busca `consent-response.json` en **todos** los perfiles; la petición se escribe 0644 (`:299`) así que el `requestId` no es secreto; un `respondedBy` distinto del usuario de consola se **registra pero se acepta** (`:322-334`, "sigue sin rechazarse mientras dure la ventana de observación"). Además `unlinkSync` como SYSTEM sobre una ruta controlada por el usuario (`:235`) es el patrón clásico de borrado arbitrario por junction en Windows.
- Fix: cerrar la ventana de observación y denegar en `otro_usuario`; `requestId` aleatorio y petición con ACL solo del usuario de consola; abrir/borrar con `O_NOFOLLOW`/`FILE_FLAG_OPEN_REPARSE_POINT` o impersonando al usuario.

**A-7 · Remote Control: sin grant de sesión, shell sin límites, root sin comprobación en el PrivSvc de Linux, transcript sin redactar** · adversario **C**, **U** (Linux), **O**
- `session-manager.ts:119-200` acepta cualquier `remoteSessionOffer` del stream: sin token firmado, sin caducidad, sin binding a equipo/operador; `operator` es solo texto. Un offer repetido se vuelve a responder (`:170-186`).
- Shell como LocalSystem/root sin lista blanca ni límite; el gate `allowPrivilegedShell` sigue siendo un comentario (`pty-session.ts:36-37`).
- Linux: `privsvc/linux/src/rcp-pty.ts:56-141` abre un pty root a petición sin ninguna comprobación de política; solo lo protege el socket `0660 root:tracenium` → miembro del grupo = root (encadena con C-2).
- El transcript sube stdout sin redacción (`transcript-buffer.ts`), mientras la grabación de pantalla sí redacta teclas.
- `peer-session.ts:237-262`: cada data channel nuevo crea otro `PtySession` y deja los anteriores vivos sin cerrar.
- Fix: grant firmado por el backend (deviceId, capacidad, operador, exp, jti, huella del SDP) verificado en `onOffer` contra clave fijada; rechazar `jti` repetidos; gate de shell privilegiada en política y en PrivSvc; un solo canal por sesión con etiqueta verificada; redactar patrones de secreto en transcripts.

**A-8 · La política en disco no está firmada y sus raíces sustituyen a las de fábrica** · adversario **A**, **C**
- El "hash" de política se calcula sobre lo recibido (`grpc-stream.ts:2434`), es idempotencia, no integridad; `policy-store.ts:103-115` no verifica nada al cargar. `features.remoteShell` y `remoteRequireConsent` se leen directamente de ahí (`session-manager.ts:280, 304-306`).
- `path-jail.ts:259-262`: si la política trae `roots`, **reemplazan** a los por defecto; `["C:\\"]` pasa la sanitización. La lista de denegación sí es inamovible (`:181-193`), así que la clave mTLS y los hives siguen sellados, pero el resto del disco no.
- Fix: HMAC/firma del documento bajo clave sellada a la identidad de inscripción y verificación al cargar; intersecar `roots` con los de plataforma o exigir un flag de tenant auditado.

### Medios

**M-1 · vCenter: el pin de certificado no ata la conexión que lleva la credencial** · **R**. `vim-client.ts:88` verifica la huella en un socket propio; el `/sdk` con el login va en otra conexión con `rejectUnauthorized:false` (`:145`). Fix: pin dentro de `checkServerIdentity` del mismo socket.

**M-2 · Distribution Point** · **R**. Cliente: `curl --cert --key -k -fSL` (`privsvc/linux/src/sdp.ts:602`) presenta la identidad del equipo a cualquier host que el control plane nombre y sigue redirecciones; el hash posterior impide inyectar bytes, no evita entregar el certificado. Servidor: acepta cualquier cert de la CA emisora sin EKU, sin revocación (`Dp.cs:194 NoCheck`), sin binding a deviceId, sin límite de conexiones, en `0.0.0.0` con regla de firewall automática (`Dp.cs:125-134`); `peerCaBundlePem` llega por job. Fix: `--cacert` + `--connect-to` en lugar de `-k`, `--max-redirs 0`; EKU `clientAuth` + SAN de deviceId + CRL; tope por IP; restringir `dpBaseUrls` a rangos privados.

**M-3 · Subida de grabaciones: `sessionId` sin validar forma la ruta y se acepta `http:`** · **C**. `rcp/index.ts:209` `path.join(recordingsDir(), sessionId + ".trec")` sin charset; `recording-uploader.ts:114` acepta `http`; un fallo de subida borra el fichero. Traversal = leer y borrar cualquier fichero como SYSTEM hacia un host arbitrario, saltándose la jaula. Fix: `^[A-Za-z0-9_-]{1,64}$`, https-only con allowlist de host, re-check de que el fichero cae en `recordingsDir()`.

**M-4 · El gate "solo LocalSystem/root" del PrivSvc comprueba la identidad del propio servicio** · **U** (Linux). `Router.cs:19-23` `WindowsIdentity.GetCurrent().IsSystem` dentro de un servicio LocalSystem sin impersonación es siempre `true`; igual en Linux/macOS. Ningún PrivSvc autentica al peer (`SO_PEERCRED`, `GetNamedPipeClientProcessId`, firma del binario). En Windows el ACL del pipe basta; en Linux el grupo `tracenium` es la única barrera. Fix: `RunAsClient`/peer credentials; exigir uid 0 o el del agente.

**M-5 · Metadata de actualización por `http:` con bearer** · **R**. `update-service.ts:200, 265` elige `http` si la URL no es https; `config.ts:91` cae a `http://localhost:3000`. Fix: rechazar todo lo que no sea `https:`.

**M-6 · Downgrade forzable por job** · **C**. `update-task.ts:271` con `downloadUrl`+`expectedHash`+`targetVersion` salta la evaluación que bloquea versiones anteriores (`update-service.ts:488`); un MSI viejo bien firmado pasa `WinVerifyTrust`. Fix: suelo monótono en `update-state.json` que el override no cruce sin flag separado.

**M-7 · FIM y Live Query no aplican lista de rutas secretas** · **C**. `file-integrity-policy.ts:46-54` acepta cualquier ruta absoluta; solo suben hash y metadatos, pero sirven de oráculo (mtime de `~/.ssh`, hash de `/etc/shadow`). Fix: reutilizar la denylist de `rcp/path-jail.ts`.

**M-8 · Colector de extensiones sigue rutas absolutas escritas por el usuario como SYSTEM** · **U**. `browser-extensions.ts:198` toma `extensions.settings[id].path` de `Preferences` (escribible por el usuario) si es absoluta y lee `manifest.json` allí. Oráculo de lectura acotado. Fix: `realpath` y exigir que quede bajo `<perfil>/Extensions`.

**M-9 · Hardening de servicio apagado en Linux y macOS** · **U**. `tracenium-agent.service` sin directivas de namespace (documentado por el aborto de Node 22), `tracenium-privsvc.service` con `NoNewPrivileges=false` y sin `ProtectSystem/CapabilityBoundingSet/PrivateTmp`; AppArmor en **complain**; SELinux best-effort; en macOS agente y privsvc corren ambos como root (plists sin `UserName`). Los daemons privilegiados de Node no tienen `uncaughtException`/`unhandledRejection` (solo AgentCore, `service.ts:752-756`) y el socket procesa mensajes sin tope de concurrencia ni timeout. Fix: reactivar directivas cuando se pase a Node 24; AppArmor a enforce; `_tracenium` en macOS; crash guard y límites en el servidor IPC.

**M-10 · Dependencias con CVE** · **R/U**. `npm audit --omit=dev`: 3 altas y 2 medias: `@grpc/grpc-js` 1.14.0–1.14.3 (2 DoS, con fix), `protobufjs` ≤7.6.4 (alta+media, con fix), `systeminformation` (alta, **inyección de comando** en `networkInterfaces()` en Linux, con fix), `xml2js` <0.5.0 vía `node-wmi` (media, sin fix). Fix: actualizar las tres con fix esta semana; evaluar sustituir `node-wmi`.

### Bajos

- **B-1** macOS: contraseña del PKCS#12 en argv de `security import` (`crypto-store.ts:488`); clave copiada a `/private/tmp` (0700) durante la importación.
- **B-2** Identidad Unix = UUID en fichero 0644 + PEM copiable (`device-id.ts:40-45`); un root local clona la identidad a otro host. Objetivo TPM/Secure Enclave (deuda ya conocida).
- **B-3** Ejecutables sin ruta completa en `PmpRemediation.cs` (`powershell.exe`, `secedit.exe`, `auditpol.exe`) frente al patrón correcto de `AdPrinters.cs:51`; plantillas secedit en `C:\Windows\Temp` con nombre GUID.
- **B-4** Logging sin capa de redacción; `debug.flag` en directorio escribible por usuarios (A-4) enciende volcados de SDP/ICE/payloads a logs legibles por `Users`.
- **B-5** `device-id.ts:12-25` construye `reg query/add` por `execSync` con shell (valores constantes hoy); `SecurityCompliance.cs:846` interpola `targetUser` en los argumentos de `gpresult`.
- **B-6** Sin pinning de huella DTLS propio (delegado a libdatachannel y a la señalización); `droppedSample` registra URLs ICE crudas.
- **B-7** Consentimiento e indicador solo para pantalla: shell y ficheros no avisan al usuario (decisión de producto documentada; combinada con C-1 y A-7 deja acciones SYSTEM sin ninguna señal en el endpoint).
- **B-8** Geolocalización: la única puerta es la política; el agente se auto-concede el consentimiento de ubicación de Windows para `S-1-5-18`. Técnicamente correcto (BSSIDs no salen del equipo), pero exige base legal e indicador visible.
- **B-9** Entitlement `disable-library-validation` en el Node firmado de macOS; `sea-config.json`/`postject` muertos.
- **B-10** Cualquier usuario local puede solicitar una instalación del catálogo dejando un JSON en su `%LOCALAPPDATA%` (`catalog-install-request-watcher.ts:24-56`); acotado por ventana de 2 min y aprobación en backend.

---

## 5. Plan de hardening

Ordenado por relación coste/riesgo. Cada fase es entregable y verificable por separado; ninguna requiere cambio de protocolo salvo P2-1.

### P0 — esta semana, cambios pequeños que cierran lo peor

| # | Cierra | Cambio | Verificación |
|---|---|---|---|
| P0-1 | A-1 | Regex `^KB?\d{1,10}$` en `grpc-stream.ts` y en `PatchManagement.cs`; job rechazado con motivo | Test con `$(…)` en un KB → `patch_install_invalid_kb` |
| P0-2 | C-1 | Directorios de instalación en `defaultDenyPaths`; rechazar sobrescritura sin `overwrite:true`; denegar `.exe .dll .sys .js .ps1 .cmd .bat` en subida | Tests de jaula por mutación |
| P0-3 | M-10 | `npm update` de grpc-js, protobufjs, systeminformation; `npm audit` sin altas | CI |
| P0-4 | A-3 | Borrar `ENROLLMENT_TOKEN` del registro tras `store.save`; `PermissionEx` SYSTEM+Admins en el MSI; `set +x` alrededor del token en el postinstall de macOS | `reg query` tras inscribir = vacío; log sin token |
| P0-5 | A-2 | Shim y `updates\` en directorio con `HardenDirectory`; nombre aleatorio; `wx` | ACL del directorio en el MSI de prueba |
| P0-6 | M-3 | Charset de `sessionId`, https-only, re-check de `recordingsDir()` | Test unitario |
| P0-7 | M-5 | Rechazar `http:` en update/metadata | Test unitario |

### P1 — dos a tres semanas

| # | Cierra | Cambio |
|---|---|---|
| P1-1 | A-4, B-4 | `HardenDirectory` sobre `Tracenium\Agent` al arrancar y sobre `Tracenium` en el MSI; `watchdog.ps1` a `Program Files`; `debug.flag` solo desde directorio SYSTEM |
| P1-2 | A-2 (SDP) | `sdp-staging` con DACL protegido; re-hash o `WinVerifyTrust` dentro de `HandleInstall` justo antes de ejecutar |
| P1-3 | C-2 | Firma de `.deb/.rpm/.pkg` verificada en PrivSvc contra clave de publicador empaquetada; sin `--force --nodeps`; staging solo-root |
| P1-4 | A-6 | Consentimiento fail-closed en `otro_usuario`; `requestId` aleatorio; petición con ACL del usuario de consola; `O_NOFOLLOW` en lectura y borrado |
| P1-5 | A-8 | `roots` de política intersecados con los de plataforma; flag de tenant auditado para ampliar |
| P1-6 | M-6 | Suelo monótono de versión en `update-state.json` |
| P1-7 | M-7, M-8 | Denylist compartida (`path-jail`) en FIM, Live Query y colector de extensiones; `realpath` bajo `Extensions` |
| P1-8 | M-1 | Pin de vCenter en `checkServerIdentity` del socket de la petición |

### P2 — un trimestre; cambian contratos

| # | Cierra | Cambio |
|---|---|---|
| P2-1 | A-7 | Grant de sesión firmado por el backend (deviceId, capacidad, operador, exp, jti, huella SDP) verificado en el agente; un canal por sesión; gate de shell privilegiada en política **y** en PrivSvc (Linux `rcp.pty.open` exige token) |
| P2-2 | A-5 | HTTPS de inscripción/renovación fijado a la raíz empaquetada; anclas solo si encadenan a ella; `enforce` por defecto tras la rotación; pins de servidor desde config local |
| P2-3 | C-3 | `command_exit` como enumeración de sondas o ruta firmada; `signingRequired` por defecto para exe/msi; `silentInstallArgs` vetados |
| P2-4 | A-8 | Firma/HMAC de la política en disco bajo clave sellada a la identidad; verificación al cargar |
| P2-5 | M-2 | DP cliente con `--cacert` + `--connect-to`; servidor con EKU, SAN de deviceId, CRL, tope por IP, bind a interfaz de sitio |
| P2-6 | M-4 | Autenticación del peer IPC (`RunAsClient` / `SO_PEERCRED`) y retirada del falso gate `IsLocalSystem` |
| P2-7 | A-1 (clase) | Lista blanca de claves de registro por `checkId` en `GenericWriteShape` en lugar de lista negra |

### P3 — deuda estructural

- Claves de identidad en TPM / Secure Enclave (B-2, deuda ya registrada en ADR-0011).
- Sandboxing de servicio en Linux tras migrar a Node 24 (M-9); AppArmor enforce; usuario `_tracenium` en macOS.
- Redacción central de logs y de transcripts de shell (A-7, B-4).
- Indicador en el endpoint para shell y ficheros (B-7) y base legal de geolocalización (B-8).
- Cobertura automatizada del PrivSvc de Windows (hoy sin proyecto de pruebas .NET que ejercite el pipe ni el router).

---

## 6. Cómo leer las cifras

- Los **críticos** son tres, pero dos de ellos (C-2, C-3) son la misma tesis: *el agente hace lo que el control plane le dice sin poder comprobarlo por su cuenta*. Cerrarlos no es solo parchear; es adoptar la regla de ADR-0011 — "lo estructural va al PrivSvc, porque un gate en el control plane no defiende de un control plane comprometido" — en actualización, instalación y detección, no solo en certificados.
- Los **altos de Windows** (A-2, A-3, A-4, A-6) comparten causa: ProgramData y Temp permiten a `Users` crear ficheros, y el código lo trata como si fueran directorios del servicio. Hay cuatro sitios donde ya se endurece bien; falta aplicar el mismo patrón al resto.
- Nada de lo anterior está siendo explotado que yo sepa, y la mayoría exige o un operador legítimo, o el control plane, o un usuario local en la máquina. Pero un cliente con equipo de seguridad va a encontrar C-1 y A-3 en la primera semana con el agente instalado, y A-1 en cuanto lea un job.
