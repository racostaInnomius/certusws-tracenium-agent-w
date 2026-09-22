# Exclusiones de EDR para el agente de Tracenium

Qué lee el agente que un EDR puede interpretar como acceso a credenciales,
qué hace falta excluir y cuándo **no** hace falta nada.

*22-sep-2026. Escrito a partir del código del agente 1.1.79 + ola 1 de CDP.*

---

## 1. Lo primero: por defecto no hace falta ninguna exclusión

El agente **no abre ficheros de clave privada** con la configuración por
defecto. Esto no es una promesa de intenciones: es lo que hace el código, y hay
un test que falla si alguien vuelve a abrirlos.

| Colector | Por defecto | Qué abre |
|---|---|---|
| Claves SSH de usuario (`cdp.sshUserKeys`) | **`public-only`** | `authorized_keys`, `authorized_keys2` y `*.pub`. De `id_rsa`, `id_ed25519` y demás sólo mira nombre, permisos, tamaño y fecha (`stat`), nunca el contenido |
| Ficheros de certificado (`cdp.fileDiscovery`) | `default` | Certificados (`.pem`, `.crt`, `.der`, `.p12`…) bajo las raíces del sistema. **Nunca** entra en `.ssh`, `.aws`, `.gnupg` ni en los llaveros de macOS |
| Almacenes del sistema, keystores Java, NSS | activos | Almacenes de certificados; en Windows a través del servicio privilegiado |

**La única configuración que abre claves privadas es `cdp.sshUserKeys: "full"`**,
que no es el valor por defecto y hay que encenderlo a propósito. Si no lo
enciendes, puedes dejar de leer aquí.

### Por qué existe este documento

El 22-sep-2026, en un Mac de desarrollo, la suite de pruebas de ese colector
—en su versión anterior, que sí leía las claves privadas para decir si estaban
cifradas— disparó una detección **High de CrowdStrike**. Ningún secreto salió
de la máquina; el patrón «un proceso lee `~/.ssh/id_*`» es suficiente para que
un EDR lo marque, y con razón: es lo que hace un ladrón de credenciales. Por eso
el comportamiento cambió a `public-only` y por eso `full` viene con esta página.

---

## 2. Qué lee exactamente cada modo de `cdp.sshUserKeys`

| Modo | Abre y lee | Sólo `stat` |
|---|---|---|
| `off` | nada | nada |
| `public-only` *(defecto)* | `<home>/.ssh/authorized_keys`, `authorized_keys2`, `<home>/.ssh/*.pub`, los ficheros de sistema de abajo y `/etc/passwd` en Linux/macOS | los ficheros de `<home>/.ssh` reconocidos como clave privada (`id_*`, `*.pem`, `*.key`, o los que tienen un `.pub` hermano) |
| `full` *(opt-in)* | lo anterior **más** esos ficheros de clave privada, para decir si están cifrados | — |

**Ficheros de sistema** (se leen en `public-only` y en `full`):
`/etc/ssh/authorized_keys`, `/etc/ssh/authorized_keys2` en Linux y macOS;
`%ProgramData%\ssh\administrators_authorized_keys` en Windows.

**Cómo encuentra los usuarios:** Linux, `/etc/passwd` (y `/home/*` si no puede
leerlo); macOS, `/Users/*` y `/etc/passwd`; Windows, `%SystemDrive%\Users\*`.

**Nunca abre:** `known_hosts`, `known_hosts2`, `config`, `environment`, `rc`,
`*.old`, `*.bak`.

**Topes:** 1 MB por fichero, 2000 líneas, 200 usuarios, 1000 claves y 300
privadas por pasada.

**Cadencia:** el colector de Crypto Discovery corre **cada 12 horas**
(`cdp.intervalSeconds`, por defecto 43200) y sólo si el plugin está contratado.
También se puede lanzar bajo demanda desde el portal, con 60 segundos de
enfriamiento entre envíos.

---

## 3. Qué proceso hace esas lecturas

En los tres sistemas lee **el agente (Node.js)**, no el servicio privilegiado.
El colector no lanza `ssh-keygen`, `dscl` ni `getent`: todo va por llamadas de
sistema de ficheros.

| Sistema | Ejecutable que lee | Servicio | Cuenta |
|---|---|---|---|
| Windows | `C:\Program Files\Tracenium\AgentCore\node\node.exe` (script `…\AgentCore\app\dist\index.js`, lanzado por `…\AgentCore\TraceniumAgentCore.exe`) | `TraceniumAgentCore` | LocalSystem |
| macOS | `/Library/Application Support/Tracenium/Runtime/node` (script `/Library/Application Support/Tracenium/Agent/agent-core.js`) | LaunchDaemon `com.certusws.tracenium.agent` | root |
| Linux | `/usr/lib/tracenium/node` (script `/usr/lib/tracenium/agent/index.js`) | `tracenium-agent.service` | usuario `tracenium` |

⚠️ **En Linux el agente no corre como root**, así que no puede leer los `~/.ssh`
de otros usuarios (permisos 0700). Eso se cuenta como «no legible» en el
inventario, no se silencia. Es un límite real de cobertura en Linux.

Para contrastar con lo que veas en el EDR: el servicio privilegiado es
`TraceniumPrivSvc` (Windows), `com.certusws.tracenium.privsvc` (macOS) y
`tracenium-privsvc.service` (Linux). **No interviene en la lectura de claves
SSH.** Sí interviene en los almacenes de certificados de Windows y en la lectura
de la CA (`certutil`).

Otros colectores de CDP sí lanzan procesos hijos, y conviene saberlo porque
aparecerán en el árbol de procesos del agente: `lsof` en macOS y
`powershell.exe` (`Get-Process -Module`) en Windows para la librería
criptográfica por proceso, y `certutil` en el servidor de la CA.

---

## 4. Exclusiones, si enciendes `full`

Excluye **por proceso**, nunca por ruta de datos: una exclusión sobre `~/.ssh`
dejaría ciego al EDR frente a un ladrón de verdad. Lo que se quiere decir es
«este binario firmado y conocido puede leer ahí», no «ahí no mires».

### CrowdStrike Falcon

En **Endpoint security → Exclusions → IOA exclusions**, crea una exclusión con
el patrón de proceso padre apuntando al ejecutable de la tabla anterior, y
acótala al grupo de equipos donde esté el agente.

- No uses «Sensor visibility exclusions»: apagan la telemetría de esa ruta
  entera, que es justo lo que no quieres.
- Si el SOC prefiere no excluir nada, la alternativa es dejar `public-only` y
  aceptar que «cifrada o no» quede sin evaluar.
- La detección que verás si no excluyes nada es de la familia *Credential
  Access*, severidad alta, con el `node` del agente como proceso.

### Microsoft Defender for Endpoint

- **Exclusión por proceso** (no por carpeta) sobre el ejecutable del agente:
  `Microsoft Defender Antivirus exclusions → Process exclusions`.
- Si tienes **reglas ASR** activas, revisa «Block credential stealing from the
  Windows local security authority subsystem». No aplica a `~/.ssh`, pero sí a
  otros colectores si algún día tocan LSASS — hoy no lo hacen.
- En Defender XDR, marca las alertas como *expected behaviour* con la
  justificación, para que no se repitan en la cola del SOC.

### SentinelOne

- **Exclusions → Interoperability → Path**, con el ejecutable del agente y la
  opción de suprimir alertas de sus hijos.
- Alternativa más estrecha: *Star Rule* que silencie la combinación proceso +
  acceso a `~/.ssh` sin desactivar nada más.

### Otros

El principio es el mismo: excluir el **binario del agente** y acotar la
exclusión a los equipos con el agente instalado. El binario va firmado:
Authenticode con Azure Trusted Signing en Windows, y `codesign` con *hardened
runtime* en macOS —el `.pkg` se notariza en el build, aunque la release puede
publicarse sólo firmada si la notarización falla, así que compruébalo con
`spctl -a -vv` si tu política lo exige—. No hace falta excluir el servicio privilegiado
para este colector.

---

## 5. Qué decirle al SOC

Tres frases que suelen bastar:

1. El agente de Tracenium inventaría claves SSH **para decir quién puede entrar**
   a cada equipo; `authorized_keys` es una concesión de acceso permanente que no
   caduca y que no aparece en ningún otro inventario.
2. Por defecto **no lee ninguna clave privada**; el modo que sí lo hace se
   enciende a propósito y sólo mira la cabecera para decir si está cifrada.
3. **Nunca sale material de clave del equipo**: se envían tipo, tamaño, huella
   SHA-256 de la parte pública, comentario, ruta y permisos.

---

## 6. Si no quieres exclusiones

Deja `cdp.sshUserKeys` en `public-only`. Pierdes una sola cosa: saber si una
clave privada está cifrada. Todo lo demás —quién puede entrar en cada equipo,
qué claves son antiguas o débiles, y la misma clave autorizada en varios
equipos— sale igual, porque vive en ficheros públicos.
