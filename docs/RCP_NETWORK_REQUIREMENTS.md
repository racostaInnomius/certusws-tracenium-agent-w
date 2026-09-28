# Qué necesita salir para que una sesión remota conecte

Escrito el 28-sep-2026, después de perder una tarde con MSIG-VEEAM-SRV. No
existía este documento, así que la pregunta «¿qué abro?» sólo se podía
contestar leyendo el código, y el diagnóstico se hizo descartando hipótesis a
mano: relay, VPN, NAT, pasarela, segmento, interfaces, puertos dinámicos y
cortafuegos local, uno por uno.

## Lo primero, porque explica casi todos los casos raros

**Una sesión puede conectar por dos caminos completamente distintos**, y el
segundo no necesita salida a Internet:

1. **Candidato `host`** — el navegador del operador alcanza la IP *privada* del
   agente. Pasa cuando el operador está en la LAN o **conectado por VPN** al
   sitio del cliente. Aquí la salida a Internet del equipo **da igual**.
2. **`srflx` (STUN) o `relay` (TURN)** — el único camino cuando el operador
   está en Internet. Exige salida del equipo, y es lo que este documento
   describe.

⚠️ Esa diferencia es la que hace que un equipo «funcione a veces». Medido el
28-sep en el sitio MSIG (T111), todos Windows Server 2022, misma subred
`10.130.130.0/24`, misma pasarela, mismo perfil de cortafuegos, mismo agente
1.1.85:

| equipo | con VPN | sin VPN |
|---|---|---|
| MSIG-WSUS | ✅ | ✅ |
| MSIG-VEEAM-SRV | ✅ | ❌ |
| MSIG-DOMAIN01 | ✅ | ❌ |
| MSIG-FTP-SPS | — | ❌ |

Un solo equipo tenía salida libre. Los demás **parecían** rotos y sólo les
faltaba permiso de salida — con la VPN puesta conectan todos.

## Lo que el AGENTE necesita alcanzar

| destino | puerto | para qué | ¿obligatorio? |
|---|---|---|---|
| `grpc.tracenium.com` | **443/TCP** | canal de control (mTLS) | **sí** — sin esto el equipo sale «offline» |
| servidores STUN/TURN | ver abajo | reunir candidatos `srflx`/`relay` | sólo si el operador NO está en la LAN/VPN |

⚠️ `grpc.tracenium.com` escucha en **443**, no en 50051. La documentación
interna decía 50051 hasta el 28-sep-2026 y llevó a probar el puerto
equivocado.

### Los extremos de STUN/TURN no son fijos: los decide el backend

`modules/remote-control/cloudflare-turn.ts` en el control plane:

* Con `CF_TURN_KEY_ID` + `CF_TURN_KEY_API_TOKEN` configurados, el backend pide
  credenciales a `rtc.live.cloudflare.com` (**esto lo hace el BACKEND, no el
  equipo**) y devuelve al agente y al navegador la lista de `iceServers` que
  responda Cloudflare — hoy sobre `turn.cloudflare.com`, UDP 3478 y TCP/TLS.
* **Sin** esas variables cae a un STUN público de reserva:
  `stun.l.google.com:19302` y `stun1.l.google.com:19302`, **UDP**. Sin TURN no
  hay relay: un equipo tras NAT simétrico o sin UDP saliente no podrá conectar
  nunca desde Internet.

Por eso este documento no fija una lista de IPs. **La forma correcta de saber
qué hay que abrir hoy** es mirar la respuesta de `POST /sessions` en las
herramientas de desarrollo del navegador: el campo `turnConfig.iceServers`
lleva exactamente los extremos que se van a intentar.

## Cómo comprobarlo en un equipo

⚠️ **Con EDR delante, el orden importa.** PowerShell abriendo sockets crudos y
mandando datagramas en bucle es un patrón de baliza de manual; en esta flota
(CrowdStrike) ya hemos disparado detecciones con diagnósticos inofensivos. Ir
de menos a más:

1. **Sin ejecutar nada**: crear `C:\ProgramData\Tracenium\Agent\debug.flag`,
   reintentar la sesión y leer las líneas `[rcp]` del log. Lo hace el propio
   agente con su binario de siempre — riesgo cero. Desde 1.1.86 el log trae el
   **recuento de candidatos por tipo** al fallar ICE, que es lo que distingue
   las tres causas:

   * sin `host` → el agente no pudo ni mirar sus interfaces;
   * sólo `host` → no hay salida UDP y no se ofreció relay;
   * con `relay` → el relay estaba, el problema es del otro extremo.

2. **TCP**, con `Test-NetConnection` (firmado, sin sockets crudos):

   ```powershell
   Test-NetConnection grpc.tracenium.com  -Port 443
   Test-NetConnection turn.cloudflare.com -Port 443
   ```

3. **UDP**, sólo si hace falta, con un binario firmado haciendo lo suyo y
   **sin bucles**:

   ```
   nslookup -port=3478 -timeout=2 prueba turn.cloudflare.com
   ```

   Da *timeout* —no es un servidor DNS— pero lo que importa es si el datagrama
   sale. Un bloqueo se nota porque ni siquiera intenta.

## Qué NO es la causa, aunque lo parezca

Descartado con medidas el 28-sep, para no repetir el camino:

* **El tipo de NAT**, salvo que se mida con UN SOLO socket contra dos
  destinos. Con un socket por consulta el puerto público cambia siempre y
  cualquier red parece simétrica.
* **El rango de puertos dinámicos** (`netsh int ipv4 show dynamicport udp`) y
  su ocupación: en los dos equipos comparados había decenas de puertos en uso,
  no miles.
* **Interfaces de más**: los dos tenían una sola NIC.
* **El perfil del cortafuegos**: `DomainAuthenticated` en ambos, y **ninguno**
  tenía regla propia para Tracenium. La que funciona tampoco la tiene.
* **El agente**: misma versión, mismo SO, misma revisión, misma arquitectura.
