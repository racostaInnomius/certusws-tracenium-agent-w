// experiments/ndc-ice-probe.cjs
//
// Aísla node-datachannel del agente para responder UNA pregunta:
// ¿reúne candidatos ICE en esta máquina?
//
// El agente produce una respuesta SDP válida pero cero candidatos —ni
// siquiera `host`, que es solo la IP de la NIC y no necesita red—. Eso
// puede ser (a) libdatachannel no enumera interfaces aquí, o (b) sí los
// genera y se pierden en el camino agente→backend→navegador. Este script
// elimina (b) por completo: no hay gRPC, ni backend, ni WebRTC remoto.
// Solo la librería y esta máquina.
//
// Ejecutar EN EL ENDPOINT, con el Node y los node_modules que instaló el
// MSI — para probar el binding realmente desplegado, no otro:
//
//   cd "$env:ProgramFiles\Tracenium\AgentCore\app"
//   & "$env:ProgramFiles\Tracenium\AgentCore\node\node.exe" ndc-ice-probe.cjs
//
// (copia este fichero a esa carpeta antes). En macOS/Linux el equivalente
// es el directorio Agent de la instalación.

const path = require("path");

function main() {
  let ndc;
  try {
    ndc = require("node-datachannel");
  } catch (err) {
    console.log("RESULTADO: el módulo NO CARGA");
    console.log("  " + (err && err.message));
    process.exit(1);
  }

  console.log("plataforma:", process.platform, process.arch, "| node:", process.version);
  try {
    console.log("binding:", require.resolve("node-datachannel"));
  } catch {}

  // Mismos servidores que el agente recibe del backend, en el formato que
  // node-datachannel espera (hostname/port, no urls[]) — idéntico a la
  // conversión de peer-session.ts.
  const iceServers = [
    { hostname: "stun.cloudflare.com", port: 3478 },
    { hostname: "stun.l.google.com", port: 19302 }
  ];

  const found = { host: 0, srflx: 0, relay: 0, prflx: 0, otros: 0 };
  const muestras = [];
  let gatheringDone = false;

  let pc;
  try {
    pc = new ndc.PeerConnection("ice-probe", { iceServers });
  } catch (err) {
    console.log("RESULTADO: PeerConnection NO SE PUEDE CONSTRUIR");
    console.log("  " + (err && err.message));
    process.exit(1);
  }

  pc.onLocalCandidate((candidate, mid) => {
    const m = /(?:^| )typ (\w+)/.exec(candidate || "");
    const tipo = m ? m[1] : "otros";
    if (found[tipo] === undefined) found.otros++;
    else found[tipo]++;
    if (muestras.length < 6) muestras.push(String(candidate).slice(0, 100));
  });

  pc.onGatheringStateChange((state) => {
    console.log("gatheringState ->", state);
    if (state === "complete") gatheringDone = true;
  });

  pc.onStateChange((state) => console.log("state ->", state));

  // Crear un DataChannel es lo que hace de OFERENTE y dispara el gathering.
  // (El agente es el que responde, pero para probar la enumeración de
  // interfaces da igual el rol: los candidatos `host` salen en ambos casos.)
  try {
    pc.createDataChannel("probe");
  } catch (err) {
    console.log("aviso: createDataChannel falló:", err && err.message);
  }

  setTimeout(() => {
    const total = found.host + found.srflx + found.relay + found.prflx + found.otros;
    console.log("");
    console.log("candidatos:", JSON.stringify(found));
    if (muestras.length) {
      console.log("muestras:");
      for (const s of muestras) console.log("  " + s);
    }
    console.log("");
    if (total === 0) {
      console.log("RESULTADO: CERO CANDIDATOS — libdatachannel no enumera interfaces");
      console.log("  en esta máquina. El fallo es del binding nativo / esta plataforma,");
      console.log("  NO del agente ni del backend. Faltan hasta los `host`, que no");
      console.log("  requieren red alguna.");
    } else if (found.host === 0) {
      console.log("RESULTADO: sin candidatos `host` pero sí otros — raro; revisar");
      console.log("  las interfaces de red de la máquina.");
    } else if (found.srflx === 0 && found.relay === 0) {
      console.log("RESULTADO: solo `host`. La librería funciona y enumera interfaces;");
      console.log("  lo que falla es alcanzar STUN/TURN desde esta red (firewall).");
    } else {
      console.log("RESULTADO: la librería FUNCIONA correctamente en esta máquina.");
      console.log("  El fallo del agente está en otro sitio: o no reenvía los");
      console.log("  candidatos (sendIce) o se pierden hacia el navegador.");
    }
    try { pc.close(); } catch {}
    try { ndc.cleanup && ndc.cleanup(); } catch {}
    process.exit(0);
  }, 12000);

  console.log("recogiendo candidatos durante 12s...");
}

main();
