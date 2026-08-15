// experiments/ndc-answerer-probe.cjs
//
// La sonda anterior (ndc-ice-probe.cjs) probó el rol de OFERENTE: crea un
// DataChannel y reúne candidatos. Pero el agente RCP es el RESPONDEDOR y
// NO crea DataChannel — espera `onDataChannel`. Es otro camino dentro de
// libdatachannel, y es el que realmente falla en producción.
//
// Este script monta los dos peers en la misma máquina:
//   A = oferente  (hace de navegador: crea el DataChannel, genera la oferta)
//   B = respondedor (hace de agente: SOLO setRemoteDescription, sin crear
//                    ningún canal — exactamente como peer-session.ts)
//
// Y cuenta los candidatos que emite CADA UNO. Si B emite cero mientras A
// emite varios, el fallo está reproducido sin backend, sin gRPC y sin red:
// libdatachannel no reúne candidatos en el rol de respondedor en esta
// plataforma.
//
// Ejecutar EN EL ENDPOINT, con el Node y node_modules del MSI:
//   cd "$env:ProgramFiles\Tracenium\AgentCore\app"
//   & "$env:ProgramFiles\Tracenium\AgentCore\node\node.exe" ndc-answerer-probe.cjs

const ndc = require("node-datachannel");

const ICE = [
  { hostname: "stun.cloudflare.com", port: 3478 },
  { hostname: "stun.l.google.com", port: 19302 }
];

const cuenta = () => ({ host: 0, srflx: 0, relay: 0, otros: 0 });
const tally = (bag, cand) => {
  const m = /(?:^| )typ (\w+)/.exec(cand || "");
  const t = m ? m[1] : "otros";
  if (bag[t] === undefined) bag.otros++;
  else bag[t]++;
};

console.log("plataforma:", process.platform, process.arch, "| node:", process.version);

const A = { cands: cuenta(), sdp: null };
const B = { cands: cuenta(), sdp: null };

const pcA = new ndc.PeerConnection("oferente", { iceServers: ICE });
const pcB = new ndc.PeerConnection("respondedor", { iceServers: ICE });

pcA.onLocalCandidate((c) => tally(A.cands, c));
pcB.onLocalCandidate((c) => {
  tally(B.cands, c);
  // El agente reenvía cada candidato por gRPC aquí (sendIce).
});

pcA.onGatheringStateChange((s) => console.log("  A gathering ->", s));
pcB.onGatheringStateChange((s) => console.log("  B gathering ->", s));

let ofertaLista = false;
pcA.onLocalDescription((sdp, type) => {
  if (type !== "offer" || ofertaLista) return;
  ofertaLista = true;
  A.sdp = sdp;
  const lineas = sdp.split(/\r?\n/);
  console.log("A generó oferta:", lineas.length, "líneas,",
    lineas.filter((l) => l.startsWith("a=candidate")).length, "candidatos embebidos");

  // ── Esto es exactamente lo que hace el agente en acceptOffer():
  //    setRemoteDescription(offer) y nada más. Sin setLocalDescription
  //    explícito, sin crear canales.
  pcB.setRemoteDescription(sdp, "offer");
  console.log("B aplicó la oferta (igual que peer-session.acceptOffer)");
});

pcB.onLocalDescription((sdp, type) => {
  if (type !== "answer" || B.sdp) return;
  B.sdp = sdp;
  const lineas = sdp.split(/\r?\n/);
  console.log("B generó respuesta:", lineas.length, "líneas,",
    lineas.filter((l) => l.startsWith("a=candidate")).length, "candidatos embebidos");
});

// Crear el canal en A dispara la oferta (rol oferente).
pcA.createDataChannel("probe");

setTimeout(() => {
  const totalA = Object.values(A.cands).reduce((a, b) => a + b, 0);
  const totalB = Object.values(B.cands).reduce((a, b) => a + b, 0);
  console.log("");
  console.log("candidatos A (oferente / navegador):", JSON.stringify(A.cands), "→", totalA);
  console.log("candidatos B (respondedor / AGENTE):", JSON.stringify(B.cands), "→", totalB);
  console.log("respuesta SDP de B generada:", B.sdp ? "sí" : "NO");
  console.log("");
  if (totalB === 0 && totalA > 0) {
    console.log("RESULTADO: FALLO REPRODUCIDO.");
    console.log("  El respondedor no emite candidatos mientras el oferente sí.");
    console.log("  Es un fallo de libdatachannel en el rol respondedor en esta");
    console.log("  plataforma — sin backend, sin red, sin agente de por medio.");
  } else if (totalB > 0) {
    console.log("RESULTADO: el respondedor SÍ emite candidatos.");
    console.log("  Entonces la librería no es la causa: el agente los genera y se");
    console.log("  pierden después (sendIce / gRPC / bus de señalización).");
  } else {
    console.log("RESULTADO: ninguno de los dos emite candidatos — mirar la red/host.");
  }
  try { pcA.close(); pcB.close(); } catch {}
  try { ndc.cleanup && ndc.cleanup(); } catch {}
  process.exit(0);
}, 15000);

console.log("recogiendo 15s...");
