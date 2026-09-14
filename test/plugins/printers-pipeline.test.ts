// La decisión que convierte una lectura en inventario de impresoras.
//
// ⚠️ Este fichero existe porque la función NO tenía tests propios: el único
// test que la nombraba la sustituía por un doble. Y la decisión que toma es
// cara de deshacer — la PRIMERA ejecución persiste la baseline, así que grabar
// una lista vacía que en realidad era un fallo de lectura convierte "no pude
// mirar" en "no tiene impresoras" de forma permanente: a partir de ahí ya no
// hay cambio nunca. Es literalmente lo que pasó con Windows.

import { describe, it, expect, vi, beforeEach } from "vitest";

const loadPrinterBaseline = vi.fn();
const upsertPrinterBaseline = vi.fn();
const deletePrintersByIds = vi.fn();

// Se dobla el REPOSITORIO (SQLite del agente), no la lógica bajo prueba.
vi.mock("../../src/domain/printer-baseline-repo", () => ({
  loadPrinterBaseline: (...a: any[]) => loadPrinterBaseline(...a),
  upsertPrinterBaseline: (...a: any[]) => upsertPrinterBaseline(...a),
  deletePrintersByIds: (...a: any[]) => deletePrintersByIds(...a)
}));

import { buildPrinterInventoryWithBaseline } from "../../src/plugins/amp/providers/printers-pipeline";

const impresora = (name: string) => ({
  installId: `windows-spooler:${name}`,
  name,
  source: "windows-spooler",
  driver: null,
  port: null,
  isDefault: false,
  isNetwork: true,
  isShared: false,
  location: null,
  comments: null,
  status: "unknown",
  detectedAtUtc: "2026-09-10T00:00:00.000Z"
}) as any;

beforeEach(() => {
  loadPrinterBaseline.mockReset();
  upsertPrinterBaseline.mockReset();
  deletePrintersByIds.mockReset();
  loadPrinterBaseline.mockReturnValue([]);
});

describe("⚠️ una lectura ciega no se graba como 'no tiene impresoras'", () => {
  it("con los dos alcances 'unavailable' NO toca la baseline", () => {
    const r = buildPrinterInventoryWithBaseline([], {
      machineScope: "unavailable",
      userScope: "unavailable"
    });

    expect(upsertPrinterBaseline).not.toHaveBeenCalled();
    // Y no se anuncia como cambio: anunciarlo consolidaría el vacío.
    expect(r.hasChanges).toBe(false);
    expect(r.machineScope).toBe("unavailable");
    expect(r.userScope).toBe("unavailable");
  });

  it("⚠️ si la máquina falla pero SÍ se leyó al usuario, cuenta como medido", () => {
    // El caso real: Spooler mudo para el servicio, colas de red del usuario
    // legibles en HKEY_USERS. Descartarlo escondería justo lo que se busca.
    const r = buildPrinterInventoryWithBaseline([impresora("\\\\SRV\\Cola")], {
      machineScope: "unavailable",
      userScope: "collected"
    });

    expect(upsertPrinterBaseline).toHaveBeenCalledOnce();
    expect(r.count).toBe(1);
    expect(r.hasChanges).toBe(true);
  });

  it("sin hive de usuario cargada pero con la máquina leída, sigue midiendo", () => {
    const r = buildPrinterInventoryWithBaseline([impresora("HP")], {
      machineScope: "collected",
      userScope: "no_user_hive"
    });
    expect(r.count).toBe(1);
    expect(r.userScope).toBe("no_user_hive");
    expect(upsertPrinterBaseline).toHaveBeenCalledOnce();
  });
});

describe("medir y no encontrar nada SÍ se graba", () => {
  it("un equipo sin impresoras deja su baseline vacía y lo anuncia una vez", () => {
    // Es la otra mitad de la distinción: sin esto, un equipo que de verdad no
    // tiene impresoras parecería "nunca medido" para siempre.
    const r = buildPrinterInventoryWithBaseline([], {
      machineScope: "collected",
      userScope: "collected"
    });
    expect(upsertPrinterBaseline).toHaveBeenCalledWith([]);
    expect(r.hasChanges).toBe(true);
    expect(r.count).toBe(0);
  });

  it("sin alcances (macOS y Linux, una sola lectura) se comporta como antes", () => {
    const r = buildPrinterInventoryWithBaseline([impresora("Cups")]);
    expect(r.count).toBe(1);
    expect(r.hasChanges).toBe(true);
    expect(r.machineScope).toBeUndefined();
  });
});

describe("los alcances viajan en los TRES caminos de salida", () => {
  // El camino "hubo cambios" devolvía el literal sin `...scopes`: el ciclo en
  // que una cola aparece o desaparece —justo el que el scheduler SÍ envía—
  // llegaba al backend sin decir si la lectura de usuario fue completa.
  it("ciclo con delta (baseline previa + cambio) conserva machineScope/userScope", () => {
    loadPrinterBaseline.mockReturnValue([impresora("HP")]);
    const r = buildPrinterInventoryWithBaseline([impresora("HP"), impresora("\\\\SRV\\Cola")], {
      machineScope: "timeout",
      userScope: "collected"
    });
    expect(r.hasChanges).toBe(true);
    expect(r.delta).toBeTruthy();
    expect(r.machineScope).toBe("timeout");
    expect(r.userScope).toBe("collected");
  });

  it("ciclo sin cambios conserva machineScope/userScope", () => {
    loadPrinterBaseline.mockReturnValue([impresora("HP")]);
    const r = buildPrinterInventoryWithBaseline([impresora("HP")], {
      machineScope: "collected",
      userScope: "no_user_hive"
    });
    expect(r.hasChanges).toBe(false);
    expect(r.userScope).toBe("no_user_hive");
  });

  it("ciclo con delta sin alcances (macOS/Linux) no los inventa", () => {
    loadPrinterBaseline.mockReturnValue([impresora("HP")]);
    const r = buildPrinterInventoryWithBaseline([impresora("HP"), impresora("Cups")]);
    expect(r.hasChanges).toBe(true);
    expect("machineScope" in r).toBe(false);
  });
});

// ⚠️ EL BORRADO POR TIMEOUT. `measured` sólo trataba `machineScope:
// "unavailable"` como ciego: un `timeout` del Spooler (o `empty_output`, o
// `unknown` de un privsvc viejo) contaba como lectura buena. Con nadie
// conectado eso es una lista vacía MEDIDA → delta con todo en `removed` → el
// backend borra las filas del equipo. Y en el primer ciclo grababa una
// baseline vacía que el backend aplica como "no tiene impresoras" (modo 1b).
describe("⚠️ una lectura fallida no borra impresoras", () => {
  const cola = (name: string) => impresora(name);

  it.each(["timeout", "empty_output", "unknown"])(
    "máquina '%s' sin usuario leído = ciega: no borra y mantiene el último count",
    (machineScope) => {
      loadPrinterBaseline.mockReturnValue([cola("HP"), cola("\\\\SRV\\Cola")]);
      const r = buildPrinterInventoryWithBaseline([], { machineScope, userScope: "no_user_hive" });

      expect(deletePrintersByIds).not.toHaveBeenCalled();
      expect(upsertPrinterBaseline).not.toHaveBeenCalled();
      expect(r.hasChanges).toBe(false);
      expect(r.delta).toBeNull();
      // El count:0 viajaba a host_current_status.total_printers como un hecho.
      expect(r.count).toBe(2);
      expect(r.machineScope).toBe(machineScope);
    }
  );

  it("primer ciclo ciego por timeout: NO graba baseline vacía ni la anuncia", () => {
    const r = buildPrinterInventoryWithBaseline([], { machineScope: "timeout", userScope: "no_user_hive" });
    expect(upsertPrinterBaseline).not.toHaveBeenCalled();
    expect(r.hasChanges).toBe(false);
    expect(r.items).toBeUndefined();
  });

  it("máquina en timeout con usuario leído: añade lo nuevo pero NO quita lo de máquina", () => {
    loadPrinterBaseline.mockReturnValue([cola("HP"), cola("\\\\SRV\\Cola")]);
    const r = buildPrinterInventoryWithBaseline([cola("\\\\SRV\\Cola"), cola("\\\\SRV\\Nueva")], {
      machineScope: "timeout",
      userScope: "collected"
    });

    expect(deletePrintersByIds).not.toHaveBeenCalled();
    expect(r.delta?.removed).toEqual([]);
    expect(r.delta?.added.map((p) => p.name)).toEqual(["\\\\SRV\\Nueva"]);
    expect(upsertPrinterBaseline).toHaveBeenCalledWith([expect.objectContaining({ name: "\\\\SRV\\Nueva" })]);
    // HP sigue contando: no se sabe que se haya ido.
    expect(r.count).toBe(3);
    expect(r.hasChanges).toBe(true);
  });

  it("máquina leída con usuario 'unavailable': no quita las conexiones de red", () => {
    loadPrinterBaseline.mockReturnValue([cola("HP"), cola("\\\\SRV\\Cola")]);
    const r = buildPrinterInventoryWithBaseline([cola("HP")], {
      machineScope: "collected",
      userScope: "unavailable"
    });

    expect(deletePrintersByIds).not.toHaveBeenCalled();
    expect(r.hasChanges).toBe(false);
    expect(r.count).toBe(2);
  });

  it("primer ciclo parcial con filas: las manda como altas, sin sustituir lo del backend", () => {
    // Por delta y no por items[]: el backend aplica items[] como SUSTITUCIÓN
    // (DELETE + INSERT), y una lectura a medias no puede sustituir nada.
    const r = buildPrinterInventoryWithBaseline([cola("\\\\SRV\\Cola")], {
      machineScope: "timeout",
      userScope: "collected"
    });
    expect(r.items).toBeUndefined();
    expect(r.delta?.added).toHaveLength(1);
    expect(r.delta?.removed).toEqual([]);
    expect(r.hasChanges).toBe(true);
  });

  it("una lectura COMPLETA sigue quitando lo que desapareció", () => {
    loadPrinterBaseline.mockReturnValue([cola("HP"), cola("\\\\SRV\\Cola")]);
    const r = buildPrinterInventoryWithBaseline([cola("HP")], {
      machineScope: "collected",
      userScope: "collected"
    });
    expect(deletePrintersByIds).toHaveBeenCalledWith(["windows-spooler:\\\\SRV\\Cola"]);
    expect(r.delta?.removed).toHaveLength(1);
    expect(r.count).toBe(1);
  });

  it("máquina leída sin nadie conectado (no_user_hive) cuenta como completa, como hasta ahora", () => {
    loadPrinterBaseline.mockReturnValue([cola("HP"), cola("USB-Local")]);
    const r = buildPrinterInventoryWithBaseline([cola("HP")], {
      machineScope: "collected",
      userScope: "no_user_hive"
    });
    expect(deletePrintersByIds).toHaveBeenCalledWith(["windows-spooler:USB-Local"]);
  });
});
