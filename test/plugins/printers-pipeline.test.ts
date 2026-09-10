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
