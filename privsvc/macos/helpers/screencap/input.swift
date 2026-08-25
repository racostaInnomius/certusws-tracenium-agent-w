// privsvc/macos/helpers/screencap/input.swift
//
// RCP — inyección de teclado y ratón en la sesión gráfica de macOS.
//
// POR QUÉ VIVE AQUÍ Y NO EN EL PRIVSVC
//
//   Por lo mismo que la captura. CGEvent se entrega a la sesión de ventanas
//   del proceso que lo publica, y el privsvc es un LaunchDaemon: no tiene
//   sesión gráfica. Además la inyección exige el permiso de ACCESIBILIDAD,
//   que TCC ancla al proceso responsable — si lo pidiera el privsvc, el
//   usuario vería a "node" pidiendo controlar su equipo, que es exactamente
//   el problema que el disclaim de main.swift resolvió para la captura.
//
//   Windows llegó aquí por el camino largo: su inyección vivía en el servicio
//   y SendInput encolaba en el escritorio de la Sesión 0, o sea en ninguna
//   parte. macOS se salta ese error empezando ya dentro de la sesión.
//
// DOS PERMISOS DISTINTOS
//
//   Grabación de Pantalla (ver) y Accesibilidad (controlar) son concesiones
//   separadas en macOS, cada una con su diálogo. Ver la pantalla NO implica
//   poder controlarla. El operador tiene que saberlo, así que la falta de
//   Accesibilidad se reporta con su propio código y no como un fallo genérico.
//
// PROTOCOLO
//
//   Una línea JSON de petición por stdin, una de respuesta por stdout:
//     { "op": "mouseMove", "x": 100, "y": 200 }
//     { "op": "mouseDown"|"mouseUp", "button": 0|1|2, "x": N, "y": N }
//     { "op": "wheel", "deltaX": N, "deltaY": N }
//     { "op": "keyDown"|"keyUp", "code": "KeyA" }   // JS KeyboardEvent.code
//     { "op": "releaseAll" }
//
//   Mismos nombres y campos que la ruta de Windows, para que el agente no
//   tenga que distinguir plataformas.

import Foundation
import CoreGraphics
import ApplicationServices

// ── Estado de la sesión de control ───────────────────────────────────
//
// Hay que recordar qué está pulsado por dos motivos:
//
//   1. Arrastrar. Mientras un botón está abajo, macOS espera eventos
//      .leftMouseDragged, no .mouseMoved. Mandar mouseMoved durante un
//      arrastre hace que la ventana no siga al cursor — el operador ve que
//      "no puede arrastrar nada" sin ningún error de por medio.
//   2. releaseAll. Si el operador cierra la sesión con el ratón pulsado o con
//      Cmd abajo, el equipo del usuario se queda con esa tecla trabada. Es la
//      clase de secuela que hace desconfiar de una herramienta de soporte.
private var heldButtons = Set<Int>()
private var heldKeys = Set<CGKeyCode>()

private func post(_ event: CGEvent?) {
    event?.post(tap: .cghidEventTap)
}

// ── Accesibilidad (TCC) ──────────────────────────────────────────────
//
// Se PIDE una vez, igual que la captura: AXIsProcessTrusted() solo consulta
// y no registra el binario en Ajustes. Con el prompt activado, macOS añade la
// entrada y muestra el diálogo — sin eso el permiso es inalcanzable, que es
// justo el callejón en el que estuvo la captura.
func ensureAccessibility(requestIfNeeded: Bool) -> Bool {
    if AXIsProcessTrusted() { return true }
    guard requestIfNeeded else { return false }
    let opts = [kAXTrustedCheckOptionPrompt.takeUnretainedValue() as String: true]
    return AXIsProcessTrustedWithOptions(opts as CFDictionary)
}

// ── Ratón ────────────────────────────────────────────────────────────

/// JS `MouseEvent.button` (0 izq, 1 medio, 2 der) → CGMouseButton.
private func cgButton(_ jsButton: Int) -> CGMouseButton {
    switch jsButton {
    case 1: return .center
    case 2: return .right
    default: return .left
    }
}

private func downType(_ jsButton: Int) -> CGEventType {
    switch jsButton {
    case 1: return .otherMouseDown
    case 2: return .rightMouseDown
    default: return .leftMouseDown
    }
}

private func upType(_ jsButton: Int) -> CGEventType {
    switch jsButton {
    case 1: return .otherMouseUp
    case 2: return .rightMouseUp
    default: return .leftMouseUp
    }
}

/// Tipo de movimiento según lo que haya pulsado. Ver el comentario de
/// `heldButtons`: durante un arrastre macOS exige el evento de arrastre.
private func moveType() -> (CGEventType, CGMouseButton) {
    if heldButtons.contains(2) { return (.rightMouseDragged, .right) }
    if heldButtons.contains(1) { return (.otherMouseDragged, .center) }
    if heldButtons.contains(0) { return (.leftMouseDragged, .left) }
    return (.mouseMoved, .left)
}

func injectMouseMove(x: Double, y: Double) {
    let (type, button) = moveType()
    post(CGEvent(mouseEventSource: nil,
                 mouseType: type,
                 mouseCursorPosition: CGPoint(x: x, y: y),
                 mouseButton: button))
}

func injectMouseButton(jsButton: Int, x: Double, y: Double, down: Bool) {
    // El clic lleva su propia posición: si solo movimos antes, un clic sin
    // coordenadas aterriza donde estuviera el cursor del USUARIO, no donde
    // apuntó el operador.
    let pos = CGPoint(x: x, y: y)
    let type = down ? downType(jsButton) : upType(jsButton)
    let ev = CGEvent(mouseEventSource: nil,
                     mouseType: type,
                     mouseCursorPosition: pos,
                     mouseButton: cgButton(jsButton))
    // clickState = 1: un clic simple. Sin esto macOS puede interpretar
    // pulsaciones seguidas como dobles clics según su temporización interna.
    ev?.setIntegerValueField(.mouseEventClickState, value: 1)
    post(ev)
    if down { heldButtons.insert(jsButton) } else { heldButtons.remove(jsButton) }
}

func injectWheel(deltaX: Double, deltaY: Double) {
    // El navegador manda deltas con el signo de "hacia dónde se mueve el
    // contenido"; CGEvent los quiere al revés.
    let dy = Int32(clamping: Int(-deltaY.rounded()))
    let dx = Int32(clamping: Int(-deltaX.rounded()))
    post(CGEvent(scrollWheelEvent2Source: nil,
                 units: .pixel,
                 wheelCount: 2,
                 wheel1: dy,
                 wheel2: dx,
                 wheel3: 0))
}

// ── Teclado ──────────────────────────────────────────────────────────
//
// JS KeyboardEvent.code → virtual keycode de macOS (kVK_*). `code` es
// POSICIONAL: describe la tecla física, no el carácter que produce, así que
// mapea directo a los virtual keycodes y no depende de la distribución de
// teclado del equipo remoto. Ese es justo el motivo por el que el agente
// manda `code` y no `key`.
private let keyCodes: [String: CGKeyCode] = [
    "KeyA": 0, "KeyS": 1, "KeyD": 2, "KeyF": 3, "KeyH": 4, "KeyG": 5,
    "KeyZ": 6, "KeyX": 7, "KeyC": 8, "KeyV": 9, "KeyB": 11, "KeyQ": 12,
    "KeyW": 13, "KeyE": 14, "KeyR": 15, "KeyY": 16, "KeyT": 17,
    "KeyO": 31, "KeyU": 32, "KeyI": 34, "KeyP": 35, "KeyL": 37, "KeyJ": 38,
    "KeyK": 40, "KeyN": 45, "KeyM": 46,

    "Digit1": 18, "Digit2": 19, "Digit3": 20, "Digit4": 21, "Digit6": 22,
    "Digit5": 23, "Digit9": 25, "Digit7": 26, "Digit8": 28, "Digit0": 29,

    "Equal": 24, "Minus": 27, "BracketRight": 30, "BracketLeft": 33,
    "Quote": 39, "Semicolon": 41, "Backslash": 42, "Comma": 43,
    "Slash": 44, "Period": 47, "Backquote": 50,

    "Enter": 36, "Tab": 48, "Space": 49, "Backspace": 51, "Escape": 53,
    "Delete": 117, "Home": 115, "End": 119, "PageUp": 116, "PageDown": 121,
    "ArrowLeft": 123, "ArrowRight": 124, "ArrowDown": 125, "ArrowUp": 126,

    "F1": 122, "F2": 120, "F3": 99, "F4": 118, "F5": 96, "F6": 97,
    "F7": 98, "F8": 100, "F9": 101, "F10": 109, "F11": 103, "F12": 111,

    // Modificadores. Se publican como keyDown/keyUp normales y CGEvent
    // mantiene el estado del flag por nosotros.
    "ShiftLeft": 56, "ShiftRight": 60,
    "ControlLeft": 59, "ControlRight": 62,
    "AltLeft": 58, "AltRight": 61,
    "MetaLeft": 55, "MetaRight": 54,
    "CapsLock": 57
]

func injectKey(code: String, down: Bool) -> Bool {
    guard let vk = keyCodes[code] else { return false }
    post(CGEvent(keyboardEventSource: nil, virtualKey: vk, keyDown: down))
    if down { heldKeys.insert(vk) } else { heldKeys.remove(vk) }
    return true
}

/// Suelta todo lo que quedara pulsado. Se llama al cerrar la sesión y cuando
/// el operador desactiva el control: dejar una tecla trabada en el equipo de
/// otra persona es peor que no haber controlado nunca.
func injectReleaseAll() {
    for vk in heldKeys {
        post(CGEvent(keyboardEventSource: nil, virtualKey: vk, keyDown: false))
    }
    heldKeys.removeAll()

    if !heldButtons.isEmpty {
        let pos = CGEvent(source: nil)?.location ?? .zero
        for b in heldButtons {
            let ev = CGEvent(mouseEventSource: nil,
                             mouseType: upType(b),
                             mouseCursorPosition: pos,
                             mouseButton: cgButton(b))
            ev?.setIntegerValueField(.mouseEventClickState, value: 1)
            post(ev)
        }
        heldButtons.removeAll()
    }
}
