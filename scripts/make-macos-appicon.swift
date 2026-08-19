#!/usr/bin/env swift
//
// make-macos-appicon.swift — genera el PNG fuente del icono de
// "Tracenium Agent Status".
//
// POR QUÉ EXISTE
// ----------------------------------------------------------------------------
// El .icns se construía con `sips` directamente desde Tracenium_tryicon.png,
// que es un glifo BLANCO puro con la forma en el canal alpha. Eso funciona en
// la barra de menús —donde el glifo se pinta como template— pero como icono de
// aplicación queda un dibujo blanco sobre nada: macOS lo compone sobre su
// fondo gris claro y en Ajustes → Privacidad y seguridad → Localización el
// icono, sencillamente, no se ve.
//
// Aquí se compone el mismo glifo sobre un fondo sólido con el color del portal,
// RGB(63,66,78), que es donde tiene contraste de sobra.
//
// El resultado se COMMITEA como asset (Resources/appicon-source.png) en vez de
// generarse en cada build: así el icono es revisable en un diff y el build no
// gana una dependencia de swiftc. Este script solo hace falta para regenerarlo
// si cambia el glifo o el color.
//
// Uso, desde la raíz del repo:
//   swift scripts/make-macos-appicon.swift
//
import AppKit

let side: CGFloat = 1024

// Color del portal, tal cual lo pidió el diseño.
let background = NSColor(calibratedRed: 63.0/255.0, green: 66.0/255.0, blue: 78.0/255.0, alpha: 1.0)

// Proporciones del icono de macOS: el cuadrado redondeado no ocupa todo el
// lienzo — deja margen a los lados, y el radio es ~22.37% del lado. Respetarlo
// es lo que hace que el icono se vea del mismo tamaño que sus vecinos en el
// Dock y en Ajustes, en vez de más grande y desalineado.
let margin = side * 0.10
let squareSide = side - margin * 2
let corner = squareSide * 0.2237

// Cuánto del cuadrado ocupa el glifo. Por debajo de ~0.6 se ve perdido; por
// encima toca los bordes redondeados.
let glyphFraction: CGFloat = 0.58

let repo = FileManager.default.currentDirectoryPath
let glyphPath = "\(repo)/Tracenium_tryicon.png"
let outPath = "\(repo)/macos/TraceniumAgentStatus/Resources/appicon-source.png"

guard let glyph = NSImage(contentsOfFile: glyphPath) else {
    FileHandle.standardError.write("no se pudo abrir \(glyphPath)\n".data(using: .utf8)!)
    exit(1)
}

guard let rep = NSBitmapImageRep(
    bitmapDataPlanes: nil,
    pixelsWide: Int(side), pixelsHigh: Int(side),
    bitsPerSample: 8, samplesPerPixel: 4, hasAlpha: true, isPlanar: false,
    colorSpaceName: .calibratedRGB, bytesPerRow: 0, bitsPerPixel: 0
) else {
    FileHandle.standardError.write("no se pudo crear el bitmap\n".data(using: .utf8)!)
    exit(1)
}

NSGraphicsContext.saveGraphicsState()
NSGraphicsContext.current = NSGraphicsContext(bitmapImageRep: rep)

let squareRect = NSRect(x: margin, y: margin, width: squareSide, height: squareSide)
background.setFill()
NSBezierPath(roundedRect: squareRect, xRadius: corner, yRadius: corner).fill()

// El glifo conserva su relación de aspecto: el original no es cuadrado
// (542x588) y estirarlo a un cuadrado lo deformaría.
let maxGlyph = squareSide * glyphFraction
let scale = min(maxGlyph / glyph.size.width, maxGlyph / glyph.size.height)
let glyphSize = NSSize(width: glyph.size.width * scale, height: glyph.size.height * scale)
let glyphRect = NSRect(
    x: (side - glyphSize.width) / 2,
    y: (side - glyphSize.height) / 2,
    width: glyphSize.width,
    height: glyphSize.height
)
glyph.draw(in: glyphRect, from: .zero, operation: .sourceOver, fraction: 1.0)

NSGraphicsContext.restoreGraphicsState()

guard let png = rep.representation(using: .png, properties: [:]) else {
    FileHandle.standardError.write("no se pudo codificar el PNG\n".data(using: .utf8)!)
    exit(1)
}
try! png.write(to: URL(fileURLWithPath: outPath))
print("escrito \(outPath)  (\(Int(side))x\(Int(side)), fondo rgb(63,66,78))")
