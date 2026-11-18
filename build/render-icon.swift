import AppKit
import CoreGraphics

let S: CGFloat = 1024
let space = CGColorSpaceCreateDeviceRGB()
guard let ctx = CGContext(
    data: nil,
    width: Int(S),
    height: Int(S),
    bitsPerComponent: 8,
    bytesPerRow: 0,
    space: space,
    bitmapInfo: CGImageAlphaInfo.premultipliedLast.rawValue
) else {
    fatalError("Cannot create context")
}

ctx.setAllowsAntialiasing(true)
ctx.setShouldAntialias(true)
ctx.clear(CGRect(x: 0, y: 0, width: S, height: S))

func color(_ hex: UInt32, _ alpha: CGFloat = 1) -> CGColor {
    let r = CGFloat((hex >> 16) & 0xFF) / 255
    let g = CGFloat((hex >> 8) & 0xFF) / 255
    let b = CGFloat(hex & 0xFF) / 255
    return CGColor(colorSpace: space, components: [r, g, b, alpha])!
}

let bgPath = CGPath(
    roundedRect: CGRect(x: 0, y: 0, width: S, height: S),
    cornerWidth: 224,
    cornerHeight: 224,
    transform: nil
)

// Background gradient (#101826 -> #0A0D12 -> #05070A)
ctx.saveGState()
ctx.addPath(bgPath)
ctx.clip()
let bgGradient = CGGradient(
    colorsSpace: space,
    colors: [color(0x101826), color(0x0A0D12), color(0x05070A)] as CFArray,
    locations: [0, 0.55, 1]
)!
ctx.drawLinearGradient(
    bgGradient,
    start: CGPoint(x: 0, y: S),
    end: CGPoint(x: S, y: 0),
    options: []
)

// Soft green glow near the top-center
let glow = CGGradient(
    colorsSpace: space,
    colors: [color(0x22C55E, 0.32), color(0x22C55E, 0)] as CFArray,
    locations: [0, 1]
)!
ctx.drawRadialGradient(
    glow,
    startCenter: CGPoint(x: S / 2, y: S * 0.72),
    startRadius: 0,
    endCenter: CGPoint(x: S / 2, y: S * 0.72),
    endRadius: S * 0.62,
    options: []
)
ctx.restoreGState()

// Inner border
let borderPath = CGPath(
    roundedRect: CGRect(x: 18, y: 18, width: S - 36, height: S - 36),
    cornerWidth: 208,
    cornerHeight: 208,
    transform: nil
)
ctx.addPath(borderPath)
ctx.setStrokeColor(color(0x1E293B))
ctx.setLineWidth(6)
ctx.strokePath()

// Lock colors
let lockGradient = CGGradient(
    colorsSpace: space,
    colors: [color(0x4ADE80), color(0x14B8A6)] as CFArray,
    locations: [0, 1]
)!

// Shackle (filled half-annulus so both edges are crisp)
let K: CGFloat = 0.5522847498
let shackle = CGMutablePath()
shackle.move(to: CGPoint(x: 710, y: 554))
shackle.addLine(to: CGPoint(x: 710, y: 666))
shackle.addCurve(
    to: CGPoint(x: 512, y: 864),
    control1: CGPoint(x: 710, y: 666 + K * 198),
    control2: CGPoint(x: 512 + K * 198, y: 864)
)
shackle.addCurve(
    to: CGPoint(x: 314, y: 666),
    control1: CGPoint(x: 512 - K * 198, y: 864),
    control2: CGPoint(x: 314, y: 666 + K * 198)
)
shackle.addLine(to: CGPoint(x: 314, y: 554))
shackle.addLine(to: CGPoint(x: 378, y: 554))
shackle.addLine(to: CGPoint(x: 378, y: 666))
shackle.addCurve(
    to: CGPoint(x: 512, y: 800),
    control1: CGPoint(x: 378, y: 666 + K * 134),
    control2: CGPoint(x: 512 - K * 134, y: 800)
)
shackle.addCurve(
    to: CGPoint(x: 646, y: 666),
    control1: CGPoint(x: 512 + K * 134, y: 800),
    control2: CGPoint(x: 646, y: 666 + K * 134)
)
shackle.addLine(to: CGPoint(x: 646, y: 554))
shackle.closeSubpath()
ctx.addPath(shackle)
ctx.saveGState()
ctx.clip()
ctx.drawLinearGradient(
    lockGradient,
    start: CGPoint(x: 314, y: 820),
    end: CGPoint(x: 710, y: 500),
    options: []
)
ctx.restoreGState()

// Body
let bodyPath = CGPath(
    roundedRect: CGRect(x: 250, y: 190, width: 524, height: 404),
    cornerWidth: 92,
    cornerHeight: 92,
    transform: nil
)
ctx.saveGState()
ctx.addPath(bodyPath)
ctx.clip()
ctx.drawLinearGradient(
    lockGradient,
    start: CGPoint(x: 260, y: 594),
    end: CGPoint(x: 764, y: 190),
    options: []
)
// Slight dark sheen at the bottom of the body
let sheen = CGGradient(
    colorsSpace: space,
    colors: [color(0x000000, 0), color(0x000000, 0.18)] as CFArray,
    locations: [0, 1]
)!
ctx.drawLinearGradient(sheen, start: CGPoint(x: 512, y: 400), end: CGPoint(x: 512, y: 190), options: [])
ctx.restoreGState()

// Keyhole
ctx.setFillColor(color(0x0A0D12))
ctx.fillEllipse(in: CGRect(x: 454, y: 370, width: 116, height: 116))

let stem = CGPath(
    roundedRect: CGRect(x: 486, y: 292, width: 52, height: 118),
    cornerWidth: 26,
    cornerHeight: 26,
    transform: nil
)
ctx.addPath(stem)
ctx.fillPath()

// Export PNG
guard let image = ctx.makeImage() else { fatalError("Cannot make image") }
let rep = NSBitmapImageRep(cgImage: image)
guard let png = rep.representation(using: .png, properties: [:]) else { fatalError("Cannot encode PNG") }
let out = URL(fileURLWithPath: CommandLine.arguments.count > 1 ? CommandLine.arguments[1] : "icon.png")
try png.write(to: out)
print("Wrote \(out.path)")
