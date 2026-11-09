// Renders Pulse's app icon PNGs into an .iconset folder (argv[1]).
import AppKit

let out = CommandLine.arguments[1]
try? FileManager.default.createDirectory(atPath: out, withIntermediateDirectories: true)

func render(_ px: Int) -> Data {
    let s = CGFloat(px)
    let rep = NSBitmapImageRep(bitmapDataPlanes: nil, pixelsWide: px, pixelsHigh: px, bitsPerSample: 8,
                               samplesPerPixel: 4, hasAlpha: true, isPlanar: false, colorSpaceName: .deviceRGB,
                               bytesPerRow: 0, bitsPerPixel: 0)!
    NSGraphicsContext.saveGraphicsState()
    NSGraphicsContext.current = NSGraphicsContext(bitmapImageRep: rep)
    let inset = s * 0.1
    let rect = NSRect(x: inset, y: inset, width: s - 2 * inset, height: s - 2 * inset)
    let shape = NSBezierPath(roundedRect: rect, xRadius: rect.width * 0.225, yRadius: rect.width * 0.225)
    NSGradient(colors: [NSColor(srgbRed: 0.24, green: 0.56, blue: 0.95, alpha: 1),
                        NSColor(srgbRed: 0.10, green: 0.33, blue: 0.75, alpha: 1)])!.draw(in: shape, angle: -90)
    // pulse line
    let w = rect.width, x0 = rect.minX, y0 = rect.minY
    let pts: [(CGFloat, CGFloat)] = [(0.14, 0.47), (0.33, 0.47), (0.42, 0.70), (0.55, 0.26), (0.65, 0.55), (0.71, 0.47), (0.86, 0.47)]
    let line = NSBezierPath()
    for (i, p) in pts.enumerated() {
        let pt = NSPoint(x: x0 + p.0 * w, y: y0 + p.1 * w)
        i == 0 ? line.move(to: pt) : line.line(to: pt)
    }
    line.lineWidth = w * 0.075
    line.lineCapStyle = .round
    line.lineJoinStyle = .round
    NSColor.white.setStroke()
    line.stroke()
    NSGraphicsContext.restoreGraphicsState()
    return rep.representation(using: .png, properties: [:])!
}

for (name, px) in [("16x16", 16), ("16x16@2x", 32), ("32x32", 32), ("32x32@2x", 64), ("128x128", 128),
                   ("128x128@2x", 256), ("256x256", 256), ("256x256@2x", 512), ("512x512", 512), ("512x512@2x", 1024)] {
    try! render(px).write(to: URL(fileURLWithPath: "\(out)/icon_\(name).png"))
}
