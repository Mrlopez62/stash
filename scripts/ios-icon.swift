// Draws the iPhone app icon (1024×1024, full bleed: iOS rounds the corners)
// from the stash mark's geometry in docs/brand/mark.svg.
//   swift scripts/ios-icon.swift ios/Stash/Assets.xcassets/AppIcon.appiconset/AppIcon.png
import AppKit

let out = CommandLine.arguments[1]
let s: CGFloat = 1024 / 64
let ctx = CGContext(data: nil, width: 1024, height: 1024, bitsPerComponent: 8, bytesPerRow: 0,
                    space: CGColorSpace(name: CGColorSpace.sRGB)!, bitmapInfo: CGImageAlphaInfo.noneSkipLast.rawValue)!
// SVG's y axis points down.
ctx.translateBy(x: 0, y: 1024)
ctx.scaleBy(x: s, y: -s)
func rgb(_ hex: UInt32) -> CGColor {
    CGColor(srgbRed: CGFloat(hex >> 16 & 0xFF) / 255, green: CGFloat(hex >> 8 & 0xFF) / 255, blue: CGFloat(hex & 0xFF) / 255, alpha: 1)
}
ctx.setFillColor(rgb(0x0E1116))
ctx.fill(CGRect(x: 0, y: 0, width: 64, height: 64))
// The prompt: polyline 14,20 26,32 14,44.
ctx.setStrokeColor(rgb(0xE8EAED))
ctx.setLineWidth(6.5)
ctx.setLineCap(.round)
ctx.setLineJoin(.round)
ctx.move(to: CGPoint(x: 14, y: 20))
ctx.addLine(to: CGPoint(x: 26, y: 32))
ctx.addLine(to: CGPoint(x: 14, y: 44))
ctx.strokePath()
// The keyhole.
ctx.setFillColor(rgb(0xF5B544))
ctx.fillEllipse(in: CGRect(x: 36, y: 20, width: 14, height: 14))
let body = CGMutablePath()
body.move(to: CGPoint(x: 39.6, y: 30))
body.addLine(to: CGPoint(x: 37.5, y: 45))
body.addQuadCurve(to: CGPoint(x: 38.8, y: 46.5), control: CGPoint(x: 37.3, y: 46.5))
body.addLine(to: CGPoint(x: 47.2, y: 46.5))
body.addQuadCurve(to: CGPoint(x: 48.5, y: 45), control: CGPoint(x: 48.7, y: 46.5))
body.addLine(to: CGPoint(x: 46.4, y: 30))
body.closeSubpath()
ctx.addPath(body)
ctx.fillPath()

let rep = NSBitmapImageRep(cgImage: ctx.makeImage()!)
try! rep.representation(using: .png, properties: [:])!.write(to: URL(fileURLWithPath: out))
