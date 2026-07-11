import AppKit
import KeygateCore
import SwiftUI

/// Off-screen renderer for verification: renders `ContentView` to a PNG
/// without opening a window. Invoked via
/// `--render-ui <out.png> [--tab keys|policy|activity|setup]`.
/// Set HOME and TMPDIR to a scratch directory to render against an empty
/// vault instead of real key data.
enum RenderHarness {
    @MainActor
    static func run() {
        let args = CommandLine.arguments
        guard let idx = args.firstIndex(of: "--render-ui"), idx + 1 < args.count else {
            FileHandle.standardError.write(Data("usage: --render-ui <out.png> [--tab keys|policy|activity|setup]\n".utf8))
            exit(2)
        }
        let outPath = args[idx + 1]

        var tab: KeygateTab = .keys
        if let tabIdx = args.firstIndex(of: "--tab"), tabIdx + 1 < args.count {
            guard let parsed = KeygateTab(rawValue: args[tabIdx + 1].capitalized) else {
                FileHandle.standardError.write(Data("unknown tab \(args[tabIdx + 1])\n".utf8))
                exit(2)
            }
            tab = parsed
        }

        let controller = KeygateController()
        let view = ContentView(initialTab: tab, scrollsContent: false)
            .environmentObject(controller)
            .frame(width: 760)
            .fixedSize(horizontal: false, vertical: true)
            .background(Color(nsColor: .windowBackgroundColor))

        let renderer = ImageRenderer(content: view)
        renderer.scale = 2

        guard let image = renderer.nsImage,
              let tiff = image.tiffRepresentation,
              let rep = NSBitmapImageRep(data: tiff),
              let png = rep.representation(using: .png, properties: [:]) else {
            FileHandle.standardError.write(Data("render failed\n".utf8))
            exit(1)
        }
        do {
            try png.write(to: URL(fileURLWithPath: outPath))
            print("rendered \(outPath)")
            exit(0)
        } catch {
            FileHandle.standardError.write(Data("write failed: \(error)\n".utf8))
            exit(1)
        }
    }
}
