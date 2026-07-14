import Foundation
import Security

#if os(macOS)
import CoreServices
import Darwin
#endif

public enum ProcessResolver {
    public static func currentProcess() -> ProcessIdentity {
        let signing = codeSigningIdentity(forExecutablePath: Bundle.main.executablePath)
        return ProcessIdentity(
            pid: getpid(),
            uid: getuid(),
            executablePath: Bundle.main.executablePath,
            bundleIdentifier: Bundle.main.bundleIdentifier,
            teamIdentifier: signing.teamIdentifier,
            signingIdentifier: signing.signingIdentifier,
            codeHash: signing.codeHash
        )
    }

    public static func peerProcess(socket: Int32) -> ProcessIdentity {
        #if os(macOS)
        var pid: pid_t = 0
        var pidLength = socklen_t(MemoryLayout.size(ofValue: pid))
        let pidStatus = getsockopt(socket, SOL_LOCAL, LOCAL_PEERPID, &pid, &pidLength)

        var uid: uid_t = 0
        var gid: gid_t = 0
        let uidStatus = getpeereid(socket, &uid, &gid)

        if pidStatus == 0 {
            let path = executablePath(pid: pid)
            let parent = parentPID(pid: pid)
            let signing = codeSigningIdentity(forExecutablePath: path)
			let terminal = terminalAppIdentity(startingFrom: parent)
            return ProcessIdentity(
                pid: pid,
                uid: uidStatus == 0 ? uid : nil,
                executablePath: path,
                bundleIdentifier: bundleIdentifier(forExecutablePath: path),
                teamIdentifier: signing.teamIdentifier,
                signingIdentifier: signing.signingIdentifier,
                codeHash: signing.codeHash,
                parentPID: parent,
                // Socket peers are often CLI tools (ssh, git); walk parents for the GUI app.
				terminalBundleIdentifier: terminal?.bundleIdentifier,
				terminalTeamIdentifier: terminal?.teamIdentifier
            )
        }

        if uidStatus == 0 {
            return ProcessIdentity(uid: uid)
        }
        #endif
        return ProcessIdentity()
    }

    /// Machine-oriented identity string used for policy matching and diagnostics.
    public static func describe(_ process: ProcessIdentity) -> String {
        if let bundle = process.bundleIdentifier {
            return bundle
        }
        if let path = process.executablePath {
            return path
        }
        if let pid = process.pid {
            return "pid \(pid)"
        }
        if let uid = process.uid {
            return "uid \(uid)"
        }
        return "unknown process"
    }

    /// User-facing label for Touch ID prompts and the Activity log.
    ///
    /// Prefers the parent terminal/GUI app (when the socket peer is a CLI tool
    /// like `ssh`), then the peer's own app bundle, then the executable name.
    public static func displayName(_ process: ProcessIdentity) -> String {
        if let terminal = process.terminalBundleIdentifier {
            return appDisplayName(bundleIdentifier: terminal)
                ?? shortBundleLabel(terminal)
        }
        if let bundle = process.bundleIdentifier {
            return appDisplayName(bundleIdentifier: bundle)
                ?? shortBundleLabel(bundle)
        }
        if let path = process.executablePath {
            return URL(fileURLWithPath: path).lastPathComponent
        }
        if let pid = process.pid {
            return "pid \(pid)"
        }
        if let uid = process.uid {
            return "uid \(uid)"
        }
        return "unknown app"
    }

    /// Detail line for Activity: friendly name plus path/bundle when useful.
    public static func activityLabel(_ process: ProcessIdentity) -> String {
        let name = displayName(process)
        if let path = process.executablePath {
            let base = URL(fileURLWithPath: path).lastPathComponent
            // When the display name is a GUI app but the peer is a different CLI
            // binary, show both: "Terminal (ssh)".
            if name != base, process.bundleIdentifier == nil || process.terminalBundleIdentifier != nil {
                return "\(name) (\(base))"
            }
            if name == base {
                return "\(base) (\(path))"
            }
        }
        if let bundle = process.bundleIdentifier ?? process.terminalBundleIdentifier, name != bundle {
            return "\(name) (\(bundle))"
        }
        return name
    }

	/// Returns a bundle identity only when its executable has a valid signature
	/// with a team identifier suitable for binding a policy rule.
	public static func validatedApplicationIdentity(at url: URL) -> ProcessIdentity? {
		#if os(macOS)
		guard let bundle = Bundle(url: url),
		      let bundleIdentifier = bundle.bundleIdentifier,
		      let executablePath = bundle.executableURL?.path else { return nil }
		let signing = codeSigningIdentity(forExecutablePath: executablePath)
		guard let teamIdentifier = signing.teamIdentifier else { return nil }
		return ProcessIdentity(
			executablePath: executablePath,
			bundleIdentifier: bundleIdentifier,
			teamIdentifier: teamIdentifier,
			signingIdentifier: signing.signingIdentifier,
			codeHash: signing.codeHash
		)
		#else
		return nil
		#endif
	}

    #if os(macOS)
    private static func codeSigningIdentity(forExecutablePath path: String?) -> (teamIdentifier: String?, signingIdentifier: String?, codeHash: String?) {
        guard let path else { return (nil, nil, nil) }
        var staticCode: SecStaticCode?
        guard SecStaticCodeCreateWithPath(URL(fileURLWithPath: path) as CFURL, [], &staticCode) == errSecSuccess,
              let staticCode,
              SecStaticCodeCheckValidity(staticCode, [], nil) == errSecSuccess else {
            return (nil, nil, nil)
        }
        var information: CFDictionary?
        guard SecCodeCopySigningInformation(staticCode, SecCSFlags(rawValue: kSecCSSigningInformation), &information) == errSecSuccess,
              let details = information as? [String: Any] else {
            return (nil, nil, nil)
        }
        let hash = (details[kSecCodeInfoUnique as String] as? Data)?.base64EncodedString()
        return (
            details[kSecCodeInfoTeamIdentifier as String] as? String,
            details[kSecCodeInfoIdentifier as String] as? String,
            hash
        )
    }

    private static func executablePath(pid: pid_t) -> String? {
        var buffer = [CChar](repeating: 0, count: 4096)
        let result = proc_pidpath(pid, &buffer, UInt32(buffer.count))
        guard result > 0 else { return nil }
        return String(cString: buffer)
    }

    private static func parentPID(pid: pid_t) -> pid_t? {
        var info = proc_bsdinfo()
        let size = MemoryLayout<proc_bsdinfo>.size
        let result = proc_pidinfo(pid, PROC_PIDTBSDINFO, 0, &info, Int32(size))
        guard result == Int32(size) else { return nil }
        return pid_t(info.pbi_ppid)
    }

    /// Application bundles enclosing an executable, ordered from the nearest
    /// nested helper to the outermost owning application.
    public static func enclosingApplicationBundlePaths(forExecutablePath path: String?) -> [String] {
        guard let path else { return [] }
        var result: [String] = []
        var url = URL(fileURLWithPath: path)
        while url.path != "/" {
            if url.pathExtension == "app" {
                result.append(url.path)
            }
            url.deleteLastPathComponent()
        }
        return result
    }

    private static func bundleIdentifier(forExecutablePath path: String?, preferOutermost: Bool = false) -> String? {
        let paths = enclosingApplicationBundlePaths(forExecutablePath: path)
        let candidates = preferOutermost ? Array(paths.reversed()) : paths
        for candidate in candidates {
            if let identifier = Bundle(url: URL(fileURLWithPath: candidate))?.bundleIdentifier {
                return identifier
            }
        }
        return nil
    }

    /// Walk the parent chain looking for a process that lives inside an `.app` bundle.
	private static func terminalAppIdentity(startingFrom pid: pid_t?) -> (bundleIdentifier: String, teamIdentifier: String)? {
        var current = pid
        var hops = 0
        // Cap depth so a broken parent chain cannot loop forever.
        while let p = current, hops < 10 {
            if p <= 1 { return nil }
            if let path = executablePath(pid: p),
			   let bundle = bundleIdentifier(forExecutablePath: path, preferOutermost: true),
			   let team = codeSigningIdentity(forExecutablePath: path).teamIdentifier {
				return (bundle, team)
            }
            current = parentPID(pid: p)
            hops += 1
        }
        return nil
    }
    #endif

    private static func appDisplayName(bundleIdentifier: String) -> String? {
        #if os(macOS)
        if let urls = LSCopyApplicationURLsForBundleIdentifier(bundleIdentifier as CFString, nil)?
            .takeRetainedValue() as? [URL],
           let url = urls.first,
           let bundle = Bundle(url: url) {
            if let display = bundle.object(forInfoDictionaryKey: "CFBundleDisplayName") as? String,
               !display.isEmpty {
                return display
            }
            if let name = bundle.object(forInfoDictionaryKey: "CFBundleName") as? String,
               !name.isEmpty {
                return name
            }
        }
        #endif
        return nil
    }

    /// `com.apple.Terminal` → `Terminal` when Launch Services has no display name.
    private static func shortBundleLabel(_ bundleIdentifier: String) -> String {
        if let last = bundleIdentifier.split(separator: ".").last, !last.isEmpty {
            return String(last)
        }
        return bundleIdentifier
    }
}
