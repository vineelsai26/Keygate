import Foundation

#if os(macOS)
import Darwin
#endif

public final class AgentSocketServer {
    private let socketURL: URL
    private let service: AgentService
    private var serverSocket: Int32 = -1
    private var isRunning = false

    public init(socketURL: URL = KeygatePaths.socketURL, service: AgentService = AgentService()) {
        self.socketURL = socketURL
        self.service = service
    }

    public func start() throws {
        // Clients (ssh, git, etc.) often disconnect mid-exchange. Without this,
        // write() to a closed socket raises SIGPIPE and kills the whole app.
        Self.ignoreSIGPIPE()

        let runtimeDirectory = socketURL.deletingLastPathComponent()
        try FileManager.default.createDirectory(
            at: runtimeDirectory,
            withIntermediateDirectories: true,
            attributes: [.posixPermissions: 0o700]
        )
        let attributes = try FileManager.default.attributesOfItem(atPath: runtimeDirectory.path)
        guard (attributes[.ownerAccountID] as? NSNumber)?.uint32Value == getuid() else {
            throw POSIXError(.EACCES)
        }
        try FileManager.default.setAttributes([.posixPermissions: 0o700], ofItemAtPath: runtimeDirectory.path)
        if FileManager.default.fileExists(atPath: socketURL.path) {
            try FileManager.default.removeItem(at: socketURL)
        }

        serverSocket = socket(AF_UNIX, SOCK_STREAM, 0)
        guard serverSocket >= 0 else { throw POSIXError(.EIO) }

        var address = sockaddr_un()
        address.sun_family = sa_family_t(AF_UNIX)
        let pathBytes = Array(socketURL.path.utf8)
        guard pathBytes.count < MemoryLayout.size(ofValue: address.sun_path) else {
            throw POSIXError(.ENAMETOOLONG)
        }

        let sunPathCapacity = MemoryLayout.size(ofValue: address.sun_path)
        withUnsafeMutablePointer(to: &address.sun_path) { pointer in
            pointer.withMemoryRebound(to: CChar.self, capacity: sunPathCapacity) { buffer in
                for index in 0 ..< pathBytes.count {
                    buffer[index] = CChar(bitPattern: pathBytes[index])
                }
                buffer[pathBytes.count] = 0
            }
        }

        let bindResult = withUnsafePointer(to: &address) { pointer in
            pointer.withMemoryRebound(to: sockaddr.self, capacity: 1) { socketAddress in
                Darwin.bind(serverSocket, socketAddress, socklen_t(MemoryLayout<sockaddr_un>.size))
            }
        }
        guard bindResult == 0 else { throw POSIXError(POSIXErrorCode(rawValue: errno) ?? .EIO) }
        guard chmod(socketURL.path, mode_t(0o600)) == 0 else {
            throw POSIXError(POSIXErrorCode(rawValue: errno) ?? .EIO)
        }
        guard listen(serverSocket, 16) == 0 else { throw POSIXError(POSIXErrorCode(rawValue: errno) ?? .EIO) }

        isRunning = true
        DispatchQueue.global(qos: .userInitiated).async { [weak self] in
            self?.acceptLoop()
        }
    }

    public func stop() {
        isRunning = false
        if serverSocket >= 0 {
            close(serverSocket)
            serverSocket = -1
        }
        try? FileManager.default.removeItem(at: socketURL)
    }

    private func acceptLoop() {
        while isRunning {
            let client = accept(serverSocket, nil, nil)
            if client < 0 {
                continue
            }
            DispatchQueue.global(qos: .userInitiated).async { [weak self] in
                self?.handle(client)
            }
        }
    }

    private func handle(_ client: Int32) {
        defer { close(client) }
        let process = ProcessResolver.peerProcess(socket: client)
        while true {
            guard let payload = readPacket(from: client) else { return }
            let response: AgentResponse
            do {
                response = service.handle(try AgentProtocolCodec.parse(payload), process: process)
            } catch {
                response = .failure
            }
            let encoded = AgentProtocolCodec.packet(response)
            // Drop the connection on short write / EPIPE instead of taking down the app.
            guard writeExact(client, data: encoded) else { return }
        }
    }

    private func readPacket(from fd: Int32) -> Data? {
        var lengthBytes = [UInt8](repeating: 0, count: 4)
        guard readExact(fd, into: &lengthBytes, count: 4) else { return nil }
        let length = Int(UInt32(lengthBytes[0]) << 24 | UInt32(lengthBytes[1]) << 16 | UInt32(lengthBytes[2]) << 8 | UInt32(lengthBytes[3]))
        guard length > 0 && length < 256 * 1024 else { return nil }
        var payload = [UInt8](repeating: 0, count: length)
        guard readExact(fd, into: &payload, count: length) else { return nil }
        return Data(payload)
    }

    private func readExact(_ fd: Int32, into buffer: inout [UInt8], count: Int) -> Bool {
        var readTotal = 0
        while readTotal < count {
            let result = buffer.withUnsafeMutableBytes { rawBuffer in
                Darwin.read(fd, rawBuffer.baseAddress!.advanced(by: readTotal), count - readTotal)
            }
            if result <= 0 {
                return false
            }
            readTotal += result
        }
        return true
    }

    private func writeExact(_ fd: Int32, data: Data) -> Bool {
        var written = 0
        return data.withUnsafeBytes { rawBuffer -> Bool in
            guard let base = rawBuffer.baseAddress else { return data.isEmpty }
            while written < data.count {
                let result = Darwin.write(fd, base.advanced(by: written), data.count - written)
                if result <= 0 {
                    // EPIPE/ECONNRESET/EINTR after peer hangup — end this client only.
                    return false
                }
                written += result
            }
            return true
        }
    }

    /// Process-wide: turn SIGPIPE into EPIPE so a dead SSH client cannot kill Keygate.
    private static func ignoreSIGPIPE() {
        #if os(macOS)
        signal(SIGPIPE, SIG_IGN)
        #endif
    }
}
