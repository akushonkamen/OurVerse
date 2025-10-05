import Foundation

struct HealthStatus: Decodable, Equatable {
    let status: String
    let timestamp: Date?
    let uptime: TimeInterval?

    var isHealthy: Bool {
        status.lowercased() == "healthy"
    }

    var statusDescription: String {
        isHealthy ? "Server is healthy" : "Server is unreachable"
    }
}
