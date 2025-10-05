import Foundation

@MainActor
final class HealthStatusViewModel: ObservableObject {
    @Published private(set) var isHealthy = false
    @Published private(set) var statusDescription = "Checking..."
    @Published private(set) var lastChecked: Date?
    @Published private(set) var errorMessage: String?
    @Published private(set) var isLoading = false

    private let client: APIClientProtocol

    init(client: APIClientProtocol = APIClient.shared) {
        self.client = client
    }

    var lastCheckedDescription: String? {
        guard let lastChecked else { return nil }
        return Self.relativeFormatter.localizedString(for: lastChecked, relativeTo: Date())
    }

    func refresh() async {
        isLoading = true
        defer { isLoading = false }

        do {
            let status = try await client.fetchHealthStatus()
            isHealthy = status.isHealthy
            statusDescription = status.statusDescription
            lastChecked = status.timestamp ?? Date()
            errorMessage = nil
        } catch {
            isHealthy = false
            statusDescription = "Server is unreachable"
            lastChecked = Date()
            errorMessage = friendlyMessage(from: error)
        }
    }

    private func friendlyMessage(from error: Error) -> String {
        if let apiError = error as? APIClientError {
            switch apiError {
            case .missingConfiguration:
                return "Backend configuration is missing or invalid."
            case .invalidResponse:
                return "The server returned an unexpected response."
            case .unreachable:
                return "Unable to reach the server. Check your network connection."
            }
        }

        return error.localizedDescription
    }

    private static let relativeFormatter: RelativeDateTimeFormatter = {
        let formatter = RelativeDateTimeFormatter()
        formatter.unitsStyle = .full
        return formatter
    }()
}
