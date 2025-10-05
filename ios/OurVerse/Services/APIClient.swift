import Foundation

protocol APIClientProtocol {
    func fetchHealthStatus() async throws -> HealthStatus
}

enum APIClientError: Error {
    case missingConfiguration
    case invalidResponse
    case unreachable
}

final class APIClient: APIClientProtocol {
    static let shared = APIClient()

    private let session: URLSession
    private let decoder: JSONDecoder
    private let bundle: Bundle

    init(session: URLSession = .shared, bundle: Bundle = .main) {
        self.session = session
        self.bundle = bundle
        self.decoder = JSONDecoder()
        self.decoder.dateDecodingStrategy = .iso8601
    }

    func fetchHealthStatus() async throws -> HealthStatus {
        let baseURL = try loadBaseURL()
        var request = URLRequest(url: baseURL.appendingPathComponent("health"))
        request.httpMethod = "GET"
        request.timeoutInterval = 10

        do {
            let (data, response) = try await session.data(for: request)
            guard let httpResponse = response as? HTTPURLResponse,
                  (200...299).contains(httpResponse.statusCode) else {
                throw APIClientError.invalidResponse
            }
            return try decoder.decode(HealthStatus.self, from: data)
        } catch let error as APIClientError {
            throw error
        } catch let urlError as URLError {
            switch urlError.code {
            case .notConnectedToInternet, .timedOut, .cannotConnectToHost:
                throw APIClientError.unreachable
            default:
                throw urlError
            }
        }
    }

    private func loadBaseURL() throws -> URL {
        guard let url = bundle.url(forResource: "BackendConfig", withExtension: "plist") else {
            throw APIClientError.missingConfiguration
        }

        let data = try Data(contentsOf: url)
        let plist = try PropertyListSerialization.propertyList(from: data, options: [], format: nil)

        guard
            let dictionary = plist as? [String: Any],
            let value = dictionary["API_BASE_URL"] as? String,
            let baseURL = URL(string: value)
        else {
            throw APIClientError.missingConfiguration
        }

        return baseURL
    }
}
