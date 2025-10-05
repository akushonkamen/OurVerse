import XCTest
@testable import OurVerse

final class OurVerseTests: XCTestCase {
    func testRefreshUpdatesStateOnSuccess() async throws {
        let expectedStatus = HealthStatus(status: "healthy", timestamp: Date(), uptime: 1)
        let viewModel = await MainActor.run { HealthStatusViewModel(client: MockAPIClient(result: .success(expectedStatus))) }

        await viewModel.refresh()

        let isHealthy = await MainActor.run { viewModel.isHealthy }
        XCTAssertTrue(isHealthy)

        let description = await MainActor.run { viewModel.statusDescription }
        XCTAssertEqual(description, expectedStatus.statusDescription)
    }

    func testRefreshHandlesFailure() async throws {
        let viewModel = await MainActor.run { HealthStatusViewModel(client: MockAPIClient(result: .failure(APIClientError.unreachable))) }

        await viewModel.refresh()

        let isHealthy = await MainActor.run { viewModel.isHealthy }
        XCTAssertFalse(isHealthy)

        let errorMessage = await MainActor.run { viewModel.errorMessage }
        XCTAssertEqual(errorMessage, "Unable to reach the server. Check your network connection.")
    }
}

private final class MockAPIClient: APIClientProtocol {
    enum Result {
        case success(HealthStatus)
        case failure(APIClientError)
    }

    private let result: Result

    init(result: Result) {
        self.result = result
    }

    func fetchHealthStatus() async throws -> HealthStatus {
        switch result {
        case .success(let status):
            return status
        case .failure(let error):
            throw error
        }
    }
}
