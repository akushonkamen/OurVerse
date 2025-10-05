import SwiftUI

struct ContentView: View {
    @ObservedObject var viewModel: HealthStatusViewModel
    @State private var hasLoaded = false

    var body: some View {
        NavigationStack {
            VStack(spacing: 24) {
                Image(systemName: viewModel.isHealthy ? "checkmark.seal.fill" : "xmark.octagon.fill")
                    .font(.system(size: 64))
                    .foregroundStyle(viewModel.isHealthy ? .green : .red)

                VStack(spacing: 8) {
                    Text(viewModel.statusDescription)
                        .font(.title2)
                        .fontWeight(.semibold)

                    if let lastChecked = viewModel.lastCheckedDescription {
                        Text("Last checked: \(lastChecked)")
                            .font(.subheadline)
                            .foregroundStyle(.secondary)
                    }
                }

                if viewModel.isLoading {
                    ProgressView()
                }

                if let errorMessage = viewModel.errorMessage {
                    Text(errorMessage)
                        .multilineTextAlignment(.center)
                        .font(.footnote)
                        .foregroundStyle(.orange)
                        .transition(.opacity)
                }

                Button(action: refresh) {
                    Label("Refresh", systemImage: "arrow.clockwise")
                        .frame(maxWidth: .infinity)
                }
                .buttonStyle(.borderedProminent)
                .disabled(viewModel.isLoading)
            }
            .padding(24)
            .navigationTitle("OurVerse API")
        }
        .task {
            guard !hasLoaded else { return }
            hasLoaded = true
            await viewModel.refresh()
        }
    }

    private func refresh() {
        Task { await viewModel.refresh() }
    }
}

#Preview {
    ContentView(viewModel: HealthStatusViewModel(client: PreviewAPIClient()))
}

private final class PreviewAPIClient: APIClientProtocol {
    func fetchHealthStatus() async throws -> HealthStatus {
        HealthStatus(status: "healthy", timestamp: Date(), uptime: 42)
    }
}
