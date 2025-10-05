import SwiftUI

@main
struct OurVerseApp: App {
    @StateObject private var viewModel = HealthStatusViewModel()

    var body: some Scene {
        WindowGroup {
            ContentView(viewModel: viewModel)
        }
    }
}
