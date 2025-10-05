import XCTest

final class OurVerseUITests: XCTestCase {
    override func setUpWithError() throws {
        continueAfterFailure = false
    }

    func testLaunchDisplaysTitle() throws {
        let app = XCUIApplication()
        app.launch()
        XCTAssertTrue(app.navigationBars["OurVerse API"].exists)
    }
}
