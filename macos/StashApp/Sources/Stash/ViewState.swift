import SwiftUI

/// A drop-in for `@State`.
///
/// In recent macOS SDKs `@State` is a compiler macro whose plugin ships only
/// with Xcode, not with the Command Line Tools. Building on `@StateObject`
/// (still a plain property wrapper) keeps the app buildable with just the
/// free Command Line Tools: `swift build`, no Xcode required.
@propertyWrapper
struct ViewState<Value>: DynamicProperty {
    @StateObject private var box: Box

    init(wrappedValue: Value) {
        _box = StateObject(wrappedValue: Box(wrappedValue))
    }

    var wrappedValue: Value {
        get { box.value }
        nonmutating set { box.value = newValue }
    }

    var projectedValue: Binding<Value> {
        Binding(get: { box.value }, set: { box.value = $0 })
    }

    final class Box: ObservableObject {
        @Published var value: Value
        init(_ value: Value) { self.value = value }
    }
}
