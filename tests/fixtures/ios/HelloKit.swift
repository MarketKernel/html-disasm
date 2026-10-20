// HelloKit.framework of the sample iOS app: Swift with a class the Objective-C runtime sees,
// a struct, a protocol and a C entry point.
import Foundation

public protocol Shape {
  func area() -> Double
}

public struct Circle: Shape {
  public let radius: Double
  public init(radius: Double) { self.radius = radius }
  public func area() -> Double { Double.pi * radius * radius }
}

@objc public class Counter: NSObject {
  @objc public private(set) var count = 0
  @objc public func increment(by step: Int) -> Int {
    count += step
    return count
  }
}

@_cdecl("HelloKitAnswer")
public func helloKitAnswer(_ x: Int) -> Int {
  let counter = Counter()
  _ = counter.increment(by: x)
  return counter.increment(by: Int(Circle(radius: 2).area()))
}
