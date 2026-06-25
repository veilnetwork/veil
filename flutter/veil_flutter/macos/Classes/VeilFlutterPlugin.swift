import Cocoa
import FlutterMacOS

/// No-op macOS registrant. veil_flutter is an FFI plugin — the Rust symbols are
/// resolved at runtime via Dart's DynamicLibrary, and there is no method-channel
/// surface on macOS — so registration does nothing. The class only gives the
/// pod a source file so CocoaPods has a well-formed target.
public class VeilFlutterPlugin: NSObject, FlutterPlugin {
  public static func register(with registrar: FlutterPluginRegistrar) {}
}
