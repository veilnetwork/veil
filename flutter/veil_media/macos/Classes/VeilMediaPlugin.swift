import Cocoa
import FlutterMacOS

/// No-op macOS registrant. veil_media is an FFI plugin — the native symbols live
/// in libveil_media.dylib (bundled into the app's Frameworks and loaded at
/// runtime via Dart's DynamicLibrary.process()), and there is no method-channel
/// surface, so registration does nothing. The class only gives the pod a source
/// file so CocoaPods has a well-formed target.
public class VeilMediaPlugin: NSObject, FlutterPlugin {
  public static func register(with registrar: FlutterPluginRegistrar) {}
}
