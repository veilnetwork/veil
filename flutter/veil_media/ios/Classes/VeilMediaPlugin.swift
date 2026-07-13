import Flutter
import UIKit

/// FFI-only plugin shell. CocoaPods force-loads libveil_media.a; Dart resolves
/// its control ABI from the process. No media bytes cross a MethodChannel.
public class VeilMediaPlugin: NSObject, FlutterPlugin {
  public static func register(with registrar: FlutterPluginRegistrar) {}
}
