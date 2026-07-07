Pod::Spec.new do |s|
  s.name             = 'veil_media'
  s.version          = '0.0.1'
  s.summary          = 'Dart-FFI control surface for the veil call media engine (macOS shell).'
  s.description      = <<-DESC
Real-time call media (audio/video/screen) over veil. macOS loads
libveil_media.dylib (codec-stripped libwebrtc + the veil Transport shim) at
runtime via Dart's DynamicLibrary, so this pod carries NO native code — the
dylib is bundled into the app's Frameworks by scripts/bundle-macos-dylibs.sh
(built by macos/build_veil_media_dylib.sh from the WebRTC checkout).
                       DESC
  s.homepage         = 'https://github.com/veilnetwork/veil'
  s.license          = { :file => '../LICENSE' }
  s.author           = { 'Veil' => 'noreply@veil.invalid' }
  s.source           = { :path => '.' }
  s.source_files     = 'Classes/**/*'
  s.dependency 'FlutterMacOS'
  s.platform = :osx, '10.15'
  s.pod_target_xcconfig = { 'DEFINES_MODULE' => 'YES' }
  s.swift_version = '5.0'
end
