#
# veil_flutter — macOS plugin podspec.
#
# The host app still loads `libveilclient_ffi.dylib` through Dart FFI. This pod
# additionally controls the separately linked PacketTunnel extension through
# Apple's NetworkExtension API.
#
Pod::Spec.new do |s|
  s.name             = 'veil_flutter'
  s.version          = '0.1.0'
  s.summary          = 'Dart-FFI bindings and packet-tunnel control for veil.'
  s.description      = <<-DESC
Censorship-resistant P2P veil network — Dart-FFI bindings and host-side system
packet-tunnel lifecycle control for macOS.
                       DESC
  s.homepage         = 'https://github.com/veilnetwork/veil'
  s.license          = { :file => '../LICENSE' }
  s.author           = { 'Veil' => 'noreply@veil.invalid' }

  s.source           = { :path => '.' }
  s.source_files     = 'Classes/**/*'
  s.dependency 'FlutterMacOS'
  s.platform = :osx, '10.15'
  s.frameworks = 'NetworkExtension'
  s.pod_target_xcconfig = { 'DEFINES_MODULE' => 'YES' }
  s.swift_version = '5.0'
end
