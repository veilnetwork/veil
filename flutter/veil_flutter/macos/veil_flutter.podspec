#
# veil_flutter — macOS plugin podspec.
#
# This is a thin shell. Unlike iOS (which vendors + force-loads the static
# lib), on macOS the Rust dylib `libveilclient_ffi.dylib` is loaded at RUNTIME
# via Dart's `DynamicLibrary.open` (the app's native_libs.dart resolves the dev
# path / the bundled Frameworks copy) — there is no compile-time link here. The
# podspec exists only so CocoaPods integration succeeds on macOS once any real
# macOS pod (e.g. flutter_local_notifications) is present; without it `pod
# install` fails with "No podspec found for veil_flutter".
#
Pod::Spec.new do |s|
  s.name             = 'veil_flutter'
  s.version          = '0.1.0'
  s.summary          = 'Dart-FFI bindings for the veil daemon (macOS shell).'
  s.description      = <<-DESC
Censorship-resistant P2P veil network — Dart-FFI bindings. macOS loads the Rust
dylib at runtime via DynamicLibrary, so this pod carries no native code.
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
