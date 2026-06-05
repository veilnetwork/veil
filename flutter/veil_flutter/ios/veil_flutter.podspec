#
# veil_flutter — iOS plugin podspec (Epic 489.10).
#
# Wires:
#   * The Rust FFI library (`libveilclient_ffi.a`, produced by
#     `scripts/build-mobile.sh --target aarch64-apple-ios` — consumer
#     pre-builds it, drops in `ios/Frameworks/`).
#   * The Swift glue для push-notification wake (this module).
#
# Consumer's `Podfile` picks up veil_flutter automatically через
# Flutter's plugin discovery — no manual `pod 'veil_flutter'`
# required.
#
Pod::Spec.new do |s|
  s.name             = 'veil_flutter'
  s.version          = '0.1.0'
  s.summary          = 'Dart-FFI bindings for the veil daemon (Epic 489).'
  s.description      = <<-DESC
Censorship-resistant P2P veil network — Dart-FFI bindings + iOS
plugin glue for push-notification wake (Epic 489.10).
                       DESC
  s.homepage         = 'https://github.com/veilnetwork/veil'
  s.license          = { :file => '../LICENSE' }
  s.author           = { 'Veil' => 'noreply@veil.invalid' }

  s.source           = { :path => '.' }
  s.source_files     = 'Classes/**/*'
  s.public_header_files = 'Classes/**/*.h'
  s.dependency 'Flutter'
  s.platform = :ios, '13.0'

  # Vendored static lib produced by scripts/build-mobile.sh.
  # Consumer drops the .a в `ios/Frameworks/` per architecture; the
  # podspec's `vendored_libraries` glob picks them up so the linker
  # finds `_veil_connect` etc. при final-app build.
  s.vendored_libraries = 'Frameworks/libveilclient_ffi.a'

  s.pod_target_xcconfig = {
    'DEFINES_MODULE'   => 'YES',
    'EXCLUDED_ARCHS[sdk=iphonesimulator*]' => 'i386',
    # Static lib carries Rust runtime symbols; tell linker не к
    # complain about unresolved symbols at the dylib stage — they're
    # resolved at the final-app link.
    'OTHER_LDFLAGS'    => '-lc++',
  }

  s.swift_version = '5.0'
end
