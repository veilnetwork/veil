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
  s.frameworks = 'NetworkExtension'
  s.platform = :ios, '13.0'

  # Vendored static lib produced by scripts/build-mobile.sh.
  # Consumer drops the .a в `ios/Frameworks/` per architecture; the
  # podspec's `vendored_libraries` glob picks them up so the linker
  # finds `_veil_connect` etc. при final-app build.
  s.vendored_libraries = 'Frameworks/libveilclient_ffi.a'

  s.pod_target_xcconfig = {
    'DEFINES_MODULE'   => 'YES',
    'EXCLUDED_ARCHS[sdk=iphonesimulator*]' => 'i386',
    # The Dart side resolves the Rust FFI symbols at runtime via
    # `DynamicLibrary.process()` (RTLD_DEFAULT) — there is no Swift call path
    # to `veil_connect` / `veil_node_start_deferred` at compile time. Plain
    # `vendored_libraries` linking pulls only the archive objects the compiled
    # code REFERENCES; since nothing references the Rust symbols at link time,
    # the linker pulls ZERO objects and the app ships without a single Rust
    # symbol — `dlsym` fails at the first FFI call. `-force_load` pulls every
    # object from the archive so the symbols are present and exported for the
    # process-scope lookup. (hidden_volume's podspec does the same.)
    # `-force_load` pulls every Rust object (FFI symbols are only referenced at
    # runtime via dlsym, so plain linking would strip them). The `-framework`
    # flags satisfy system deps the Rust staticlib references but cannot declare:
    # SystemConfiguration (the `system-configuration` crate — `SCDynamicStore*`,
    # network/proxy reachability) and Security (keychain / SecRandom in the TLS +
    # crypto stack). Folded into OTHER_LDFLAGS because `s.frameworks` does not
    # emit `-framework` under `use_frameworks!` for a vendored-staticlib pod.
    'OTHER_LDFLAGS'    => '-lc++ -force_load "${PODS_TARGET_SRCROOT}/Frameworks/libveilclient_ffi.a" -framework SystemConfiguration -framework Security',
  }

  s.swift_version = '5.0'
end
