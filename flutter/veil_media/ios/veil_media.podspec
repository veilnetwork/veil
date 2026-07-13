Pod::Spec.new do |s|
  s.name             = 'veil_media'
  s.version          = '0.0.3'
  s.summary          = 'Native veil group audio/video engine for iOS.'
  s.description      = <<-DESC
One WebRTC audio/video engine transported over authenticated veil media
channels. RTP, Opus, VP8 and decoded PCM remain native and never touch Dart.
                       DESC
  s.homepage         = 'https://github.com/veilnetwork/veil'
  s.license          = { :type => 'MIT' }
  s.author           = { 'Veil' => 'noreply@veil.invalid' }
  s.source           = { :path => '.' }
  s.source_files     = 'Classes/**/*'
  s.dependency 'Flutter'
  # The transport callback ABI is exported by veilclient-ffi inside the
  # veil_flutter pod. With use_frameworks! each pod links independently, so an
  # explicit dependency is required for the media shim's two callback symbols.
  s.dependency 'veil_flutter'
  s.platform         = :ios, '13.0'

  # libveil_media owns only the veil control/shim/capture objects. WebRTC stays
  # a separate archive so the final app linker pulls only the graph reachable
  # from those force-loaded entrypoints instead of embedding every WebRTC TU.
  s.vendored_libraries = [
    'Frameworks/libveil_media.a',
    'Frameworks/libwebrtc.a',
    'Frameworks/libwebrtc_cxx.a',
    'Frameworks/libwebrtc_cxxabi.a',
  ]
  s.frameworks = [
    'AVFoundation', 'AudioToolbox', 'CoreAudio',
    'CoreFoundation', 'CoreGraphics', 'CoreMedia', 'CoreVideo',
    'Foundation', 'Security', 'SystemConfiguration', 'UIKit',
  ]
  s.pod_target_xcconfig = {
    'DEFINES_MODULE' => 'YES',
    'EXCLUDED_ARCHS[sdk=iphonesimulator*]' => 'i386',
    # The ABI is reached only through dlsym, so normal archive extraction sees
    # no reference and strips it. Force-load the small veil archive; its WebRTC
    # references then pull the required codec/audio graph normally.
    'OTHER_LDFLAGS' => '-lc++ -force_load "${PODS_TARGET_SRCROOT}/Frameworks/libveil_media.a" -force_load "${PODS_TARGET_SRCROOT}/Frameworks/libwebrtc_cxx.a" -force_load "${PODS_TARGET_SRCROOT}/Frameworks/libwebrtc_cxxabi.a"',
  }
  s.swift_version = '5.0'
end
