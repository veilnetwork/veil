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
  #
  # All four are gitignored build artifacts (ios/Frameworks/.gitignore ignores
  # everything), produced by ios/build_veil_media_ios.sh from a from-source
  # WebRTC checkout, tens of GB. A clean clone has none of them, and naming a
  # vendored library that is not on disk does not fail here: it fails much
  # later, inside the Runner link, as `-force_load` complaining about a file
  # nobody mentioned in the build log.
  #
  # So this asks first, and asks the same question the desktop plugins ask.
  # cmake/veil_media_engine_policy.cmake holds the long version. Same order,
  # same default: an explicit VEIL_MEDIA_REQUIRE_ENGINE wins, else CI means
  # strict, else a local build gets a warning and an app whose Dart side
  # reports calls, voice messages, video notes and speech-to-text as
  # unavailable (VeilMediaNative.available()).
  #
  # Dropping the archives leaves a working pod: Classes/ is an empty plugin
  # shell that references none of them, and the Dart FFI layer resolves the
  # control ABI through DynamicLibrary.process(), which simply finds nothing.
  #
  # ASCII only, deliberately. CocoaPods evaluates this file with `eval` over a
  # string, so it is parsed in Encoding.default_external rather than in the
  # file's own encoding: under a POSIX/C locale a single non-ASCII character
  # anywhere here is a SyntaxError, and the podspec stops loading. A prose dash
  # took the whole pod out that way while this was being written.
  _veil_media_archives = [
    'Frameworks/libveil_media.a',
    'Frameworks/libwebrtc.a',
    'Frameworks/libwebrtc_cxx.a',
    'Frameworks/libwebrtc_cxxabi.a',
  ]
  _veil_media_missing = _veil_media_archives.reject do |lib|
    File.exist?(File.join(__dir__, lib))
  end

  # A lambda and not a `def`: this file is evaluated inside a block, where a
  # `def` would land on whatever object happens to be `self` at load time.
  _veil_media_falsey = lambda do |value|
    %w[0 off no false n].include?(value.downcase)
  end
  _veil_media_policy = lambda do
    explicit = ENV['VEIL_MEDIA_REQUIRE_ENGINE']
    if !explicit.nil? && !explicit.empty?
      next [!_veil_media_falsey.call(explicit),
            "VEIL_MEDIA_REQUIRE_ENGINE=#{explicit} is set"]
    end
    ci = ENV['CI']
    if !ci.nil? && !ci.empty? && !_veil_media_falsey.call(ci)
      next [true, "CI=#{ci} (an automated build is assumed to be shipping)"]
    end
    [false, 'this is a local build (no VEIL_MEDIA_REQUIRE_ENGINE, no CI)']
  end

  unless _veil_media_missing.empty?
    _veil_media_required, _veil_media_why = _veil_media_policy.call
    if _veil_media_required
      raise <<~MSG
        veil_media (ios): prebuilt engine missing:
          #{_veil_media_missing.join("\n  ")}
        Refusing to build without it because #{_veil_media_why}.
        An app without it installs, looks healthy, and throws at the first
        voice message. v0.9.1 shipped exactly that.
        Build it with a from-source iOS WebRTC checkout:
          veil_media/ios/build_veil_media_ios.sh
      MSG
    end
    warn <<~MSG
      veil_media (ios): building WITHOUT the call media engine.
        missing: #{_veil_media_missing.join("\n  ")}
        This build will run. Calls, group calls, voice messages, video notes and
        speech-to-text will report themselves as unavailable rather than
        working: the Dart side checks the engine is loadable before it offers
        them.
        To get those features: veil_media/ios/build_veil_media_ios.sh
        A release refuses instead of warning; VEIL_MEDIA_REQUIRE_ENGINE / CI
        decide which you get.
    MSG
  end

  s.vendored_libraries = _veil_media_missing.empty? ? _veil_media_archives : []
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
    #
    # With no archives on disk the force_loads name files that are not there
    # and the Runner link fails, so the flags go away with them, leaving
    # -lc++ (which the empty Swift shell still wants) and an app that has no
    # media ABI to find.
    'OTHER_LDFLAGS' => _veil_media_missing.empty? ?
      '-lc++ -force_load "${PODS_TARGET_SRCROOT}/Frameworks/libveil_media.a" -force_load "${PODS_TARGET_SRCROOT}/Frameworks/libwebrtc_cxx.a" -force_load "${PODS_TARGET_SRCROOT}/Frameworks/libwebrtc_cxxabi.a"' :
      '-lc++',
  }
  s.swift_version = '5.0'
end
