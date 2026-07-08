# veil_media — Android (Phase 3 return leg)

The macOS side (desktop) already sends real Opus audio over veil. For a
two-way call the phone needs the same engine, which means a libwebrtc built for
android-arm64 plus an Android AudioDeviceModule. The C++ engine + shim are
shared; only the ADM differs (AAudio instead of AVAudioEngine).

## ⚠️ Hard constraint: build libwebrtc on x86_64 Linux

WebRTC's gn refuses Android target builds off Linux:

    build/config/BUILDCONFIG.gn:257 assert(host_os == "linux",
      "Android builds are only supported on Linux.")

and the NDK toolchain it downloads is `linux-x86_64` only (no darwin, no
linux-arm64). So the static lib **cannot** be built on the macOS dev machine or
on an Apple-silicon (aarch64) Linux VM natively. Options:

- a real x86_64 Linux box (fastest), or
- an x86_64 Linux container on this Mac (`colima start --arch x86_64` → Rosetta;
  the emulated build of ~3000 TUs takes hours), or
- a cloud x86_64 Linux instance.

## Steps

1. **libwebrtc.a (Linux host):** `android/build_libwebrtc_android_linux.sh`.
   Pinned to the same WebRTC commit as the mac build (4ef980bc…) so the engine +
   shim API signatures match. Produces `out/android-arm64/obj/libwebrtc.a` and
   `compile_commands.json`.

2. **libveil_media.so (same Linux host):** `android/build_veil_media_so.sh`.
   Compiles `veil_media_engine.cc` + `veil_transport_shim.cc` +
   `veil_aaudio_adm.cc` with call.cc's exact android flags, links a shared lib
   exporting only `veil_media_*` (ELF version script), links `libwebrtc.a` +
   `-llog -laaudio`. `veil_media_send_datagram` / `veil_media_set_recv_callback`
   stay undefined → resolve at runtime from `libveilclient_ffi.so`.

   ⚠️ **Cross-.so symbol resolution** (the one thing to verify on device): on
   ELF/Android those two undefined symbols only resolve if `libveilclient_ffi.so`
   is loaded with global scope BEFORE `libveil_media.so`, or `libveil_media.so`
   has a `DT_NEEDED` on it. Simplest robust fix: in the Android plugin, before
   dlopen'ing libveil_media, `dlopen("libveilclient_ffi.so", RTLD_NOW|RTLD_GLOBAL)`
   so its symbols are in the global group. (macOS used `-undefined dynamic_lookup`
   which resolves against the whole process; ELF needs the explicit global load.)

3. **Bundle:** drop `libveil_media.so` into the app's
   `android/app/src/main/jniLibs/arm64-v8a/` (like the cargo-ndk-built
   `libveilclient_ffi.so`), OR ship it inside this plugin's
   `android/src/main/jniLibs/arm64-v8a/` and let Gradle merge it.

4. **Dart:** `lib/src/native.dart` already opens the macOS dylib explicitly; add
   an Android branch that `DynamicLibrary.open('libveil_media.so')` (plus the
   RTLD_GLOBAL preload of libveilclient_ffi from step 2, done natively in the
   plugin's Android side or via a tiny JNI_OnLoad).

5. **Permission:** add `<uses-permission android:name="android.permission.RECORD_AUDIO"/>`
   to `android/app/src/main/AndroidManifest.xml` and request it at runtime
   (permission_handler or a MethodChannel) before the call goes active — the
   AAudio input stream is silent until RECORD_AUDIO is granted. Mirror the macOS
   `MacMediaPermissions` flow (non-blocking, bounded) on Android.

6. **minSdk:** AAudio needs API 26+. `veil_aaudio_adm.cc` sticks to API-26 AAudio
   calls (no `setUsage`/`setInputPreset`, which are API 28) for broad support.

## Verify

Same rig as macOS: place a call, then on the *desktop* measure
`/media_recv_count?peer=<phone>` — the return leg should climb ~50/s once the
phone captures + sends. Watch `logcat -s veil_media` for the `aaudio_adm:` lines
(stream sr/ch, requestStart results).
